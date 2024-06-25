import redis
import ssl
from typing import Any, Optional
import os

class CacheManager:
    def __init__(self, host: str, port: int, password: str, ssl_certfile: Optional[str] = None, ssl_keyfile: Optional[str] = None):
        ssl_context = None
        if ssl_certfile and ssl_keyfile:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=ssl_certfile, keyfile=ssl_keyfile)
        
        try:
            self.client = redis.Redis(
                host=host,
                port=port,
                password=password,
                ssl=ssl_context is not None,
                ssl_certfile=ssl_certfile,
                ssl_keyfile=ssl_keyfile,
                ssl_cert_reqs=ssl.CERT_REQUIRED if ssl_context else None,
                ssl_ca_certs=ssl_certfile if ssl_context else None
            )
            # Test connection
            self.client.ping()
            print("Connected to Redis")
        except redis.ConnectionError as e:
            print(f"Error connecting to Redis: {e}")
            self.client = None
    
    def set(self, key: str, value: Any, ex: int = 3600):
        """Set a value in the cache with an expiration time (default 1 hour)."""
        if self.client:
            self.client.set(name=key, value=value, ex=ex)
        else:
            print("Redis client is not connected.")
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        if self.client:
            value = self.client.get(name=key)
            if value:
                return value.decode('utf-8')
            return None
        else:
            print("Redis client is not connected.")
            return None
    
    def delete(self, key: str):
        """Delete a value from the cache."""
        if self.client:
            self.client.delete(name=key)
        else:
            print("Redis client is not connected.")
    
    def flush_cache(self):
        """Flush the entire cache (use with caution)."""
        if self.client:
            self.client.flushdb()
        else:
            print("Redis client is not connected.")
        
if __name__ == "__main__":
    # Leer parámetros de entorno para mayor seguridad
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "yourpassword")
    SSL_CERTFILE = os.getenv("SSL_CERTFILE", None)
    SSL_KEYFILE = os.getenv("SSL_KEYFILE", None)

    cache = CacheManager(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        ssl_certfile=SSL_CERTFILE,
        ssl_keyfile=SSL_KEYFILE
    )

    # Ejemplos de uso
    cache.set("example_key", "example_value")
    print("Set example_key to 'example_value'")

    value = cache.get("example_key")
    print(f"Got value for example_key: {value}")

    cache.delete("example_key")
    print("Deleted example_key")
    
    # Flushing the cache - use with caution!
    # cache.flush_cache()
    # print("Flushed the cache")
