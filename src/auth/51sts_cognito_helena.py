import json
import hashlib
import base64
import time
import uuid
from typing import Dict, Any

class CognitoUserPool:
    def __init__(self, user_pool_id: str, client_id: str):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.users: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, str]] = {}  # {group_name: {username: role}}

    def sign_up(self, username: str, password: str, email: str) -> bool:
        if username in self.users:
            print("Usuario ya existe.")
            return False

        salt = self._generate_salt()
        hashed_password = self._hash_password(password, salt)

        self.users[username] = {
            "password": hashed_password,
            "salt": salt,
            "email": email,
            "confirmed": False
        }
        print(f"Usuario {username} registrado exitosamente.")
        return True

    def confirm_sign_up(self, username: str, confirmation_code: str) -> bool:
        if username not in self.users:
            print("Usuario no encontrado.")
            return False

        if self.users[username]["confirmed"]:
            print("Usuario ya confirmado.")
            return False

        # Simulación de la verificación del código de confirmación
        self.users[username]["confirmed"] = True
        print(f"Usuario {username} confirmado exitosamente.")
        return True

    def sign_in(self, username: str, password: str) -> Dict[str, str]:
        if username not in self.users:
            print("Usuario no encontrado.")
            return {}

        if not self.users[username]["confirmed"]:
            print("Usuario no confirmado.")
            return {}

        stored_password = self.users[username]["password"]
        salt = self.users[username]["salt"]

        if self._hash_password(password, salt) == stored_password:
            return self._generate_tokens(username)
        else:
            print("Contraseña incorrecta.")
            return {}

    def add_user_to_group(self, username: str, group_name: str, role: str) -> bool:
        if username not in self.users:
            print(f"Usuario {username} no encontrado.")
            return False

        if group_name not in self.groups:
            self.groups[group_name] = {}

        self.groups[group_name][username] = role
        print(f"Usuario {username} agregado al grupo {group_name} con rol {role}.")
        return True

    def _generate_salt(self) -> str:
        return base64.b64encode(uuid.uuid4().bytes).decode('utf-8')

    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def _generate_tokens(self, username: str) -> Dict[str, str]:
        current_time = int(time.time())
        access_token = {
            "sub": username,
            "iat": current_time,
            "exp": current_time + 3600,  # Token válido por 1 hora
            "token_use": "access"
        }
        id_token = {
            "sub": username,
            "email": self.users[username]["email"],
            "iat": current_time,
            "exp": current_time + 3600,
            "token_use": "id"
        }
        return {
            "AccessToken": base64.b64encode(json.dumps(access_token).encode()).decode(),
            "IdToken": base64.b64encode(json.dumps(id_token).encode()).decode()
        }

def validate_token(token: str) -> bool:
    try:
        decoded_token = json.loads(base64.b64decode(token))
        current_time = int(time.time())
        return decoded_token["exp"] > current_time
    except Exception as e:
        print(f"Error al validar el token: {e}")
        return False

def main():
    user_pool = CognitoUserPool("us-east-1_royalhigh", "royalhighmath20240207")

    # Registrar y confirmar usuarios
    user_pool.sign_up("teacher1", "password1", "teacher1@example.com")
    user_pool.confirm_sign_up("teacher1", "dummy_code")

    user_pool.sign_up("student1", "password1", "student1@example.com")
    user_pool.confirm_sign_up("student1", "dummy_code")

    # Agregar usuarios a grupos
    user_pool.add_user_to_group("teacher1", "math_teachers", "teacher")
    user_pool.add_user_to_group("student1", "math_students", "student")

    # Autenticar usuarios
    tokens = user_pool.sign_in("teacher1", "password1")
    if tokens:
        print("Inicio de sesión exitoso.")
        print(f"Access Token: {tokens['AccessToken']}")
        print(f"ID Token: {tokens['IdToken']}")

    # Validar token
    if validate_token(tokens['AccessToken']):
        print("Token válido.")
    else:
        print("Token inválido o expirado.")

if __name__ == "__main__":
    main()
