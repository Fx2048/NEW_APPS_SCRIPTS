import jwt
import hashlib
import time

class CognitoUserPool:
    def __init__(self, pool_data):
        self.user_pool_id = pool_data['UserPoolId']
        self.client_id = pool_data['ClientId']
        self.users = {}
        self.roles = {}

    def register_user(self, username, password, role):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            'password': hashed_password,
            'role': role
        }
        print(f"Usuario {username} registrado exitosamente con rol {role}.")

    def authenticate_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username in self.users and self.users[username]['password'] == hashed_password:
            return self.generate_token(username)
        else:
            raise Exception("Autenticación fallida.")

    def generate_token(self, username):
        payload = {
            'username': username,
            'role': self.users[username]['role'],
            'exp': time.time() + 3600  # Expira en 1 hora
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        return token

def validate_token(token):
    try:
        decoded = jwt.decode(token, 'secret', algorithms=['HS256'])
        print(f"Token válido. Usuario: {decoded['username']}, Rol: {decoded['role']}")
    except jwt.ExpiredSignatureError:
        print("El token ha expirado.")
    except jwt.InvalidTokenError:
        print("Token inválido.")

def simulate_user_interaction():
    # Datos Ficticios
    pool_data = [
        {'UserPoolId': 'us-east-1', 'ClientId': 'history_teachers'},
        {'UserPoolId': 'us-east-1', 'ClientId': 'math_teachers'},
        {'UserPoolId': 'us-east-1', 'ClientId': 'science_teachers'},
        {'UserPoolId': 'us-east-1', 'ClientId': 'history_students'},
        {'UserPoolId': 'us-east-1', 'ClientId': 'math_students'},
        {'UserPoolId': 'us-east-1', 'ClientId': 'science_students'}
    ]

    user_pools = {data['ClientId']: CognitoUserPool(data) for data in pool_data}

    users = [
        ('Albert', 'Bernal', 'history_teachers', 'teacher'),
        ('Adrien_student_math', 'Bernal', 'math_students', 'student'),
        ('Alexandro_student', 'Bernal', 'history_students', 'student'),
        ('David_teacher', 'Bernal', 'science_teachers', 'teacher'),
        ('Adrian_student_science', 'Bernal', 'science_students', 'student'),
        ('Santiago_student_history', 'Bernal', 'history_students', 'student'),
        ('Eduardo_student_math', 'Bernal', 'math_students', 'student'),
        ('Marco_student_science', 'Bernal', 'science_students', 'student')
    ]

    # Registro de usuarios
    for username, password, pool, role in users:
        user_pools[pool].register_user(username, password, role)

    # Autenticación de usuarios y validación de tokens
    for username, password, pool, role in users:
        try:
            token = user_pools[pool].authenticate_user(username, password)
            print(f"Token de acceso para {username}: {token}")
            validate_token(token)
        except Exception as e:
            print(e)

if __name__ == "__main__":
    simulate_user_interaction()
