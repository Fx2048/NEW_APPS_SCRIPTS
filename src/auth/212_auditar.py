import os
import hashlib
import json
import time
import jwt

# Definir una clave secreta ficticia
SECRET_KEY = 'supersecretkey123'

# Simulated IAM and Cognito Services
class SimulatedIAM:
    def __init__(self):
        self.roles = {}
        self.policies = {}

    def create_role(self, role_name, policy_document):
        self.roles[role_name] = {
            'policy_document': policy_document,
            'attached_policies': []
        }
        print(f"Simulated Role created: {role_name}")
        return self.roles[role_name]

    def attach_policy_to_role(self, role_name, policy_arn):
        if role_name in self.roles:
            self.roles[role_name]['attached_policies'].append(policy_arn)
            print(f"Simulated Policy {policy_arn} attached to Role {role_name}")
        else:
            print(f"Role {role_name} not found")
        return self.roles[role_name]


class SimulatedCognitoUserPool:
    def __init__(self, pool_data):
        self.user_pool_id = pool_data['UserPoolId']
        self.client_id = pool_data['ClientId']
        self.users = {}

    def register_user(self, username, password, role):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            'password': hashed_password,
            'role': role
        }
        print(f"User {username} registered with role {role}")

    def authenticate_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username in self.users and self.users[username]['password'] == hashed_password:
            return self.generate_token(username)
        else:
            raise Exception("Authentication failed")

    def generate_token(self, username):
        payload = {
            'username': username,
            'role': self.users[username]['role'],
            'exp': time.time() + 3600
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token


def validate_token(token, secret_key=SECRET_KEY):
    try:
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        print(f"Valid Token. User: {decoded['username']}, Role: {decoded['role']}")
    except jwt.ExpiredSignatureError:
        print("Token has expired")
    except jwt.InvalidTokenError:
        print("Invalid Token")


def audit_roles_and_policies(iam):
    for role_name, role_data in iam.roles.items():
        print(f"Auditing Role: {role_name}")
        print(f"Policy Document: {role_data['policy_document']}")
        for policy in role_data['attached_policies']:
            print(f"Attached Policy: {policy}")


def identify_excessive_permissions(iam):
    for role_name, role_data in iam.roles.items():
        print(f"Checking permissions for Role: {role_name}")
        for policy in role_data['attached_policies']:
            if "SimulatedCognitoPowerUser" in policy:
                print(f"Role {role_name} has excessive permissions with policy {policy}")


def mitigate_excessive_permissions(iam):
    for role_name, role_data in iam.roles.items():
        for policy in role_data['attached_policies']:
            if "SimulatedCognitoPowerUser" in policy:
                # Adjuntar una política más restrictiva
                iam.attach_policy_to_role(role_name, 'arn:aws:iam::aws:policy/SimulatedCognitoReadOnly')
                # Quitar la política de permisos excesivos
                role_data['attached_policies'].remove(policy)
                print(f"Mitigated excessive permissions for Role: {role_name}")


def main():
    # Simulated IAM and Cognito Services
    iam = SimulatedIAM()
    cognito_user_pools = {}

    # Example policy document
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "cognito-idp.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # Create roles
    teacher_role = iam.create_role("Simulated_Teacher_Role", policy_document)
    student_role = iam.create_role("Simulated_Student_Role", policy_document)

    # Attach policies
    iam.attach_policy_to_role("Simulated_Teacher_Role", 'arn:aws:iam::aws:policy/SimulatedCognitoPowerUser')
    iam.attach_policy_to_role("Simulated_Student_Role", 'arn:aws:iam::aws:policy/SimulatedCognitoReadOnly')

    # Simulate user pools
    pool_data = [
        {'UserPoolId': 'simulated_user_pool_id', 'ClientId': 'history_teachers_client'},
        {'UserPoolId': 'simulated_user_pool_id', 'ClientId': 'math_teachers_client'},
        {'UserPoolId': 'simulated_user_pool_id', 'ClientId': 'science_teachers_client'},
        {'UserPoolId': 'simulated_user_pool_id', 'ClientId': 'history_students_client'},
        {'UserPoolId': 'simulated_user_pool_id', 'ClientId': 'math_students_client'},
        {'UserPoolId': 'simulated_user_pool_id', 'ClientId': 'science_students_client'}
    ]

    for data in pool_data:
        cognito_user_pools[data['ClientId']] = SimulatedCognitoUserPool(data)

    users = [
        ('Albert', 'password', 'history_teachers_client', 'teacher'),
        ('Adrien_student_math', 'password', 'math_students_client', 'student'),
        ('Alexandro_student', 'password', 'history_students_client', 'student'),
        ('David_teacher', 'password', 'science_teachers_client', 'teacher'),
        ('Adrian_student_science', 'password', 'science_students_client', 'student'),
        ('Santiago_student_history', 'password', 'history_students_client', 'student'),
        ('Eduardo_student_math', 'password', 'math_students_client', 'student'),
        ('Marco_student_science', 'password', 'science_students_client', 'student')
    ]

    # Register and authenticate users
    for username, password, pool, role in users:
        cognito_user_pools[pool].register_user(username, password, role)

    for username, password, pool, role in users:
        try:
            token = cognito_user_pools[pool].authenticate_user(username, password)
            print(f"Access token for {username}: {token}")
            validate_token(token)
        except Exception as e:
            print(e)

    # Auditar roles y políticas
    audit_roles_and_policies(iam)

    # Identificar permisos excesivos
    identify_excessive_permissions(iam)

    # Mitigar permisos excesivos
    mitigate_excessive_permissions(iam)

    # Re-auditar roles y políticas
    audit_roles_and_policies(iam)


if __name__ == "__main__":
    main()
