import random
import string
import hashlib

class CognitoUserPoolSimulator:
    def __init__(self):
        self.users = {}
        self.mfa_enabled = False

    def create_user(self, email, phone, password):
        user_id = self._generate_user_id()
        self.users[user_id] = {
            'email': email,
            'phone': phone,
            'password': self._hash_password(password),
            'verified': False,
            'mfa_enabled': self.mfa_enabled
        }
        self._send_verification_code(email, phone)
        return user_id

    def enable_mfa(self):
        self.mfa_enabled = True

    def verify_user(self, user_id, verification_code):
        user = self.users.get(user_id)
        if not user:
            return "User not found."

        if user['verification_code'] == verification_code:
            user['verified'] = True
            return "User verified successfully!"
        else:
            return "Verification failed. Invalid code."

    def _generate_user_id(self):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def _send_verification_code(self, email, phone):
        verification_code = ''.join(random.choices(string.digits, k=6))
        for user in self.users.values():
            if user['email'] == email and user['phone'] == phone:
                user['verification_code'] = verification_code
                print(f"Verification code sent to {email} and {phone}: {verification_code}")

class RolesAndPermissionsSimulator:
    def __init__(self):
        self.roles = {}
        self.policies = {}

    def create_role(self, role_name):
        self.roles[role_name] = []
        print(f"Role '{role_name}' created.")

    def create_policy(self, policy_name, actions):
        self.policies[policy_name] = actions
        print(f"Policy '{policy_name}' created with actions: {actions}")

    def attach_policy_to_role(self, role_name, policy_name):
        role = self.roles.get(role_name)
        policy = self.policies.get(policy_name)

        if role is None:
            print(f"Role '{role_name}' not found.")
            return

        if policy is None:
            print(f"Policy '{policy_name}' not found.")
            return

        role.append(policy)
        print(f"Policy '{policy_name}' attached to role '{role_name}'.")

def main():
    # Crear instancias de los simuladores
    cognito_simulator = CognitoUserPoolSimulator()
    roles_simulator = RolesAndPermissionsSimulator()

    # Configurar MFA
    cognito_simulator.enable_mfa()

    # Crear un usuario simulado
    user_id = cognito_simulator.create_user(
        email="Brigitte.bernal@upch.pe",
        phone="983073205",
        password="fakepassword123"
    )

    # Verificar el usuario
    verification_code = input("Enter the verification code sent to your email and phone: ")
    print(cognito_simulator.verify_user(user_id, verification_code))

    # Crear roles y políticas falsos
    roles_simulator.create_role("admin_role")
    roles_simulator.create_policy("admin_policy", ["read", "write", "delete"])
    roles_simulator.attach_policy_to_role("admin_role", "admin_policy")

    # Simulación de autenticación con la web falsa
    print("Simulación de autenticación con la web falsa de royalfoundation.com")
    fake_authentication(cognito_simulator, "Brigitte.bernal@upch.pe", "fakepassword123")

    # Mensaje de verificación simulado
    print("Mensaje de verificación enviado a tu celular simulado.")

def fake_authentication(cognito_simulator, email, password):
    for user in cognito_simulator.users.values():
        if user['email'] == email and user['password'] == cognito_simulator._hash_password(password):
            if user['verified']:
                print(f"User {email} authenticated successfully!")
            else:
                print(f"User {email} needs to verify their account.")
            return
    print("Authentication failed. Invalid email or password.")

if __name__ == "__main__":
    main()
