import os
import hashlib
import json
import time
import jwt
import random

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
                # Attach a more restrictive policy
                iam.attach_policy_to_role(role_name, 'arn:aws:iam::aws:policy/SimulatedCognitoReadOnly')
                # Remove the excessive permission policy
                role_data['attached_policies'].remove(policy)
                print(f"Mitigated excessive permissions for Role: {role_name}")

# Simulated AWS WAF
class SimulatedAWSWAF:
    def __init__(self):
        self.rules = []
        self.logs = []

    def add_rule(self, rule):
        self.rules.append(rule)
        print(f"Rule added: {rule}")

    def monitor_traffic(self, request):
        for rule in self.rules:
            if rule in request:
                self.logs.append(f"Blocked request: {request} due to rule: {rule}")
                print(f"Blocked request: {request} due to rule: {rule}")
                return False
        self.logs.append(f"Allowed request: {request}")
        return True

    def analyze_logs(self):
        for log in self.logs:
            print(log)

# Simulated AWS Shield
class SimulatedAWSShield:
    def __init__(self):
        self.protections = []

    def add_protection(self, resource):
        self.protections.append(resource)
        print(f"Shield protection added for: {resource}")

    def detect_ddos(self, traffic):
        print("Checking for DDoS attacks...")
        if traffic > 1000:  # Arbitrary threshold for simulation
            print("DDoS attack detected!")
            return True
        print("No DDoS attack detected.")
        return False

# Simulated Amazon GuardDuty
class SimulatedGuardDuty:
    def __init__(self):
        self.findings = []

    def analyze_logs(self, logs):
        print("Analyzing logs for suspicious activity...")
        for log in logs:
            if "blocked" in log.lower():
                self.findings.append(f"Suspicious activity detected in log: {log}")
        if self.findings:
            print("GuardDuty findings:")
            for finding in self.findings:
                print(finding)
        else:
            print("No suspicious activity detected.")

# Simulated CloudWatch
class SimulatedCloudWatch:
    def __init__(self):
        self.alarms = []

    def create_alarm(self, alarm_name, metric, threshold):
        self.alarms.append({
            'name': alarm_name,
            'metric': metric,
            'threshold': threshold
        })
        print(f"CloudWatch Alarm created: {alarm_name}")

    def check_alarms(self, metric_value):
        triggered_alarms = []
        for alarm in self.alarms:
            if metric_value > alarm['threshold']:
                triggered_alarms.append(alarm['name'])
                print(f"Alarm {alarm['name']} triggered!")
        return triggered_alarms

# Simulated Lambda
class SimulatedLambda:
    def __init__(self):
        self.functions = {}

    def create_function(self, function_name, handler):
        self.functions[function_name] = handler
        print(f"Lambda function created: {function_name}")

    def invoke_function(self, function_name, event, context=None):
        if function_name in self.functions:
            print(f"Invoking Lambda function: {function_name}")
            return self.functions[function_name](event, context)
        else:
            print(f"Lambda function not found: {function_name}")

# Funciones Lambda ficticias
def lambda_handler_audit(event, context):
    iam = event['iam']
    audit_roles_and_policies(iam)
    return "Audit completed"

def lambda_handler_mitigate(event, context):
    iam = event['iam']
    identify_excessive_permissions(iam)
    mitigate_excessive_permissions(iam)
    return "Mitigation completed"

def lambda_handler_isolate(event, context):
    resource = event['resource']
    shield = event['shield']
    shield.add_protection(resource)
    return f"Resource {resource} isolated"

def lambda_handler_block_ip(event, context):
    ip = event['ip']
    waf = event['waf']
    waf.add_rule(f"Block IP {ip}")
    return f"Blocked IP address: {ip}"

def lambda_handler_notify(event, context):
    message = event['message']
    print(f"Notification sent: {message}")
    return "Notification sent"

# Simulación de eventos de CloudWatch y respuestas automatizadas
def simulate_incident_response():
    iam = SimulatedIAM()
    shield = SimulatedAWSShield()
    waf = SimulatedAWSWAF()
    cloudwatch = SimulatedCloudWatch()
    lambda_service = SimulatedLambda()
    cognito = SimulatedCognitoUserPool({'UserPoolId': 'us-east-1_example', 'ClientId': 'example'})

    # Crear funciones Lambda
    lambda_service.create_function("audit_function", lambda_handler_audit)
    lambda_service.create_function("mitigate_function", lambda_handler_mitigate)
    lambda_service.create_function("isolate_function", lambda_handler_isolate)
    lambda_service.create_function("block_ip_function", lambda_handler_block_ip)
    lambda_service.create_function("notify_function", lambda_handler_notify)

    # Crear alarmas de CloudWatch
    cloudwatch.create_alarm("HighErrorRate", "ErrorCount", 10)
    cloudwatch.create_alarm("HighCPUUsage", "CPUUtilization", 80)
    cloudwatch.create_alarm("SuspiciousActivity", "SuspiciousActivityCount", 5)

    # Simular eventos y respuestas
    for i in range(5):  # Simular 5 ciclos de eventos
        print(f"\n--- Simulation Cycle {i+1} ---")
        # Simular métricas
        error_count = random.randint(0, 20)
        cpu_utilization = random.randint(50, 100)
        suspicious_activity_count = random.randint(0, 10)

        print(f"Current metrics - Errors: {error_count}, CPU: {cpu_utilization}%, Suspicious Activities: {suspicious_activity_count}")

        # Verificar alarmas
        triggered_alarms = (
            cloudwatch.check_alarms(error_count) + 
            cloudwatch.check_alarms(cpu_utilization) + 
            cloudwatch.check_alarms(suspicious_activity_count)
        )

        for alarm in triggered_alarms:
            if alarm == "HighErrorRate":
                # Auditar y mitigar
                result = lambda_service.invoke_function("audit_function", {'iam': iam})
                print(f"Audit result: {result}")
                result = lambda_service.invoke_function("mitigate_function", {'iam': iam})
                print(f"Mitigation result: {result}")
            elif alarm == "HighCPUUsage":
                # Aislar recurso y notificar
                result = lambda_service.invoke_function("isolate_function", {'resource': 'high_cpu_instance', 'shield': shield})
                print(f"Isolation result: {result}")
                result = lambda_service.invoke_function("notify_function", {'message': "High CPU usage detected, resource isolated"})
                print(f"Notification result: {result}")
            elif alarm == "SuspiciousActivity":
                # Bloquear IP sospechosa y notificar
                suspicious_ip = f"192.168.1.{random.randint(1, 255)}"
                result = lambda_service.invoke_function("block_ip_function", {'ip': suspicious_ip, 'waf': waf})
                print(f"IP blocking result: {result}")
                result = lambda_service.invoke_function("notify_function", {'message': f"Suspicious activity detected, IP {suspicious_ip} blocked"})
                print(f"Notification result: {result}")

        time.sleep(1)  # Esperar 1 segundo entre ciclos

if __name__ == "__main__":
    simulate_incident_response()
