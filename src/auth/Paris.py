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
#creaciion de roles
    def create_role(self, role_name, policy_document):
        self.roles[role_name] = {
            'policy_document': policy_document,
            'attached_policies': []
        }
        print(f"Simulated Role created: {role_name}")
        return self.roles[role_name]
#adjuntar politicas a roles
    def attach_policy_to_role(self, role_name, policy_arn):
        if role_name in self.roles:
            self.roles[role_name]['attached_policies'].append(policy_arn)
            print(f"Simulated Policy {policy_arn} attached to Role {role_name}")
        else:
            print(f"Role {role_name} not found")
        return self.roles[role_name]
#simulacion de grupo de usuarios cognito
class SimulatedCognitoUserPool:
    def __init__(self, pool_data):
        self.user_pool_id = pool_data['UserPoolId']
        self.client_id = pool_data['ClientId']
        self.users = {}
# registro de usuarios
    def register_user(self, username, password, role):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            'password': hashed_password,
            'role': role
        }
        print(f"User {username} registered with role {role}")
#autenticacion de usuarios
    def authenticate_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username in self.users and self.users[username]['password'] == hashed_password:
            return self.generate_token(username)
        else:
            raise Exception("Authentication failed")
#generar token
    def generate_token(self, username):
        payload = {
            'username': username,
            'role': self.users[username]['role'],
            'exp': time.time() + 3600
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
# validar token
def validate_token(token, secret_key=SECRET_KEY):
    try:
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        print(f"Valid Token. User: {decoded['username']}, Role: {decoded['role']}")
    except jwt.ExpiredSignatureError:
        print("Token has expired")
    except jwt.InvalidTokenError:
        print("Invalid Token")
#auditar roles y politicas
def audit_roles_and_policies(iam):
    for role_name, role_data in iam.roles.items():
        print(f"Auditing Role: {role_name}")
        print(f"Policy Document: {role_data['policy_document']}")
        for policy in role_data['attached_policies']:
            print(f"Attached Policy: {policy}")
# identificar excesivos permisos
def identify_excessive_permissions(iam):
    for role_name, role_data in iam.roles.items():
        print(f"Checking permissions for Role: {role_name}")
        for policy in role_data['attached_policies']:
            if "SimulatedCognitoPowerUser" in policy:
                print(f"Role {role_name} has excessive permissions with policy {policy}")
# mitigar excesivos permisos
def mitigate_excessive_permissions(iam):
    for role_name, role_data in iam.roles.items():
        for policy in role_data['attached_policies']:
            if "SimulatedCognitoPowerUser" in policy:
                # Adjuntar una política más restrictiva
                iam.attach_policy_to_role(role_name, 'arn:aws:iam::aws:policy/SimulatedCognitoReadOnly')
                # Quitar la política de permisos excesivos
                role_data['attached_policies'].remove(policy)
                print(f"Mitigated excessive permissions for Role: {role_name}")

# Simular AWS WAF
class SimulatedAWSWAF:
    def __init__(self):
        self.rules = []
        self.logs = []
# añadir reglas
    def add_rule(self, rule):
        self.rules.append(rule)
        print(f"Rule added: {rule}")
# monitiorear trafico
    def monitor_traffic(self, request):
        for rule in self.rules:
            if rule in request:
                self.logs.append(f"Blocked request: {request} due to rule: {rule}")
                print(f"Blocked request: {request} due to rule: {rule}")
                return False
        self.logs.append(f"Allowed request: {request}")
        return True
#anañizar registros
    def analyze_logs(self):
        for log in self.logs:
            print(log)

# Simulated AWS Shield
class SimulatedAWSShield:
    def __init__(self):
        self.protections = []
#añadir proteccion
    def add_protection(self, resource):
        self.protections.append(resource)
        print(f"Shield protection added for: {resource}")
#detectar ddos
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

def simulate_brute_force_attack(user_pool):
    usernames = list(user_pool.users.keys())
    for username in usernames:
        for i in range(5):  # Simulate 5 failed login attempts
            try:
                user_pool.authenticate_user(username, "wrongpassword")
            except Exception as e:
                print(f"Brute force attack failed for {username} with 'wrongpassword': {e}")

def simulate_xss_attack():
    xss_payload = "<script>alert('XSS');</script>"
    print(f"Simulating XSS attack with payload: {xss_payload}")
    return xss_payload

#class ---------------------------------------------------2.4etapa
class FakeOWASPZAP:
    def __init__(self, app):
        self.app = app

    def scan_for_vulnerabilities(self):
        print("Starting OWASP ZAP scan...")
        self.check_sql_injection()
        self.check_xss()
        self.check_csrf()

    def check_sql_injection(self):
        print("Checking for SQL Injection vulnerabilities...")
        print("No SQL Injection vulnerabilities found.")

    def check_xss(self):
        print("Checking for XSS vulnerabilities...")
        payload = "<script>alert('XSS');</script>"
        if self.app.block_request(payload):
            print(f"Blocked request: {payload} due to rule: {payload}")
        else:
            print("XSS vulnerability found!")

    def check_csrf(self):
        print("Checking for CSRF vulnerabilities...")
        print("No CSRF vulnerabilities found.")

class FakeBurpSuite:
    def __init__(self, app):
        self.app = app

    def perform_security_tests(self):
        print("Starting Burp Suite security tests...")
        self.test_authentication()
        self.test_session_management()
        self.test_input_validation()

    def test_authentication(self):
        print("Testing authentication mechanisms...")
        for user in self.app.users:
            for _ in range(5):
                try:
                    self.app.authenticate_user(user, 'wrongpassword')
                except Exception as e:
                    print(f"Brute force attack failed for {user} with 'wrongpassword': {e}")

    def test_session_management(self):
        print("Testing session management...")
        print("Session management is secure.")

    def test_input_validation(self):
        print("Testing input validation...")
        print("Input validation is secure.")
class FakeApp:
    def __init__(self):
        self.users = {
            'Adrien_student_math': 'password123',
            'Alexandro_student': 'password123',
            'David_teacher': 'password123',
            'Adrian_student_science': 'password123',
            'Santiago_student_history': 'password123',
            'Eduardo_student_math': 'password123',
            'Marco_student_science': 'password123'
        }
        self.blocked_requests = []

    def authenticate_user(self, username, password):
        if self.users.get(username) == password:
            print(f"Valid Token. User: {username}, Role: student")
        else:
            raise Exception("Authentication failed")

    def block_request(self, payload):
        if payload in ["<script>alert('XSS');</script>"]:
            self.blocked_requests.append(payload)
            return True
        return False



#endclass/start lambda ---------------------------------------------------5.1etapa{lambda} lo nuevo que se añade
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

#main------------------------------ Simulación de eventos de CloudWatch y respuestas automatizadas
def main():
 #añadiendo parametros a simular
    
    iam = SimulatedIAM()
    cognito_user_pools = {}
    shield = SimulatedAWSShield()
    waf = SimulatedAWSWAF()
    cloudwatch = SimulatedCloudWatch()
    guardduty = SimulatedGuardDuty()

    lambda_service = SimulatedLambda()
    cognito = SimulatedCognitoUserPool({'UserPoolId': 'us-east-1_example', 'ClientId': 'example'})
#añadir documentos de politica----------------------------------
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

    # Attach policiesu
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

    # Add WAF rules
    waf.add_rule("wrongpassword")
    waf.add_rule("<script>alert('XSS');</script>")

    # Add Shield protections
    shield.add_protection("UserPool")
    shield.add_protection("IAMRoles")

    # Simulate attacks
    for pool in cognito_user_pools.values():
        simulate_brute_force_attack(pool)

    xss_attack = simulate_xss_attack()
    waf.monitor_traffic(xss_attack)

    # Analyze WAF logs
    waf.analyze_logs()

    # Check for DDoS attacks
    shield.detect_ddos(traffic=1200)  # Simulate traffic for DDoS detection

    # GuardDuty analyzes WAF logs
    guardduty.analyze_logs(waf.logs)
    
#añadiendo vulnearbility settings----------------------------------------------2.4.3 versiones
    # Crear instancia de la aplicación ficticia
    app = FakeApp()

    # Ejecutar simulación de OWASP ZAP
    fake_zap = FakeOWASPZAP(app)
    fake_zap.scan_for_vulnerabilities()

    # Ejecutar simulación de Burp Suite
    fake_burp = FakeBurpSuite(app)
    fake_burp.perform_security_tests()

    #------------------------------------
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
    main()
