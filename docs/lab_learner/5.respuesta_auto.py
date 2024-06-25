import boto3
import json 
import logging
#coNFIGURAR Logging
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)
#Clientes de aws
lambda_client = boto3.client('lambda')
cloudwatch_client = boto3.client('cloudwatch')
#Crear lambda function:
def create_lambda_function(function_name, role_arn, handler, code_zip_path):
    """
Objetivo: 
    • Automatizar las respuestas a incidentes de seguridad utilizando AWS Lambda y Amazon 
        CloudWatch.  
Descripción: 
    • Desarrolla funciones Lambda que se activarán en respuesta a alertas de seguridad 
        específicas de CloudWatch. 
    • Las funciones pueden, por ejemplo, modificar automáticamente las políticas de seguridad, 
        aislar recursos comprometidos o escalar alertas a los equipos de operaciones. 
    • Prueba la efectividad de las respuestas automáticas en diferentes escenarios de simulación.

    """
    with open(code_zip_path, 'rb') as f:
        zipped_code = f.read()
    
    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.8',
            Role=role_arn,
            Handler=handler,
            Code=dict(ZipFile=zipped_code),
            Timeout=300,  # Tiempo de espera permitido límite 
        )
        logger.info(f"Lambda function {function_name} created successfully")
        return response ['FunctionArn']
    except Exception as e:
        logger.error(f"Error creating lamnda function : {e}")

def create_cloudwatch_rule(rule_name, event_pattern):
    """
    Crea una regla de CloudWatch que activa una función Lambda basada en un patrón de eventos.
    """
    try:
        response = cloudwatch_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State='ENABLED'
        )
        logger.info(f"CloudWatch rule {rule_name}created successfully")
        return response['Rule Arn']
    except Exception as e:
        logger.error(f"Error creating CloudWatch rule : {e}")
        

def add_lambda_permission(function_name, rule_arn):
    """
    Agrega permiso a la función Lambda para ser invocada por la regla de CloudWatch.
    """
    try:
        response = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=f'{function_name}-InvokePermission',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=rule_arn
        )
        logger.info(f"Permission added to Lambda function {function_name} ")
    except Exception as e:
        logger.error(F"Error adding permission to Lambda function: {e}")
# Definir parámetros de lambda y  Cloudwatch rule , configuración total:   
def main():
    function_name = 'SecurityIncidentResponder'
    role_arn = 'arn:aws:iam::account-id:role/lambda-execution-role'
    handler = 'responder.handler'
    code_zip_path = 'responder.zip'
    
    # Crear función Lambda
    lambda_arn = create_lambda_function(function_name, role_arn, handler, code_zip_path)
    rule_name = 'SecurityIncidentRule'
    event_pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "detail": {
            "state": ["ALARM"]
        }
    }
    
    # Crear una regla de CloudWatch
    rule_arn = create_cloudwatch_rule(rule_name, event_pattern)
    
    # Agregar permiso para invocar la función Lambda
    add_lambda_permission(function_name, rule_arn)
# ejecutar todo:
if __name__ == '__main__':
    main()
