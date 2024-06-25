import boto3
import json
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear cliente IAM
iam_client = boto3.client('iam')

iam_client=boto3-client('iam')
def create_policy(policy_name, policy_document):
    """
    Objetivo: Crear y aplicar políticas de IAM personalizadas que reflejen las necesidades específicas de 
    seguridad de la aplicación.  

    Descripción: 
    • Diseña políticas de IAM que restrinjan el acceso a recursos específicos basados en roles y 
      responsabilidades definidos. 
    • Aplica estas políticas a grupos de usuarios y roles dentro de Amazon Cognito. 
    • Realiza pruebas para asegurar que las políticas funcionan como se espera sin impedir la 
      funcionalidad de la aplicación.
    """
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        logger.info(f"Policy {policy_name} created successfully")
        return response['Policy']['Arn']
    except Exception as e:
        logger.error(f"Error creating policy: {e}")

    
#cREAR una política personalizada IAM
    policy_arn=create_policy(policy_name,policy_document)
    if policy_arn:
        logger.info(f"Policy ARN: {policy_arn}")
if __name__=='__main__':
     main()

