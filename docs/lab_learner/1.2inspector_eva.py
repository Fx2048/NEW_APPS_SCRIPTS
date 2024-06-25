import boto3
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear cliente para AWS Inspector
inspector_client = boto3.client('inspector', region_name='us-west-1')  # Asegúrate de especificar la región

# Función start_inspector_assessment (evaluar plantilla)
def start_inspector_assessment(assessment_template_arn):
    """
    Iniciar evaluación en AWS Inspector usando la plantilla dada.
    :param assessment_template_arn: ARN de la plantilla de evaluación
    :return: ARN de ejecución de la evaluación
    """
    try:
        response = inspector_client.start_assessment_run(
            assessmentTemplateArn=assessment_template_arn,
            assessmentRunName='SecurityAuditRun'
        )
        logger.info("Assessment run started exitosamente")
        return response['assessmentRunArn']
    except inspector_client.exceptions.NoSuchEntityException:
        logger.error("The specified assessment template ARN does not exist")
    except inspector_client.exceptions.AccessDeniedException:
        logger.error("Access denied when attempting to start the assessment run")
    except Exception as e:
        logger.error(f"Error starting assessment run: {e}")

# Función main: ejecutar la evaluación de AWS Inspector
def main():
    """
    Función principal para iniciar una evaluación en AWS Inspector.
    """
    ASSESSMENT_TEMPLATE_ARN = 'arn:aws:inspector:region:account-id:target/0-abcdefg/template/0-hijklmn'

    # Empezamos con la evaluación en AWS Inspector
    assessment_run_arn = start_inspector_assessment(ASSESSMENT_TEMPLATE_ARN)
    
    if assessment_run_arn:
        logger.info(f"Assessment run ARN: {assessment_run_arn}")
    else:
        logger.error("Failed to start assessment run")

# Ejecutar script
if __name__ == '__main__':
    main()
