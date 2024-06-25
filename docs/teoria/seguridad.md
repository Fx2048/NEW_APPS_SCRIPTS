# Conceptos de Seguridad en AWS
La seguridad en AWS es un pilar fundamental y abarca diversas prácticas y herramientas para garantizar la protección de datos y aplicaciones. Entre las mejores prácticas se incluyen:

## Autenticación y Autorización:
Utilizar servicios como AWS IAM (Identity and Access Management) para gestionar usuarios y permisos. IAM permite crear roles, políticas y grupos para asegurar que solo usuarios autorizados accedan a los recursos.

## Protección de Conexiones de Red: 
Configurar VPC (Virtual Private Cloud) para segmentar la red y utilizar subnets públicas y privadas. Implementar grupos de seguridad y listas de control de acceso (NACLs) para controlar el tráfico entrante y saliente.

## Monitoreo y Registro:
Utilizar servicios como AWS CloudTrail para registrar todas las acciones realizadas en la cuenta AWS y AWS CloudWatch para monitorear métricas y configurar alertas.

## Protección de Datos: 
Encriptar datos en tránsito y en reposo usando AWS Key Management Service (KMS) y SSL/TLS. Utilizar servicios como AWS Shield para protegerse contra ataques DDoS.


Imagen referencial de los servicios de AWS que intervienen en la seguridad de AWS integrados:
![image](https://github.com/Fx2048/AWS_safe_apps/assets/131219987/d6a3ea1a-94fa-421e-be75-fafa5c9a9c50)

También existen los siguientes que participan en los serverless
![image](https://github.com/Fx2048/AWS_safe_apps/assets/131219987/f8e6c154-0710-4037-bff8-6c4fdfb6542c)

![image](https://github.com/Fx2048/AWS_safe_apps/assets/131219987/a2af4b69-30d8-4202-8689-da97d1489f25)

