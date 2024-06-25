import boto3
import json

# Crear clientes de AWS para IAM, STS y Cognito Identity Provider
cliente_iam = boto3.client('iam', region_name='us-east-1')
cliente_sts = boto3.client('sts', region_name='us-east-1')
cliente_cognito = boto3.client('cognito-idp', region_name='us-east-1')

# Crear un nuevo rol en IAM
def crear_rol_iam(nombre_rol, documento_politica):
    try:
        respuesta = cliente_iam.create_role(
            RoleName=nombre_rol,
            AssumeRolePolicyDocument=documento_politica
        )
        print(f"El rol {nombre_rol} ha sido creado exitosamente")
        return respuesta['Role']['Arn']
    except Exception as e:
        print(f"Error al crear el rol: {e}")

# Vincular una política a un rol en IAM
def vincular_politica_a_rol(nombre_rol, arn_politica):
    try:
        cliente_iam.attach_role_policy(
            RoleName=nombre_rol,
            PolicyArn=arn_politica
        )
        print(f"La política {arn_politica} se ha vinculado exitosamente al rol {nombre_rol}")
    except Exception as e:
        print(f"Error al vincular la política: {e}")

# Crear un nuevo grupo de usuarios en Cognito
def crear_pool_usuarios(nombre_pool):
    try:
        respuesta = cliente_cognito.create_user_pool(PoolName=nombre_pool)
        print(f"El pool de usuarios {nombre_pool} ha sido creado exitosamente")
        return respuesta['UserPool']['Id']
    except Exception as e:
        print(f"Error al crear el pool de usuarios: {e}")

# Crear un nuevo cliente para el pool de usuarios en Cognito
def crear_cliente_pool_usuarios(id_pool_usuarios, nombre_cliente):
    try:
        respuesta = cliente_cognito.create_user_pool_client(
            UserPoolId=id_pool_usuarios,
            ClientName=nombre_cliente
        )
        print(f"El cliente del pool de usuarios {nombre_cliente} ha sido creado exitosamente")
        return respuesta['UserPoolClient']['ClientId']
    except Exception as e:
        print(f"Error al crear el cliente del pool de usuarios: {e}")

def main():
    nombre_rol = 'MiRolDeSeguridad'
    documento_politica = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })
    arn_politica = 'arn:aws:iam::aws:policy/ReadOnlyAccess'

    # Crear rol en IAM y vincular política
    arn_rol = crear_rol_iam(nombre_rol, documento_politica)
    if arn_rol:
        vincular_politica_a_rol(nombre_rol, arn_politica)

    # Crear pool de usuarios y cliente
    id_pool_usuarios = crear_pool_usuarios('MiPoolDeUsuarios')
    if id_pool_usuarios:
        crear_cliente_pool_usuarios(id_pool_usuarios, 'MiClienteDePoolDeUsuarios')

# Ejecutar función principal
if __name__ == '__main__':
    main()



        


