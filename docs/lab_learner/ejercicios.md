# Lab learner

![image](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/0ad62d1a-21b5-44fc-8586-200d42976cd9)

![image](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/9438a279-2804-4310-a537-2a7f02341415)


Configurar una Virtual Private Cloud (VPC) y subnets, así como implementar grupos de seguridad y listas de control de acceso a redes (NACLs), es esencial para asegurar tus conexiones de red en AWS. Aquí te dejo una guía paso a paso para realizar estas configuraciones:

Configurar una VPC y Subnets

Crear una VPC:

Abre la consola de Amazon VPC en AWS Management Console.

En el panel de navegación, selecciona “Your VPCs” y luego “Create VPC”.

Ingresa un nombre para tu VPC y un bloque CIDR (por ejemplo, 10.0.0.0/16).

Selecciona “Create”.

Crear Subnets:

En el panel de navegación, selecciona “Subnets” y luego “Create Subnet”.

Selecciona la VPC que acabas de crear.

Ingresa un nombre para la subred y un bloque CIDR (por ejemplo, 10.0.1.0/24 para una subred pública y 10.0.2.0/24 para una subred privada).





![Imagen de WhatsApp 2024-07-02 a las 12 02 02_87cea69b](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/e0302457-2b36-4072-aa8b-37e60efd1c0c)

Selecciona la zona de disponibilidad y crea la subred.

Configurar una Internet Gateway:

En el panel de navegación, selecciona “Internet Gateways” y luego “Create Internet Gateway”.

![Imagen de WhatsApp 2024-07-02 a las 12 04 56_aa755aa4](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/57f09f94-ae1f-4fe8-8cdb-dc8a75aade5a)

Ingresa un nombre y selecciona “Create”.

Adjunta la Internet Gateway a tu VPC




![Imagen de WhatsApp 2024-07-02 a las 12 05 40_67b30408](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/3225e76e-7686-42a0-b9d3-b308e00958d2)

Configurar Route Tables:

En el panel de navegación, selecciona “Route Tables” y luego “Create Route Table”.

![Imagen de WhatsApp 2024-07-02 a las 12 06 58_523ff03d](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/3918b5ba-4e5e-4b74-bf9d-e12628bef856)

![Imagen de WhatsApp 2024-07-02 a las 12 20 54_497db99c](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/f534f1d5-42fa-4676-ab46-e8a2b4e025eb)
Selecciona tu VPC y crea la tabla de rutas.

Agrega una ruta para la subred pública que apunte a la Internet Gateway (0.0.0.0/0 -> igw-id)



Agregar una Nueva Ruta:
Haz clic en “Add route” (Agregar ruta).

Campo “Destination” (Destino):

Ingresa 0.0.0.0/0 para permitir el tráfico a cualquier destino.
Campo “Target” (Destino):

Selecciona “Puerta de enlace de Internet” de la lista de opciones.
Guardar Cambios:

Haz clic en “Save changes” (Guardar cambios) para aplicar la nueva ruta



Pasos para Agregar Permisos a un Rol
Iniciar Sesión en AWS:

Abre la consola de administración de AWS y inicia sesión.

Acceder a IAM:

En el menú de servicios, selecciona “IAM”.

Navegar a Roles:

En el panel de navegación de la izquierda, selecciona “Roles”.

Seleccionar el Rol:

Busca y selecciona el rol voclabs.

Agregar Permisos:

En la pestaña “Permissions” (Permisos), haz clic en “Add permissions” (Agregar permisos).

Selecciona “Attach policies directly” (Adjuntar políticas directamente).

Buscar y Seleccionar la Política:

Busca la política AccessAnalyzerFullAccess o una política personalizada que incluya el permiso access-analyzer:ValidatePolicy.

Marca la casilla junto a la política y haz clic en “Next: Review” (Siguiente: Revisar).

Revisa los permisos y haz clic en “Add permissions” (Agregar permisos).

Ejemplo de Política en JSON

Si prefieres crear una política personalizada, aquí tienes un ejemplo en formato JSON:

JSON
````
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "access-analyzer:ValidatePolicy",
      "Resource": "*"
    }
  ]
}

````
![Imagen de WhatsApp 2024-07-02 a las 12 35 48_a2eae40b](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/2fa6beff-cd56-45b4-8323-a3d0d849b97f)


![Imagen de WhatsApp 2024-07-02 a las 12 44 03_57eb4a2e](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/0f57e2a4-6d92-4232-9fad-508b613651fa)

Agregar la Política Personalizada

Crear una Nueva Política:
En el panel de IAM, selecciona “Policies” (Políticas).
Haz clic en “Create policy” (Crear política).
Selecciona la pestaña “JSON” y pega el código de la política.
Haz clic en “Review policy” (Revisar política).
Asigna un nombre y una descripción a la política y haz clic en “Create policy” (Crear política).
Adjuntar la Política al Rol:
Sigue los pasos anteriores para agregar permisos y selecciona la nueva política personalizada


Pasos para Agregar Permisos a un Rol
Iniciar Sesión en AWS:

Abre la consola de administración de AWS y inicia sesión.
Acceder a IAM:

En el menú de servicios, selecciona “IAM”.
Navegar a Roles:

En el panel de navegación de la izquierda, selecciona “Roles”.
Seleccionar el Rol:

Busca y selecciona el rol voclabs.
Agregar Permisos:

En la pestaña “Permissions” (Permisos), haz clic en “Add permissions” (Agregar permisos).

Selecciona “Attach policies directly” (Adjuntar políticas directamente).

Buscar y Seleccionar la Política:

Busca la política AmazonEC2FullAccess o crea una política personalizada que incluya los permisos necesarios.






![Imagen de WhatsApp 2024-07-02 a las 13 38 39_8391a4c1](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/9f207e48-f031-4c81-bda4-1d95c6bb6fba)


![Imagen de WhatsApp 2024-07-02 a las 14 07 04_0b44927b](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/5cc1e29b-eb81-4960-b6dc-a118d5e53a62)


![Imagen de WhatsApp 2024-07-02 a las 14 11 44_0a19685d](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/36963c86-c6cb-4040-886b-149443a8703a)

![Imagen de WhatsApp 2024-07-02 a las 14 37 12_e18554a9](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/bdf22122-7f68-4d0f-ae96-af17cc2e309e)

![Imagen de WhatsApp 2024-07-02 a las 14 37 12_c53490c4](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/5ac5bda8-b2cd-4ad1-a4c9-d2ccd1b87f37)

![Imagen de WhatsApp 2024-07-02 a las 14 40 10_3bc93bb8](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/68de698a-fc9a-45c1-9308-432ffe8bf2fa)


![Imagen de WhatsApp 2024-07-02 a las 14 42 05_e4171c89](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/2e4c7925-6d56-4209-95e0-45c94a78414d)

![Imagen de WhatsApp 2024-07-02 a las 15 02 37_a7ff853a](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/76816b95-43d1-4e88-939b-eadb46c394cd)



![Imagen de WhatsApp 2024-07-02 a las 15 52 48_560c1085](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/2ea1bca8-b601-4ad4-a860-fa7313158a21)


![Imagen de WhatsApp 2024-07-02 a las 16 13 55_0bf61d8a](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/7082b484-7957-4c1f-acc7-ae595325a80d)

![Imagen de WhatsApp 2024-07-02 a las 18 35 51_a25b13c3](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/ed9db489-4f0d-4252-b4d0-ec5227e37c76)


![Imagen de WhatsApp 2024-07-02 a las 18 40 18_40b71be2](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/818a0b56-502b-4883-ae77-ea9c3cfabc14)


![Imagen de WhatsApp 2024-07-02 a las 18 54 47_249a0d0b](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/c679b876-84a1-4d9c-8327-661b4a38a437)


![Imagen de WhatsApp 2024-07-02 a las 19 00 49_0fb6cd56](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/cb02f206-a84f-4e8a-8b4e-76cecc242900)

![Imagen de WhatsApp 2024-07-02 a las 19 10 03_8870af72](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/fc94604a-7ee3-49e4-aef7-85f3218ee9e8)


![Imagen de WhatsApp 2024-07-02 a las 19 33 03_651ee0b3](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/e1aea84f-bbdc-4c0a-80ba-f5a56ef7ef77)


![Imagen de WhatsApp 2024-07-02 a las 19 47 56_d59be41c](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/9fa3f399-500d-42c0-9d74-34468b48074f)


![Imagen de WhatsApp 2024-07-02 a las 20 45 03_6f207647](https://github.com/Fx2048/NEW_APPS_SCRIPTS/assets/131219987/3aa68d38-3f00-4cea-b1f1-0fd1bd092f9f)










[Códigos de ensayo creados a partir del LAB LEARNER](https://github.com/Fx2048/COMU_REDES/tree/main/TAREAS/LAB_AMAZON/ENSAYOS_LABS/code%201%20y%202/24%20actividades_act17)


[Códigos estructurados sobre la base del problema asignado en Lab Learner]()
