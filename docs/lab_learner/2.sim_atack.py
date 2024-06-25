# Simulador de ciberataques básico en Python

class Nodo:
    """
    Objetivo: Simular ataques de seguridad para evaluar la robustez de las configuraciones y políticas 
implementadas.  
Descripción: 
• Planifica y ejecuta un conjunto de ataques simulados, incluyendo ataques de fuerza bruta y 
XSS (Cross-Site Scripting) contra aplicaciones protegidas por Amazon Cognito. 
• Utilizar AWS WAF para monitorizar y bloquear los ataques. 
• Analizar los registros y métricas para identificar áreas de mejora en las políticas de 
seguridad. 

    """
    def __init__(self, nombre):
        self.nombre = nombre
        self.vulnerabilidades = []

    def agregar_vulnerabilidad(self, vulnerabilidad):
        self.vulnerabilidades.append(vulnerabilidad)

class Vulnerabilidad:
    def __init__(self, nombre):
        self.nombre = nombre

class Simulador:
    def __init__(self):
        self.red = {}

    def agregar_nodo(self, nodo):
        self.red[nodo.nombre] = nodo

    def simular_ataque(self, atacante, objetivo):
        if atacante in self.red and objetivo in self.red:
            for vulnerabilidad in self.red[objetivo].vulnerabilidades:
                if vulnerabilidad in self.red[atacante].vulnerabilidades:
                    print(f"¡Ataque exitoso! {atacante} comprometió {objetivo}.")
                    return
            print(f"El ataque de {atacante} a {objetivo} falló.")
        else:
            print("Nodo no encontrado en la red.")

# Crear nodos y vulnerabilidades
nodo1 = Nodo("Servidor1")
nodo1.agregar_vulnerabilidad(Vulnerabilidad("CVE-2021-1234"))

nodo2 = Nodo("Cliente1")
nodo2.agregar_vulnerabilidad(Vulnerabilidad("CVE-2021-5678"))

# Construir la red
simulador = Simulador()
simulador.agregar_nodo(nodo1)
simulador.agregar_nodo(nodo2)

# Simular un ataque
simulador.simular_ataque("Cliente1", "Servidor1")
