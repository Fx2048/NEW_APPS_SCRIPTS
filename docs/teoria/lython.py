1. Encapsulación:
La encapsulación es el proceso de ocultar la información 
interna de un objeto y exponer solo los detalles relevantes y
necesarios para su uso externo. Esto se logra mediante 
el uso de clases en la POO. Una clase actúa como un plano 
o una plantilla para crear objetos, y encapsula tanto los 
datos como las funciones relacionadas en un solo lugar.

2. Herencia:
La herencia permite que una clase herede propiedades
y comportamientos de otra clase. Esto significa que una 
clase hija puede aprovechar y extender las características 
de su clase padre. La herencia es una forma poderosa de reutilizar
código y crear jerarquías de clases bien estructuradas.

3. Polimorfismo:
El polimorfismo se refiere a la capacidad de un objeto de tomar
muchas formas diferentes. En la POO, esto se logra mediante el
uso de la herencia y la implementación de métodos y funciones
con el mismo nombre en diferentes clases. El polimorfismo permite
escribir código genérico que puede funcionar con diferentes tipos
de objetos, lo que aumenta la flexibilidad y la modularidad del software.

4. Abstracción:
La abstracción es el proceso de simplificar un objeto o un sistema 
complejo mediante la identificación de las características y 
comportamientos esenciales y la eliminación de los detalles innecesarios.
En la POO, esto se logra mediante la creación de clases abstractas e
interfaces, que definen una estructura común y establecen un conjunto 
de métodos que deben implementarse en las clases derivadas

import random
import time

class Cliente:
    def __init__(self, servidor):
        """
        Inicializa el cliente con el servidor dado.
        """
        self.servidor = servidor
        self.estado = "CLOSED"

    def enviar_syn(self):
        """
        Envía un paquete SYN al servidor.
        """
        print("Cliente: Enviando SYN")
        self.estado = "SYN-SENT"
        try:
            if self.simular_perdida_paquete():
                raise ConnectionError("Cliente: SYN perdido, reintentando...")
            else:
                self.servidor.recibir_syn(self)
        except ConnectionError as e:
            print(e)
            time.sleep(1)
            self.enviar_syn()

    def recibir_syn_ack(self):
        """
        Recibe un paquete SYN-ACK del servidor.
        """
        print("Cliente: Recibiendo SYN-ACK")
        self.estado = "SYN-RECEIVED"
        self.enviar_ack()

    def enviar_ack(self):
        """
        Envía un paquete ACK al servidor.
        """
        print("Cliente: Enviando ACK")
        self.estado = "ESTABLISHED"
        self.servidor.recibir_ack()

    def simular_perdida_paquete(self):
        """
        Simula la pérdida de un paquete.
        """
        return random.choice([True, False])

class Servidor:
    def __init__(self):
        """
        Inicializa el servidor.
        """
        self.estado = "CLOSED"

    def recibir_syn(self, cliente):
        """
        Recibe un paquete SYN del cliente.
        """
        print("Servidor: Recibiendo SYN")
        self.estado = "SYN-RECEIVED"
        self.enviar_syn_ack(cliente)

    def enviar_syn_ack(self, cliente):
        """
        Envía un paquete SYN-ACK al cliente.
        """
        print("Servidor: Enviando SYN-ACK")
        self.estado = "SYN-SENT"
        try:
            if self.simular_perdida_paquete():
                raise ConnectionError("Servidor: SYN-ACK perdido, reintentando...")
            else:
                cliente.recibir_syn_ack()
        except ConnectionError as e:
            print(e)
            time.sleep(1)
            self.enviar_syn_ack(cliente)

    def recibir_ack(self):
        """
        Recibe un paquete ACK del cliente.
        """
        print("Servidor: Recibiendo ACK")
        self.estado = "ESTABLISHED"

    def simular_perdida_paquete(self):
        """
        Simula la pérdida de un paquete.
        """
        return random.choice([True, False])

def main():
    servidor = Servidor()
    cliente = Cliente(servidor)

    cliente.enviar_syn()

if __name__ == "__main__":
    main()



import random
import time

class ARPEntry:
    def __init__(self, ip_address, mac_address, timestamp):
        """
        Inicializa una entrada ARP con dirección IP, dirección MAC y marca de tiempo.
        """
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.timestamp = timestamp

class ARPTable:
    def __init__(self):
        """
        Inicializa una tabla ARP vacía.
        """
        self.table = {}

    def add_entry(self, ip_address, mac_address):
        """
        Añade una entrada a la tabla ARP.
        """
        try:
            timestamp = time.time()
            self.table[ip_address] = ARPEntry(ip_address, mac_address, timestamp)
            print(f"Entry added: IP {ip_address} -> MAC {mac_address}")
        except Exception as e:
            print(f"Error adding entry: {e}")

    def remove_entry(self, ip_address):
        """
        Elimina una entrada de la tabla ARP.
        """
        try:
            if ip_address in self.table:
                del self.table[ip_address]
                print(f"Entry removed: IP {ip_address}")
            else:
                print(f"IP address {ip_address} not found in ARP table.")
        except Exception as e:
            print(f"Error removing entry: {e}")

    def get_mac(self, ip_address):
        """
        Obtiene la dirección MAC asociada a una dirección IP.
        """
        try:
            return self.table.get(ip_address)
        except Exception as e:
            print(f"Error getting MAC for IP {ip_address}: {e}")
            return None

    def age_entries(self, max_age):
        """
        Elimina las entradas de la tabla ARP que son más viejas que max_age segundos.
        """
        try:
            current_time = time.time()
            for ip_address in list(self.table.keys()):
                if current_time - self.table[ip_address].timestamp > max_age:
                    self.remove_entry(ip_address)
        except Exception as e:
            print(f"Error aging entries: {e}")

def simulate_arp_request(arp_table, ip_address):
    """
    Simula una solicitud ARP.
    """
    try:
        entry = arp_table.get_mac(ip_address)
        if entry:
            print(f"ARP Response: IP {ip_address} -> MAC {entry.mac_address}")
        else:
            print(f"ARP Request: Who has IP {ip_address}?")
            # Simulate the addition of a new ARP entry
            # In a real scenario, this would be a response from the device with the IP address
            simulated_mac = "00:00:00:00:00:01"
            arp_table.add_entry(ip_address, simulated_mac)
            print(f"Simulated ARP Response: IP {ip_address} -> MAC {simulated_mac}")
    except Exception as e:
        print(f"Error simulating ARP request: {e}")

# Crear una tabla ARP y añadir algunas entradas iniciales
arp_table = ARPTable()
arp_table.add_entry("192.168.1.1", "00:11:22:33:44:55")
arp_table.add_entry("192.168.1.2", "66:77:88:99:AA:BB")

# Simular solicitudes ARP
simulate_arp_request(arp_table, "192.168.1.1")
simulate_arp_request(arp_table, "192.168.1.3")

# Simular envejecimiento de entradas (por ejemplo, eliminar entradas más viejas que 60 segundos)
time.sleep(2)  # Esperar 2 segundos para simular el paso del tiempo
arp_table.age_entries(max_age=1)  # Usar un tiempo de envejecimiento de 1 segundo para la prueba

# Mostrar las entradas restantes en la tabla ARP
try:
    for ip, entry in arp_table.table.items():
        print(f"Remaining ARP entry: IP {ip} -> MAC {entry.mac_address}")
except Exception as e:
    print(f"Error displaying ARP entries: {e}")


import json

class VLANManager:
    def __init__(self):
        """
        Inicializa el administrador de VLANs con una tabla vacía.
        """
        self.vlans = {}

    def crear_vlan(self, vlan_id, nombre):
        """
        Crea una nueva VLAN con el ID y nombre proporcionados.
        """
        if vlan_id in self.vlans:
            print(f"Error: Ya existe una VLAN con el ID {vlan_id}.")
            return False
        self.vlans[vlan_id] = {'nombre': nombre, 'dispositivos': []}
        print(f"VLAN {vlan_id} - '{nombre}' creada exitosamente.")
        return True

    def asignar_dispositivo(self, vlan_id, dispositivo):
        """
        Asigna un dispositivo a una VLAN específica.
        """
        if vlan_id not in self.vlans:
            print(f"Error: No se encontró la VLAN con ID {vlan_id}.")
            return False
        if dispositivo in self.vlans[vlan_id]['dispositivos']:
            print(f"Error: El dispositivo {dispositivo} ya está asignado a la VLAN {vlan_id}.")
            return False
        self.vlans[vlan_id]['dispositivos'].append(dispositivo)
        print(f"Dispositivo {dispositivo} asignado a VLAN {vlan_id} exitosamente.")
        return True

    def listar_vlans(self):
        """
        Lista todas las VLANs registradas.
        """
        if not self.vlans:
            print("No hay VLANs registradas.")
            return
        for vlan_id, info in self.vlans.items():
            print(f"VLAN ID: {vlan_id}, Nombre: {info['nombre']}, Dispositivos: {info['dispositivos']}")

    def eliminar_vlan(self, vlan_id):
        """
        Elimina una VLAN específica.
        """
        if vlan_id not in self.vlans:
            print(f"Error: No se encontró la VLAN con ID {vlan_id}.")
            return False
        del self.vlans[vlan_id]
        print(f"VLAN {vlan_id} eliminada exitosamente.")
        return True

    def modificar_nombre_vlan(self, vlan_id, nuevo_nombre):
        """
        Modifica el nombre de una VLAN específica.
        """
        if vlan_id not in self.vlans:
            print(f"Error: No se encontró la VLAN con ID {vlan_id}.")
            return False
        self.vlans[vlan_id]['nombre'] = nuevo_nombre
        print(f"Nombre de VLAN {vlan_id} cambiado a '{nuevo_nombre}' exitosamente.")
        return True

    def buscar_dispositivo(self, dispositivo):
        """
        Busca un dispositivo en todas las VLANs.
        """
        for vlan_id, info in self.vlans.items():
            if dispositivo in info['dispositivos']:
                print(f"Dispositivo {dispositivo} está asignado a VLAN ID {vlan_id}, Nombre: {info['nombre']}")
                return vlan_id, info['nombre']
        print(f"Dispositivo {dispositivo} no está asignado a ninguna VLAN.")
        return None

    def exportar_configuracion(self, archivo):
        """
        Exporta la configuración de VLANs a un archivo JSON.
        """
        try:
            with open(archivo, 'w') as f:
                json.dump(self.vlans, f)
            print(f"Configuración exportada a {archivo} exitosamente.")
        except Exception as e:
            print(f"Error exportando configuración: {e}")

    def importar_configuracion(self, archivo):
        """
        Importa la configuración de VLANs desde un archivo JSON.
        """
        try:
            with open(archivo, 'r') as f:
                self.vlans = json.load(f)
            print(f"Configuración importada desde {archivo} exitosamente.")
        except FileNotFoundError:
            print(f"Error: El archivo {archivo} no existe.")
        except json.JSONDecodeError:
            print(f"Error: El archivo {archivo} no tiene un formato válido.")
        except Exception as e:
            print(f"Error importando configuración: {e}")

# Demostración del uso de la clase VLANManager
if __name__ == "__main__":
    manager = VLANManager()
    manager.crear_vlan(1, "Producción")
    manager.crear_vlan(2, "Desarrollo")
    manager.asignar_dispositivo(1, "00:1A:2B:3C:4D:5E")
    manager.asignar_dispositivo(2, "00:1A:2B:3C:4D:5F")
    manager.listar_vlans()
    manager.modificar_nombre_vlan(2, "Test")
    manager.listar_vlans()
    manager.buscar_dispositivo("00:1A:2B:3C:4D:5E")
    manager.exportar_configuracion("vlans.json")
    manager.eliminar_vlan(2)
    manager.listar_vlans()
    manager.importar_configuracion("vlans.json")
    manager.listar_vlans()


import random
import time
import threading

class VirtualMachine:
    def __init__(self, vm_id, name, cpu, memory):
        """
        Inicializa una máquina virtual con ID, nombre, CPU y memoria.
        """
        self.id = vm_id
        self.name = name
        self.cpu = cpu
        self.memory = memory
        self.state = "stopped"  # Estados: stopped, running, failed

    def start(self):
        """
        Inicia la máquina virtual.
        """
        try:
            if self.state == "stopped":
                self.state = "running"
                print(f"VM {self.name} started.")
            else:
                print(f"VM {self.name} is already running or failed.")
        except Exception as e:
            print(f"Error starting VM {self.name}: {e}")

    def stop(self):
        """
        Detiene la máquina virtual.
        """
        try:
            if self.state == "running":
                self.state = "stopped"
                print(f"VM {self.name} stopped.")
            else:
                print(f"VM {self.name} is not running.")
        except Exception as e:
            print(f"Error stopping VM {self.name}: {e}")

    def restart(self):
        """
        Reinicia la máquina virtual.
        """
        try:
            if self.state == "running":
                self.stop()
                self.start()
                print(f"VM {self.name} restarted.")
            else:
                print(f"VM {self.name} is not running. Cannot restart.")
        except Exception as e:
            print(f"Error restarting VM {self.name}: {e}")

    def fail(self):
        """
        Simula una falla en la máquina virtual.
        """
        try:
            self.state = "failed"
            print(f"VM {self.name} has failed.")
        except Exception as e:
            print(f"Error failing VM {self.name}: {e}")

    def recover(self):
        """
        Recupera la máquina virtual de un estado de falla.
        """
        try:
            if self.state == "failed":
                self.state = "running"
                print(f"VM {self.name} has recovered and is now running.")
            else:
                print(f"VM {self.name} is not in a failed state.")
        except Exception as e:
            print(f"Error recovering VM {self.name}: {e}")

class Hypervisor:
    def __init__(self):
        """
        Inicializa el hipervisor con una lista vacía de máquinas virtuales.
        """
        self.vms = {}
        self.lock = threading.Lock()

    def add_vm(self, vm):
        """
        Añade una máquina virtual al hipervisor.
        """
        try:
            self.vms[vm.id] = vm
            print(f"VM {vm.name} added to hypervisor.")
        except Exception as e:
            print(f"Error adding VM {vm.name}: {e}")

    def remove_vm(self, vm_id):
        """
        Elimina una máquina virtual del hipervisor.
        """
        try:
            if vm_id in self.vms:
                del self.vms[vm_id]
                print(f"VM with ID {vm_id} removed from hypervisor.")
            else:
                print(f"VM with ID {vm_id} does not exist.")
        except Exception as e:
            print(f"Error removing VM with ID {vm_id}: {e}")

    def start_vm(self, vm_id):
        """
        Inicia una máquina virtual específica.
        """
        try:
            if vm_id in self.vms:
                self.vms[vm_id].start()
            else:
                print(f"VM with ID {vm_id} does not exist.")
        except Exception as e:
            print(f"Error starting VM with ID {vm_id}: {e}")

    def stop_vm(self, vm_id):
        """
        Detiene una máquina virtual específica.
        """
        try:
            if vm_id in self.vms:
                self.vms[vm_id].stop()
            else:
                print(f"VM with ID {vm_id} does not exist.")
        except Exception as e:
            print(f"Error stopping VM with ID {vm_id}: {e}")

    def restart_vm(self, vm_id):
        """
        Reinicia una máquina virtual específica.
        """
        try:
            if vm_id in self.vms:
                self.vms[vm_id].restart()
            else:
                print(f"VM with ID {vm_id} does not exist.")
        except Exception as e:
            print(f"Error restarting VM with ID {vm_id}: {e}")

    def simulate_failure(self):
        """
        Simula fallos aleatorios en las máquinas virtuales.
        """
        while True:
            try:
                with self.lock:
                    vm = random.choice(list(self.vms.values()))
                    if vm.state == "running":
                        vm.fail()
                time.sleep(random.randint(5, 10))
            except Exception as e:
                print(f"Error during failure simulation: {e}")

    def auto_recover(self):
        """
        Recupera automáticamente las máquinas virtuales que han fallado.
        """
        while True:
            try:
                with self.lock:
                    for vm in self.vms.values():
                        if vm.state == "failed":
                            vm.recover()
                time.sleep(random.randint(3, 7))
            except Exception as e:
                print(f"Error during auto recovery: {e}")

# Demostración del uso de la clase Hypervisor
if __name__ == "__main__":
    hypervisor = Hypervisor()

    # Crear máquinas virtuales
    vm1 = VirtualMachine(1, "VM1", 2, 4096)
    vm2 = VirtualMachine(2, "VM2", 4, 8192)
    vm3 = VirtualMachine(3, "VM3", 1, 2048)

    # Añadir VMs al hypervisor
    hypervisor.add_vm(vm1)
    hypervisor.add_vm(vm2)
    hypervisor.add_vm(vm3)

    # Iniciar VMs
    hypervisor.start_vm(1)
    hypervisor.start_vm(2)
    hypervisor.start_vm(3)

    # Simulación de fallos y recuperación automática en hilos separados
    failure_thread = threading.Thread(target=hypervisor.simulate_failure, daemon=True)
    recovery_thread = threading.Thread(target=hypervisor.auto_recover, daemon=True)
    failure_thread.start()
    recovery_thread.start()

    # Mantener el programa en ejecución para observar la simulación
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Simulación terminada.")


##Pregunta 1

import logging

class LambdaFunction:
    def __init__(self, name, function_code):
        self.name = name
        self.function_code = function_code
    def execute(self, event):
        exec(self.function_code, {'event': event})

class Event:
    def __init__(self, event_type, data):
        self.event_type = event_type
        self.data = data

class LambdaManager:
    def __init__(self):
        self.functions = {}
    def create_function(self, name, function_code):
        self.functions[name] = LambdaFunction(name, function_code)
        print(f"Función {name} creada.")
    def update_function(self, name, function_code):
        if name in self.functions:
            self.functions[name].function_code = function_code
            print(f"Función {name} actualizada.")
        else:
            print(f"La función {name} no existe.")
    def delete_function(self, name):
        if name in self.functions:
            del self.functions[name]
            print(f"Función {name} eliminada.")
        else:
            print(f"La función {name} no existe.")
    def invoke_function(self, name, event):
        if name in self.functions:
            self.functions[name].execute(event)
            print(f"Función {name} ejecutada.")
        else:
            print(f"La función {name} no existe.")

class EventManager:
    def __init__(self):
        self.triggers = {}
    def add_trigger(self, event_type, function_name):
        if event_type not in self.triggers:
            self.triggers[event_type] = []
        self.triggers[event_type].append(function_name)
        print(f"Disparador agregado: {event_type} -> {function_name}")
    def remove_trigger(self, event_type, function_name):
        if event_type in self.triggers and function_name in self.triggers[event_type]:
            self.triggers[event_type].remove(function_name)
            print(f"Disparador removido: {event_type} -> {function_name}")
    def trigger_event(self, event, lambda_manager):
        if event.event_type in self.triggers:
            for function_name in self.triggers[event.event_type]:
                lambda_manager.invoke_function(function_name, event)

logging.basicConfig(level=logging.INFO)

class LoadBalancer:
    def __init__(self, name):
        self.name = name
        self.servers = []
    def add_server(self, server):
        self.servers.append(server)
    def remove_server(self, server):
        self.servers.remove(server)
    def distribute(self, request):
        raise NotImplementedError("Método distribute no implementado")

class RoundRobinLoadBalancer(LoadBalancer):
    def __init__(self, name):
        super().__init__(name)
        self.current = 0
    def distribute(self, request):
        server = self.servers[self.current]
        self.current = (self.current + 1) % len(self.servers)
        return server

class LeastConnectionsLoadBalancer(LoadBalancer):
    def __init__(self, name):
        super().__init__(name)
        self.connections = {}
    def distribute(self, request):
        if not self.connections:
            self.connections = {server: 0 for server in self.servers}
        server = min(self.servers, key=lambda s: self.connections[s])
        self.connections[server] += 1
        return server

class IPHashLoadBalancer(LoadBalancer):
    def distribute(self, request):
        server = self.servers[hash(request.ip) % len(self.servers)]
        return server

class LoadBalancerManager:
    def __init__(self):
        self.load_balancers = {}
    def create_load_balancer(self, lb_type, name):
        lb_classes = {"round_robin": RoundRobinLoadBalancer,
                      "least_connections": LeastConnectionsLoadBalancer,
                      "ip_hash": IPHashLoadBalancer}
        if lb_type in lb_classes:
            self.load_balancers[name] = lb_classes[lb_type](name)
            print(f"Balanceador de carga {name} de tipo {lb_type} creado.")
    def delete_load_balancer(self, name):
        if name in self.load_balancers:
            del self.load_balancers[name]
            print(f"Balanceador de carga {name} eliminado.")
        else:
            print(f"El balanceador de carga {name} no existe.")
    def add_server_to_lb(self, lb_name, server):
        if lb_name in self.load_balancers:
            self.load_balancers[lb_name].add_server(server)
            print(f"Servidor {server} agregado al balanceador de carga {lb_name}.")
    def remove_server_from_lb(self, lb_name, server):
        if lb_name in self.load_balancers:
            self.load_balancers[lb_name].remove_server(server)
            print(f"Servidor {server} removido del balanceador de carga {lb_name}.")
    def distribute_request(self, lb_name, request):
        if lb_name in self.load_balancers:
            server = self.load_balancers[lb_name].distribute(request)
            print(f"Solicitud distribuida al servidor {server}.")
        else:
            print(f"El balanceador de carga {lb_name} no existe.")

class Request:
    def __init__(self, ip, data):
        self.ip = ip
        self.data = data

def main():
    lambda_manager = LambdaManager()
    event_manager = EventManager()
    lb_manager = LoadBalancerManager()
    while True:
        command = input("Comando (lambda, load_balancer, exit): ")
        if command == "lambda":
            subcommand = input("Subcomando (create, update, delete, trigger, add_trigger, remove_trigger): ")
            if subcommand == "create":
                name = input("Nombre de la función: ")
                code = input("Código de la función: ")
                lambda_manager.create_function(name, code)
            elif subcommand == "update":
                name = input("Nombre de la función: ")
                code = input("Código de la función: ")
                lambda_manager.update_function(name, code)
            elif subcommand == "delete":
                name = input("Nombre de la función: ")
                lambda_manager.delete_function(name)
            elif subcommand == "trigger":
                event_type = input("Tipo de evento: ")
                data = input("Datos del evento: ")
                event = Event(event_type, data)
                event_manager.trigger_event(event, lambda_manager)
            elif subcommand == "add_trigger":
                event_type = input("Tipo de evento: ")
                function_name = input("Nombre de la función: ")
                event_manager.add_trigger(event_type, function_name)
            elif subcommand == "remove_trigger":
                event_type = input("Tipo de evento: ")
                function_name = input("Nombre de la función: ")
                event_manager.remove_trigger(event_type, function_name)
            else:
                print("Subcomando inválido")
        elif command == "load_balancer":
            subcommand = input("Subcomando (create, delete, add_server, remove_server, distribute): ")
            if subcommand == "create":
                lb_type = input("Tipo de balanceador (round_robin, least_connections, ip_hash): ")
                name = input("Nombre del balanceador: ")
                lb_manager.create_load_balancer(lb_type, name)
            elif subcommand == "delete":
                name = input("Nombre del balanceador: ")
                lb_manager.delete_load_balancer(name)
            elif subcommand == "add_server":
                lb_name = input("Nombre del balanceador: ")
                server = input("Nombre del servidor: ")
                lb_manager.add_server_to_lb(lb_name, server)
            elif subcommand == "remove_server":
                lb_name = input("Nombre del balanceador: ")
                server = input("Nombre del servidor: ")
                lb_manager.remove_server_from_lb(lb_name, server)
            elif subcommand == "distribute":
                lb_name = input("Nombre del balanceador: ")
                ip = input("IP de la solicitud: ")
                data = input("Datos de la solicitud: ")
                request = Request(ip, data)
                lb_manager.distribute_request(lb_name, request)
            else:
                print("Subcomando inválido")
        elif command == "exit":
            break
        else:
            print("Comando inválido")

if __name__ == "__main__":
    main()

## Pregunta 2

import random, time
from collections import defaultdict

class DHCP:
    def __init__(self, ip_range):
        self.ip_pool = self.generate_ip_pool(ip_range)
        self.assigned_ips = {}
    def generate_ip_pool(self, ip_range):
        start_ip, end_ip = ip_range.split('-')
        start_ip, end_ip = list(map(int, start_ip.split('.'))), list(map(int, end_ip.split('.')))
        return [f"{start_ip[0]}.{start_ip[1]}.{start_ip[2]}.{i}" for i in range(start_ip[3], end_ip[3] + 1)]
    def assign_ip(self, mac_address):
        if mac_address in self.assigned_ips: return self.assigned_ips[mac_address]
        if not self.ip_pool: raise Exception("No IP addresses available")
        assigned_ip = self.ip_pool.pop(0)
        self.assigned_ips[mac_address] = assigned_ip
        return assigned_ip

class SubnetCalculator:
    def __init__(self, network):
        self.network, self.prefixlen = network.split('/')
        self.prefixlen = int(self.prefixlen)
    def get_network_info(self):
        netmask = self.prefix_to_netmask(self.prefixlen)
        network_address = self.calculate_network_address(self.network, netmask)
        broadcast_address = self.calculate_broadcast_address(network_address, netmask)
        return {'network': network_address, 'netmask': netmask, 'broadcast': broadcast_address, 'num_addresses': 2**(32 - self.prefixlen), 'prefixlen': self.prefixlen}
    def prefix_to_netmask(self, prefixlen):
        mask = (1 << 32) - (1 << (32 - prefixlen))
        return f"{(mask >> 24) & 255}.{(mask >> 16) & 255}.{(mask >> 8) & 255}.{mask & 255}"
    def calculate_network_address(self, ip, netmask):
        ip_bin, netmask_bin = self.ip_to_bin(ip), self.ip_to_bin(netmask)
        return self.bin_to_ip([str(int(ip_bin[i]) & int(netmask_bin[i])) for i in range(32)])
    def calculate_broadcast_address(self, network_address, netmask):
        network_address_bin, netmask_bin = self.ip_to_bin(network_address), self.ip_to_bin(netmask)
        return self.bin_to_ip([str(int(network_address_bin[i]) | (1 - int(netmask_bin[i]))) for i in range(32)])
    def ip_to_bin(self, ip): return ''.join([f"{int(octet):08b}" for octet in ip.split('.')])
    def bin_to_ip(self, ip_bin): return '.'.join([str(int(''.join(ip_bin[i:i+8]), 2)) for i in range(0, 32, 8)])
    def get_subnets(self, new_prefixlen):
        num_subnets = 2 ** (new_prefixlen - self.prefixlen)
        network_address_bin = self.ip_to_bin(self.get_network_info()['network'])
        return [self.bin_to_ip(network_address_bin[:self.prefixlen] + f"{i:0{new_prefixlen - self.prefixlen}b}" + '0' * (32 - new_prefixlen)) + f"/{new_prefixlen}" for i in range(num_subnets)]

class CIDRManager:
    @staticmethod
    def merge_ips_to_cidr(ips):
        sorted_ips, merged, i = sorted(ips, key=lambda ip: CIDRManager.ip_to_bin(ip)), [], 0
        while i < len(sorted_ips):
            start_ip = sorted_ips[i]
            cidr_range, num_ips = CIDRManager.calculate_cidr_range(start_ip, sorted_ips[i:])
            merged.append(cidr_range)
            i += num_ips
        return merged
    @staticmethod
    def calculate_cidr_range(start_ip, ip_list):
        prefixlen, end_idx = 32, 1
        while end_idx < len(ip_list) and ip_list[end_idx].startswith(start_ip[:prefixlen // 8]):
            end_idx += 1
            prefixlen -= 1
        return start_ip + f"/{prefixlen}", end_idx
    @staticmethod
    def divide_cidr(network, new_prefixlen):
        return SubnetCalculator(network).get_subnets(new_prefixlen)
    @staticmethod
    def ip_to_bin(ip): return ''.join([f"{int(octet):08b}" for octet in ip.split('.')])

class VPC:
    def __init__(self, cidr):
        self.network, self.subnets, self.route_table, self.security_rules = cidr, [], defaultdict(list), defaultdict(list)
    def create_subnet(self, cidr): self.subnets.append(cidr)
    def add_route(self, subnet, destination, next_hop): self.route_table[subnet].append((destination, next_hop))
    def add_security_rule(self, subnet, rule): self.security_rules[subnet].append(rule)

class NAT:
    def __init__(self, public_ip): self.public_ip, self.translation_table = public_ip, {}
    def translate(self, private_ip):
        if private_ip not in self.translation_table: self.translation_table[private_ip] = self.public_ip
        return self.translation_table[private_ip]

class VPCPeering:
    def __init__(self, vpc1, vpc2): self.vpc1, self.vpc2 = vpc1, vpc2
    def route_between_vpcs(self, route1, route2):
        self.vpc1.add_route(route1, self.vpc2.network, "VPC Peering")
        self.vpc2.add_route(route2, self.vpc1.network, "VPC Peering")

class TransitGateway:
    def __init__(self): self.vpcs = []
    def connect_vpc(self, vpc):
        self.vpcs.append(vpc)
        for other_vpc in self.vpcs:
            if other_vpc != vpc:
                vpc.add_route(vpc.network, other_vpc.network, "Transit Gateway")
                other_vpc.add_route(other_vpc.network, vpc.network, "Transit Gateway")

class VPN:
    def __init__(self, network1, network2): self.network1, self.network2 = network1, network2
    def create_tunnel(self): print(f"Creando un tunel VPN entre {self.network1} y {self.network2}")

class DirectConnect:
    def __init__(self, local_network, remote_network): self.local_network, self.remote_network = local_network, remote_network
    def establish_connection(self): print(f"Estableciendo conexión Directa entre {self.local_network}  {self.remote_network}")

class DNS:
    def __init__(self): self.records = {}
    def add_record(self, domain, ip): self.records[domain] = ip
    def resolve(self, domain): return self.records.get(domain, "Dominio no encontrado")

class GlobalRouting:
    def __init__(self): self.routes = defaultdict(list)
    def add_route(self, domain, ip, latency): self.routes[domain].append((ip, latency))
    def get_best_route(self, domain): return min(self.routes[domain], key=lambda x: x[1]) if domain in self.routes else "Ruta no definida"

class CDN:
    def __init__(self): self.caches = defaultdict(list)
    def add_content(self, location, content): self.caches[location].append(content)
    def invalidate_content(self, location, content): self.caches[location].remove(content) if content in self.caches[location] else None
    def get_content(self, location): return self.caches[location]

class APIGateway:
    def __init__(self): self.routes, self.rate_limit = {}, {}
    def add_route(self, path, service): self.routes[path] = service
    def set_rate_limit(self, path, limit): self.rate_limit[path] = limit
    def handle_request(self, path):
        if path in self.routes:
            service = self.routes[path]
            if self.rate_limit.get(path, 0) > 0:
                self.rate_limit[path] -= 1
                return service()
            else:
                return "Tasa de limite excedida"
        return "Ruta no encontrada"

# --- Ejemplo de uso ---
dhcp = DHCP("192.168.1.1-192.168.1.254")
print(dhcp.assign_ip("00:1A:2B:3C:4D:5E"))
subnet_calculator = SubnetCalculator("192.168.1.0/24")
print(subnet_calculator.get_network_info())
print(subnet_calculator.get_subnets(26))
cidr_manager = CIDRManager()
ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
print(cidr_manager.merge_ips_to_cidr(ips))
print(cidr_manager.divide_cidr("192.168.1.0/24", 26))
vpc = VPC("10.0.0.0/16")
vpc.create_subnet("10.0.1.0/24")
vpc.add_route("10.0.1.0/24", "0.0.0.0/0", "igw")
vpc.add_security_rule("10.0.1.0/24", "Allow all traffic")
print(vpc.subnets)
print(vpc.route_table)
print(vpc.security_rules)
nat = NAT("203.0.113.1")
print(nat.translate("10.0.1.10"))
vpc1, vpc2 = VPC("10.0.0.0/16"), VPC("10.1.0.0/16")
peering = VPCPeering(vpc1, vpc2)
peering.route_between_vpcs("10.0.0.0/16", "10.1.0.0/16")
print(vpc1.route_table)
print(vpc2.route_table)
tg = TransitGateway()
tg.connect_vpc(vpc1)
tg.connect_vpc(vpc2)
print(vpc1.route_table)
print(vpc2.route_table)
vpn = VPN("192.168.1.0/24", "10.0.0.0/16")
vpn.create_tunnel()
dc = DirectConnect("192.168.1.0/24", "203.0.113.0/24")
dc.establish_connection()
dns = DNS()
dns.add_record("example.com", "93.184.216.34")
print(dns.resolve("example.com"))
gr = GlobalRouting()
gr.add_route("example.com", "93.184.216.34", 10)
gr.add_route("example.com", "93.184.216.35", 20)
print(gr.get_best_route("example.com"))
cdn = CDN()
cdn.add_content("US", "Content 1")
cdn.add_content("EU", "Content 2")
cdn.invalidate_content("US", "Contenido 1")
print(cdn.get_content("US"))
print(cdn.get_content("EU"))
api_gateway = APIGateway()
api_gateway.add_route("/service1", lambda: "Respuesta Service 1 ")
api_gateway.set_rate_limit("/service1", 5)
print(api_gateway.handle_request("/service1"))
print(api_gateway.handle_request("/service1"))
print(api_gateway.handle_request("/service2"))



##Pregunta 3
class EC2Instance:
    def __init__(self, instance_id, instance_type):
        self.instance_id, self.instance_type, self.state = instance_id, instance_type, 'detenida'
        self.attached_volumes = []
    def start(self):
        if self.state == 'detenida':
            self.state = 'en ejecución'
            print(f'Instancia {self.instance_id} iniciada.')
    def stop(self):
        if self.state == 'en ejecución':
            self.state = 'detenida'
            print(f'Instancia {self.instance_id} detenida.')
    def terminate(self):
        self.state = 'terminada'
        print(f'Instancia {self.instance_id} terminada.')
    def attach_volume(self, volume):
        self.attached_volumes.append(volume)
        print(f'Volumen {volume.volume_id} adjuntado a {self.instance_id}.')
    def detach_volume(self, volume):
        self.attached_volumes.remove(volume)
        print(f'Volumen {volume.volume_id} desadjuntado de {self.instance_id}.')

class EBSVolume:
    def __init__(self, volume_id, size):
        self.volume_id, self.size, self.attached_instance = volume_id, size, None
    def attach(self, instance):
        self.attached_instance = instance
        instance.attach_volume(self)
    def detach(self):
        if self.attached_instance:
            self.attached_instance.detach_volume(self)
            self.attached_instance = None

class EFS:
    def __init__(self, efs_id):
        self.efs_id, self.attached_instances = efs_id, []
    def attach(self, instance):
        self.attached_instances.append(instance)
        print(f'EFS {self.efs_id} adjuntado a {instance.instance_id}.')
    def detach(self, instance):
        self.attached_instances.remove(instance)
        print(f'EFS {self.efs_id} desadjuntado de {instance.instance_id}.')

class LambdaFunction:
    def __init__(self, function_name, handler):
        self.function_name, self.handler = function_name, handler
    def update_handler(self, new_handler):
        self.handler = new_handler
        print(f'Handler para {self.function_name} actualizado.')
    def delete(self):
        print(f'Función Lambda {self.function_name} eliminada.')
    def invoke(self, event):
        print(f'Invocando {self.function_name} con el evento {event}.')
        self.handler(event)

class Event:
    def __init__(self, event_type, data):
        self.event_type, self.data = event_type, data

class LoadBalancer:
    def __init__(self, lb_id):
        self.lb_id, self.instances = lb_id, []
    def register_instance(self, instance):
        self.instances.append(instance)
        print(f'Instancia {instance.instance_id} registrada al LB {self.lb_id}.')
    def deregister_instance(self, instance):
        self.instances.remove(instance)
        print(f'Instancia {instance.instance_id} desregistrada del LB {self.lb_id}.')

class ApplicationLoadBalancer(LoadBalancer):
    def distribute_load(self):
        print(f'Distribuyendo carga en ALB {self.lb_id}.')

class AutoScalingGroup:
    def __init__(self, group_name, min_size, max_size):
        self.group_name, self.min_size, self.max_size, self.instances = group_name, min_size, max_size, []
    def scale_up(self):
        if len(self.instances) < self.max_size:
            new_instance = EC2Instance(f'instance_{len(self.instances) + 1}', 't2.micro')
            self.instances.append(new_instance)
            print(f'Añadida la instancia {new_instance.instance_id}.')
    def scale_down(self):
        if len(self.instances) > self.min_size:
            instance_to_remove = self.instances.pop()
            instance_to_remove.terminate()
            print(f'Eliminada la instancia {instance_to_remove.instance_id}.')

class ConsoleInterface:
    def __init__(self):
        self.instances, self.volumes, self.lambda_functions, self.load_balancers, self.auto_scaling_groups = {}, {}, {}, {}, {}
    def create_instance(self, instance_id, instance_type):
        instance = EC2Instance(instance_id, instance_type)
        self.instances[instance_id] = instance
        print(f'Instancia {instance_id} creada.')
    def create_volume(self, volume_id, size):
        volume = EBSVolume(volume_id, size)
        self.volumes[volume_id] = volume
        print(f'Volumen {volume_id} de tamaño {size}GB creado.')
    def create_lambda_function(self, function_name, handler):
        lambda_function = LambdaFunction(function_name, handler)
        self.lambda_functions[function_name] = lambda_function
        print(f'Función Lambda {function_name} creada.')
    def create_load_balancer(self, lb_type, lb_id):
        lb = ApplicationLoadBalancer(lb_id) if lb_type == 'ALB' else None
        self.load_balancers[lb_id] = lb
        print(f'{lb_type} {lb_id} creado.')
    def create_auto_scaling_group(self, group_name, min_size, max_size):
        asg = AutoScalingGroup(group_name, min_size, max_size)
        self.auto_scaling_groups[group_name] = asg
        print(f'Grupo de Autoescalado {group_name} creado.')
    def run(self):
        while True:
            command = input('Ingresa comando: ')
            if command == 'exit':
                break
            try:
                eval(command)
            except Exception as e:
                print(f'Error: {e}')

if __name__ == '__main__':
    interface = ConsoleInterface()
    interface.run()

