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
