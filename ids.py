from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import subprocess
import platform
import threading
import colorama
from colorama import Fore, Style
import os
import time

colorama.init()

PORT_SCAN_THRESHOLD = 3
FLOOD_THRESHOLD = 100
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW = 5
LOG_FILE = "ids_alerts.log"
AUTO_BLOCK = True
WHITELIST = []

blocked_ips = set()
packet_count = defaultdict(list)
port_tracker = defaultdict(set)
brute_force_tracker = defaultdict(list)
lock = threading.Lock()

def log_alert(alert_type, src_ip, detail=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] ALERT | {alert_type} | SRC: {src_ip} | {detail}"
    print(Fore.RED + msg + Style.RESET_ALL)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def block_ip(ip):
    if ip in blocked_ips or ip in WHITELIST:
        return
    blocked_ips.add(ip)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] BLOCKED | IP: {ip}"
    print(Fore.YELLOW + msg + Style.RESET_ALL)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")
    try:
        if platform.system() == "Linux":
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        elif platform.system() == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=BLOCK_{ip}", "dir=in", "action=block",
                f"remoteip={ip}"
            ], check=True)
    except Exception as e:
        print(Fore.MAGENTA + f"[!] Could not auto-block {ip}: {e}" + Style.RESET_ALL)

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    now = time.time()

    with lock:
        packet_count[src_ip].append(now)
        packet_count[src_ip] = [t for t in packet_count[src_ip] if now - t < TIME_WINDOW]
        if len(packet_count[src_ip]) > FLOOD_THRESHOLD:
            log_alert("DoS/Flood Attack", src_ip,
                      f"{len(packet_count[src_ip])} packets in {TIME_WINDOW}s")
            if AUTO_BLOCK:
                block_ip(src_ip)
            return

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            port_tracker[src_ip].add(dst_port)
            if len(port_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                log_alert("Port Scan", src_ip,
                          f"Scanned {len(port_tracker[src_ip])} ports")
                if AUTO_BLOCK:
                    block_ip(src_ip)
                port_tracker[src_ip] = set()

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            if dst_port in (22, 21, 3389):
                brute_force_tracker[src_ip].append(now)
                brute_force_tracker[src_ip] = [
                    t for t in brute_force_tracker[src_ip] if now - t < TIME_WINDOW
                ]
                if len(brute_force_tracker[src_ip]) > BRUTE_FORCE_THRESHOLD:
                    log_alert("Brute Force Attempt", src_ip,
                              f"Port {dst_port} | {len(brute_force_tracker[src_ip])} attempts in {TIME_WINDOW}s")
                    if AUTO_BLOCK:
                        block_ip(src_ip)

        if packet.haslayer(ICMP):
            log_alert("ICMP Packet", src_ip, "ICMP detected (possible ping flood if repeated)")

def print_banner():
    print(Fore.CYAN + """
 ╔══════════════════════════════════════════════════╗
 ║     Real-Time Network Intrusion Detection System ║
 ║          + Automated Prevention (IDS/IPS)        ║
 ╚══════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
    print(f"  {Fore.GREEN}Auto-block:{Style.RESET_ALL} {'ON' if AUTO_BLOCK else 'OFF'}")
    print(f"  {Fore.GREEN}Log file:{Style.RESET_ALL}   {LOG_FILE}")
    print(f"  {Fore.GREEN}Whitelist:{Style.RESET_ALL}  {WHITELIST}")
    print(f"  {Fore.GREEN}Thresholds:{Style.RESET_ALL} Flood={FLOOD_THRESHOLD}pkt | PortScan={PORT_SCAN_THRESHOLD}ports | BruteForce={BRUTE_FORCE_THRESHOLD}attempts")
    print(Fore.CYAN + "\n  [*] Listening for packets... Press Ctrl+C to stop\n" + Style.RESET_ALL)

def show_stats():
    while True:
        time.sleep(30)
        print(Fore.BLUE + f"\n[STATS] Blocked IPs so far: {blocked_ips if blocked_ips else 'None'}" + Style.RESET_ALL)

if __name__ == "__main__":
    print_banner()
    stats_thread = threading.Thread(target=show_stats, daemon=True)
    stats_thread.start()
    try:
        sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[*] IDS stopped. Check ids_alerts.log for full report." + Style.RESET_ALL)