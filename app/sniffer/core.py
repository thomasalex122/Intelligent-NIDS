import logging
from scapy.all import *
from app import socketio
from collections import defaultdict
from datetime import datetime
import os

# --- CONFIGURATION: ACTIVE DEFENSE ---
# 1. Whitelist: IPs that will NEVER be blocked (Safety Net)
# Add your Windows IP here if you know it (e.g., '192.168.1.5') to prevent locking yourself out.
WHITELIST = {
    '127.0.0.1',       # Localhost
    '0.0.0.0',         # Broadcast
    '192.168.1.1',     # Router Gateway
    '8.8.8.8',         # Google DNS
}

# 2. Blocked Memory: Remembers who is banned so we don't spam the firewall
BLOCKED_IPS = set()

# 3. Connection Tracking: Counts packets per second for each IP
connection_count = defaultdict(int)
last_reset_time = datetime.now()

def block_ip(ip_address):
    """
    Executes the Linux Firewall command to drop all packets from an attacker.
    """
    # Safety Checks
    if ip_address in WHITELIST:
        print(f"⚠️ SAFETY: Skipped blocking Whitelisted IP: {ip_address}")
        return
    if ip_address in BLOCKED_IPS:
        return

    print(f"🚫 ACTIVATING IPS: Blocking Attacker {ip_address}...")
    
    # THE KILL COMMAND: Tells Linux Kernel to DROP packets from this IP
    os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
    
    # Update Memory
    BLOCKED_IPS.add(ip_address)

    # Notify Dashboard (Update the Firewall Log UI)
    socketio.emit('ip_blocked', {
        'ip': ip_address,
        'time': datetime.now().strftime("%H:%M:%S"),
        'reason': 'Port Scan / Flood Detected'
    })

def packet_callback(packet):
    global last_reset_time, connection_count

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine Protocol Name
        if proto == 6: protocol_name = 'TCP'
        elif proto == 17: protocol_name = 'UDP'
        elif proto == 1: protocol_name = 'ICMP'
        else: protocol_name = 'Other'

        # Get Destination Port (if applicable)
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0

        # --- DETECTION LOGIC ---
        
        # 1. Reset counters every 1 second
        current_time = datetime.now()
        if (current_time - last_reset_time).total_seconds() > 1:
            connection_count.clear()
            last_reset_time = current_time

        # 2. Count packets from this IP
        connection_count[src_ip] += 1
        
        # 3. CHECK RULE: Is this an attack? (>15 packets/sec)
        is_threat = False
        if connection_count[src_ip] > 15:
            is_threat = True
            
            # >>> TRIGGER ACTIVE DEFENSE <<<
            block_ip(src_ip)

        # --- SEND TO DASHBOARD ---
        socketio.emit('new_packet', {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol_name,
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'is_threat': is_threat
        })

# ... (rest of your imports and code) ...

# CHANGE THIS LINE (Add *args)
def start_sniffer_service(*args):
    """Starts the packet capture loop."""
    print("🛡️  Intelligent NIDS Started...")
    print("🔥 Active Defense (IPS) is ENABLED.")
    try:
        # Sniff on eth0. Store=0 prevents memory leaks.
        sniff(iface="eth0", prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error in sniffer: {e}")
