from scapy.all import sniff, IP, TCP, UDP, ICMP
from app import db, socketio
from app.models import PacketLog
from config import Config
from collections import defaultdict
import time
import requests
import ipaddress

# Global Variables
scan_tracker = defaultdict(list)
geo_cache = {}

def get_location(ip_addr):
    """Returns the Country Flag for a given IP."""
    if ip_addr in geo_cache:
        return geo_cache[ip_addr]
    
    try:
        ip_obj = ipaddress.ip_address(ip_addr)
        if ip_obj.is_private or ip_obj.is_loopback:
            geo_cache[ip_addr] = "🏠 LAN"
            return "🏠 LAN"
    except ValueError:
        return "Unknown"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=2)
        if response.status_code == 200 and response.json()['status'] == 'success':
            country = response.json()['countryCode']
            flag = "".join([chr(127397 + ord(c)) for c in country.upper()])
            loc = f"{flag} {country}"
            geo_cache[ip_addr] = loc
            return loc
    except:
        pass
    
    return "🌐 NET"

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "OTHER"
        dst_port = "-"

        if TCP in packet:
            proto = "TCP"
            dst_port = str(packet[TCP].dport)
        elif UDP in packet:
            proto = "UDP"
            dst_port = str(packet[UDP].dport)
        elif ICMP in packet:
            proto = "ICMP"
            
        # --- ATTACK DETECTION (Velocity Check) ---
        current_time = time.time()
        scan_tracker[src_ip].append(current_time)
        # Keep only packets from the last 1 second
        scan_tracker[src_ip] = [t for t in scan_tracker[src_ip] if current_time - t < 1.0]
        
        is_attack = False
        if len(scan_tracker[src_ip]) > 20: # RULE: >20 packets/sec = Attack
            is_attack = True
            print(f"🚨 ALERT: Scan from {src_ip}")
        
        # Get Location
        src_location = get_location(src_ip)

        # Send to Dashboard
        socketio.emit('new_packet', {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'dst_port': dst_port,
            'timestamp': time.strftime('%H:%M:%S'),
            'is_attack': is_attack,
            'location': src_location
        })

def start_sniffer_service(app_instance):
    with app_instance.app_context():
        print(f"[*] Sniffer started on {Config.SNIFF_INTERFACE}")
        sniff(iface=Config.SNIFF_INTERFACE, prn=packet_callback, store=0)
