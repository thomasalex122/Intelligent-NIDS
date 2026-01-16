from scapy.all import sniff, IP, TCP, UDP, ICMP
from app import db, socketio
from app.models import PacketLog
from config import Config
from collections import defaultdict
import time
import requests # <--- New Library
import ipaddress # <--- To check for private IPs

# --- MEMORY & CACHE ---
scan_tracker = defaultdict(list)
geo_cache = {} # <--- Stores { '1.2.3.4': '🇺🇸 USA' } to avoid slow API calls

def get_location(ip_addr):
    """
    Returns the Country Flag and Code for a given IP.
    Uses caching to prevent rate-limiting.
    """
    # 1. Check Cache first (Fastest)
    if ip_addr in geo_cache:
        return geo_cache[ip_addr]
    
    # 2. Check if Private/Local IP (LAN)
    try:
        ip_obj = ipaddress.ip_address(ip_addr)
        if ip_obj.is_private or ip_obj.is_loopback:
            geo_cache[ip_addr] = "🏠 LAN"
            return "🏠 LAN"
    except ValueError:
        return "Unknown"

    # 3. Ask the API (Only for new Public IPs)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                # Convert country code to Flag Emoji (Python trick)
                country_code = data['countryCode']
                flag = "".join([chr(127397 + ord(c)) for c in country_code.upper()])
                
                location_str = f"{flag} {data['countryCode']}"
                geo_cache[ip_addr] = location_str # Save to memory
                return location_str
    except Exception as e:
        print(f"GeoIP Error: {e}")
    
    # If failed
    return "🌐 NET"

def packet_callback(packet):
    # 1. Extract Details
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
            
        # --- DETECTION LOGIC ---
        current_time = time.time()
        scan_tracker[src_ip].append(current_time)
        scan_tracker[src_ip] = [t for t in scan_tracker[src_ip] if current_time - t < 1.0]
        
        is_attack = False
        if len(scan_tracker[src_ip]) > 20:
            is_attack = True
            print(f"🚨 ALERT: Port Scan Detected from {src_ip}!")
        
        # --- GEO-LOCATION LOOKUP ---
        # Get location for Source IP
        src_location = get_location(src_ip)

        # 2. Save to DB
        new_log = PacketLog(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            dst_port=dst_port,
            payload_preview=str(packet.summary())
        )
        
        try:
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()

        # 3. Send to Dashboard (Now includes 'location')
        socketio.emit('new_packet', {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'dst_port': dst_port,
            'timestamp': new_log.timestamp.strftime('%H:%M:%S'),
            'is_attack': is_attack,
            'location': src_location # <--- Sending the flag!
        })

def start_sniffer_service(app_instance):
    with app_instance.app_context():
        print(f"[*] Sniffer started on interface: {Config.SNIFF_INTERFACE}")
        print(f"[*] Intelligence: ACTIVE")
        print(f"[*] Geo-Location: ACTIVE")
        
        sniff(
            iface=Config.SNIFF_INTERFACE, 
            filter=Config.BPF_FILTER, 
            prn=packet_callback, 
            store=0
        )
