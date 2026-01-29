# --- MUST BE FIRST ---
import eventlet
eventlet.monkey_patch()

# --- NOW IMPORT OTHERS ---
from app import create_app, socketio
from app.sniffer.core import start_sniffer_service
import threading

app = create_app()

if __name__ == '__main__':
    print("[-] Starting Intelligent NIDS...")
    
    # Start Sniffer in Background
    # We use socketio.start_background_task instead of threading for better compatibility
    socketio.start_background_task(start_sniffer_service)

    print("[+] Web Dashboard Active at http://0.0.0.0:5000")
    # debug=False is safer for threads
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
