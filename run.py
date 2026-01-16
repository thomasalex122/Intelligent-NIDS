import eventlet
# Essential: Monkey patch allows the server to handle many connections at once
# This MUST be the very first line
eventlet.monkey_patch()

from app import create_app, socketio
from app.sniffer.core import start_sniffer_service

# 1. Create the REAL App instance
app = create_app()

if __name__ == '__main__':
    print("[-] Starting Intelligent NIDS...")
    
    # 2. Start the Sniffer in a Background Task
    # CRITICAL CHANGE: We pass 'app' as an argument to the function.
    # This links the sniffer to the running web server.
    socketio.start_background_task(start_sniffer_service, app)
    
    print("[+] Web Dashboard Active at http://0.0.0.0:5000")
    
    # 3. Run the Server
    # use_reloader=False prevents the code from running twice
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)
