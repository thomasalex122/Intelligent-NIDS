from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from config import Config

# 1. Create the Extension Instances
# We create them here, but we don't attach them to the app yet.
db = SQLAlchemy()
socketio = SocketIO(cors_allowed_origins="*") # Allows connections from any origin (good for dev)

def create_app():
    # 2. Create the Flask App
    app = Flask(__name__)
    
    # 3. Load Configuration (Database path, etc.)
    app.config.from_object(Config)

    # 4. Link Extensions to the App
    db.init_app(app)
    socketio.init_app(app)

    # 5. Load the Application Context
    # This allows us to access the database and routes
    with app.app_context():
        from . import routes, models  # Import routes and models here to avoid "Circular Import" errors
        
        # 6. Create Database Tables
        # This looks at models.py and creates the 'nids_log.db' file automatically!
        db.create_all()
        print("[+] Database tables created successfully.")

    return app
