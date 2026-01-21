from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from config import Config

# Initialize Plugins
db = SQLAlchemy()
socketio = SocketIO(cors_allowed_origins="*", async_mode='eventlet')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    socketio.init_app(app)

    # --- DATABASE CREATION ---
    from app.models import PacketLog
    with app.app_context():
        db.create_all()

    # --- ROUTES ---
    @app.route('/')
    def index():
        return render_template('index.html')

    return app
