from flask import render_template, jsonify
from flask import current_app as app
from .models import PacketLog
from . import db

@app.route('/')
def index():
    # This looks for 'index.html' inside the 'templates' folder
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    # A simple API endpoint we can test later
    count = PacketLog.query.count()
    return jsonify({'total_packets': count})
