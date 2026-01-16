from . import db
from datetime import datetime

class PacketLog(db.Model):
    # This is the name of the table in the SQL database
    __tablename__ = 'packet_logs'

    # 1. Unique ID for every single packet (Primary Key)
    id = db.Column(db.Integer, primary_key=True)

    # 2. When did it happen? (Default to current time)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    # 3. Who sent it? (Source IP)
    src_ip = db.Column(db.String(50), nullable=False)

    # 4. Who was it for? (Destination IP)
    dst_ip = db.Column(db.String(50), nullable=False)

    # 5. What language were they speaking? (TCP, UDP, ICMP)
    protocol = db.Column(db.String(10), nullable=False)

    # 6. Which door did they knock on? (Port number, e.g., 80, 22)
    # We store as String because sometimes it's "-" or multiple
    dst_port = db.Column(db.String(10), nullable=True)

    # 7. The Payload (Optional: The actual data inside, snippets only)
    payload_preview = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        return f"<Packet {self.id}: {self.src_ip} -> {self.dst_ip}>"
