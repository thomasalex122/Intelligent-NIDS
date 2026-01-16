import os

class Config:
    SECRET_KEY = 'secret-key-for-dev'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///../data/nids_log.db'

    # NETWORK CONFIG
    SNIFF_INTERFACE = "eth0"

    # FILTER RULES (This was missing!)
    # We ignore port 5000 so we don't sniff our own dashboard traffic
    # We ignore port 443 so YouTube/Netflix doesn't crash the app
    BPF_FILTER = "ip and (tcp or udp or icmp) and not port 5000 and not port 443"
