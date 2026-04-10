#!/usr/bin/env python3
"""
Demo Script - Generate Sample Traffic Data
Creates realistic packet logs and anomalies for demonstration
"""

import sqlite3
from datetime import datetime, timedelta
import random

DB_NAME = "packet_logs.db"

def init_database():
    """Initialize database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, src_ip TEXT, dst_ip TEXT,
            src_port INTEGER, dst_port INTEGER,
            protocol TEXT, length INTEGER, flags TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, anomaly_type TEXT, source_ip TEXT,
            description TEXT, severity TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def generate_sample_data():
    """Generate realistic sample traffic data"""
    print("[+] Generating sample traffic data...")
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Sample IP addresses
    internal_ips = [f"192.168.1.{i}" for i in range(100, 120)]
    external_ips = [
        "142.250.185.78",  # Google
        "172.217.164.142", # Google
        "13.107.42.14",    # Microsoft
        "151.101.1.140",   # Reddit
        "52.85.151.34",    # Amazon
        "104.244.42.1",    # Twitter
        "31.13.71.36",     # Facebook
        "8.8.8.8",         # DNS
        "1.1.1.1",         # Cloudflare DNS
    ]
    
    protocols = ["TCP", "UDP", "ICMP"]
    common_ports = [80, 443, 22, 21, 25, 53, 3389, 3306, 5432, 8080]
    tcp_flags = ["S", "SA", "A", "PA", "F", "R"]
    
    # Generate 500 normal packets
    base_time = datetime.now() - timedelta(minutes=30)
    
    for i in range(500):
        timestamp = (base_time + timedelta(seconds=random.randint(0, 1800))).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips)
        protocol = random.choice(protocols)
        
        if protocol == "TCP":
            src_port = random.randint(49152, 65535)
            dst_port = random.choice(common_ports)
            flags = random.choice(tcp_flags)
            length = random.randint(60, 1500)
        elif protocol == "UDP":
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([53, 123, 161, 162])
            flags = ""
            length = random.randint(60, 1400)
        else:  # ICMP
            src_port = None
            dst_port = None
            flags = ""
            length = random.randint(60, 100)
        
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                               protocol, length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags))
    
    # Generate port scan packets
    scanner_ip = "10.0.0.50"
    scan_time = datetime.now() - timedelta(minutes=15)
    
    print("[+] Injecting port scan activity...")
    for port in range(20, 40):  # Scan 20 ports
        timestamp = (scan_time + timedelta(seconds=port-20)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                               protocol, length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, scanner_ip, internal_ips[0], random.randint(49152, 65535), 
              port, "TCP", 60, "S"))
    
    # Log port scan anomaly
    cursor.execute('''
        INSERT INTO anomalies (timestamp, anomaly_type, source_ip, description, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (scan_time.strftime("%Y-%m-%d %H:%M:%S"), "PORT_SCAN", scanner_ip, 
          "Possible port scan detected: 20 unique ports accessed", "HIGH"))
    
    # Generate flooding packets
    flooder_ip = "203.0.113.45"
    flood_time = datetime.now() - timedelta(minutes=5)
    
    print("[+] Injecting packet flooding activity...")
    for i in range(150):
        timestamp = (flood_time + timedelta(milliseconds=i*50)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                               protocol, length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, flooder_ip, internal_ips[5], random.randint(49152, 65535), 
              80, "TCP", random.randint(60, 1500), "S"))
    
    # Log flooding anomaly
    cursor.execute('''
        INSERT INTO anomalies (timestamp, anomaly_type, source_ip, description, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (flood_time.strftime("%Y-%m-%d %H:%M:%S"), "FLOODING", flooder_ip, 
          "Flooding detected: 150.0 packets/sec", "CRITICAL"))
    
    # Add one more suspicious activity
    cursor.execute('''
        INSERT INTO anomalies (timestamp, anomaly_type, source_ip, description, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', ((datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"), 
          "PORT_SCAN", "172.16.0.99", 
          "Possible port scan detected: 15 unique ports accessed", "HIGH"))
    
    conn.commit()
    conn.close()
    
    print(f"[+] Generated 650+ packets and 3 anomalies")
    print(f"[+] Database: {DB_NAME}")

def main():
    print("="*60)
    print("Network Packet Sniffer - Demo Data Generator")
    print("="*60 + "\n")
    
    init_database()
    generate_sample_data()
    
    print("\n[+] Sample data generated successfully!")
    print("[+] Now run: python3 analyze_traffic.py")
    print("="*60)

if __name__ == "__main__":
    main()
