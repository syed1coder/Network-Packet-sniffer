#!/usr/bin/env python3
"""
Network Packet Sniffer with Anomaly Detection
Real-time packet capture with port scanning and flooding detection
"""

import sqlite3
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import argparse
import sys

# Configuration
DB_NAME = "packet_logs.db"
SCAN_THRESHOLD = 10  # Number of unique ports from same IP to trigger port scan alert
FLOOD_THRESHOLD = 100  # Packets per second to trigger flood alert
TIME_WINDOW = 10  # Seconds for anomaly detection window

class PacketSniffer:
    def __init__(self, interface=None, packet_count=0):
        self.interface = interface
        self.packet_count = packet_count
        self.total_packets = 0
        self.anomalies = []
        
        # Tracking structures for anomaly detection
        self.port_tracker = defaultdict(set)  # IP -> set of ports
        self.packet_tracker = defaultdict(lambda: deque(maxlen=FLOOD_THRESHOLD))  # IP -> timestamps
        self.protocol_stats = defaultdict(int)
        
        # Initialize database
        self.init_database()
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
    def init_database(self):
        """Initialize SQLite database for packet logging"""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                flags TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                anomaly_type TEXT,
                source_ip TEXT,
                description TEXT,
                severity TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[+] Database initialized: {DB_NAME}")
        
    def log_packet(self, packet_data):
        """Log packet to SQLite database"""
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                                   protocol, length, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', packet_data)
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Database error: {e}")
            
    def log_anomaly(self, anomaly_type, source_ip, description, severity="MEDIUM"):
        """Log detected anomaly to database and alerts list"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies (timestamp, anomaly_type, source_ip, description, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, anomaly_type, source_ip, description, severity))
            
            conn.commit()
            conn.close()
            
            # Add to in-memory alerts
            alert = {
                'timestamp': timestamp,
                'type': anomaly_type,
                'source': source_ip,
                'description': description,
                'severity': severity
            }
            
            with self.lock:
                self.anomalies.append(alert)
            
            # Print alert
            print(f"\n{'='*70}")
            print(f"[!] ALERT: {anomaly_type}")
            print(f"[!] Time: {timestamp}")
            print(f"[!] Source IP: {source_ip}")
            print(f"[!] Details: {description}")
            print(f"[!] Severity: {severity}")
            print(f"{'='*70}\n")
            
        except Exception as e:
            print(f"[!] Error logging anomaly: {e}")
    
    def detect_port_scan(self, src_ip, dst_port):
        """Detect potential port scanning activity"""
        if dst_port:
            self.port_tracker[src_ip].add(dst_port)
            
            if len(self.port_tracker[src_ip]) >= SCAN_THRESHOLD:
                description = f"Possible port scan detected: {len(self.port_tracker[src_ip])} unique ports accessed"
                self.log_anomaly("PORT_SCAN", src_ip, description, "HIGH")
                # Reset tracker after alert
                self.port_tracker[src_ip].clear()
    
    def detect_flooding(self, src_ip):
        """Detect packet flooding/DDoS attempts"""
        current_time = time.time()
        self.packet_tracker[src_ip].append(current_time)
        
        # Check if we have enough packets in the deque
        if len(self.packet_tracker[src_ip]) >= FLOOD_THRESHOLD:
            time_diff = current_time - self.packet_tracker[src_ip][0]
            
            if time_diff <= TIME_WINDOW:
                packets_per_sec = FLOOD_THRESHOLD / time_diff
                description = f"Flooding detected: {packets_per_sec:.1f} packets/sec"
                self.log_anomaly("FLOODING", src_ip, description, "CRITICAL")
                # Clear tracker after alert
                self.packet_tracker[src_ip].clear()
    
    def process_packet(self, packet):
        """Process and analyze each captured packet"""
        try:
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = "OTHER"
                src_port = None
                dst_port = None
                flags = ""
                
                # Extract protocol-specific information
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = str(packet[TCP].flags)
                    self.protocol_stats['TCP'] += 1
                    
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    self.protocol_stats['UDP'] += 1
                    
                elif ICMP in packet:
                    protocol = "ICMP"
                    self.protocol_stats['ICMP'] += 1
                    
                else:
                    self.protocol_stats['OTHER'] += 1
                
                # Packet metadata
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                length = len(packet)
                
                # Log packet to database
                packet_data = (timestamp, src_ip, dst_ip, src_port, dst_port, 
                             protocol, length, flags)
                self.log_packet(packet_data)
                
                # Anomaly detection
                self.detect_port_scan(src_ip, dst_port)
                self.detect_flooding(src_ip)
                
                # Increment counter
                with self.lock:
                    self.total_packets += 1
                
                # Display packet info (every 10 packets to avoid spam)
                if self.total_packets % 10 == 0:
                    print(f"[{self.total_packets}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol} | {length} bytes")
                    
        except Exception as e:
            print(f"[!] Error processing packet: {e}")
    
    def start_sniffing(self):
        """Start packet capture"""
        print("[+] Starting packet sniffer...")
        print(f"[+] Interface: {self.interface if self.interface else 'All'}")
        print(f"[+] Packet count: {self.packet_count if self.packet_count > 0 else 'Unlimited'}")
        print(f"[+] Port scan threshold: {SCAN_THRESHOLD} unique ports")
        print(f"[+] Flood threshold: {FLOOD_THRESHOLD} packets in {TIME_WINDOW}s")
        print("[+] Press Ctrl+C to stop\n")
        
        try:
            if self.packet_count > 0:
                sniff(iface=self.interface, prn=self.process_packet, 
                     count=self.packet_count, store=False)
            else:
                sniff(iface=self.interface, prn=self.process_packet, store=False)
                
        except KeyboardInterrupt:
            print("\n[+] Stopping packet capture...")
        except PermissionError:
            print("[!] Permission denied. Run with sudo/administrator privileges")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
            
    def print_summary(self):
        """Print traffic summary"""
        print("\n" + "="*70)
        print("TRAFFIC SUMMARY")
        print("="*70)
        print(f"Total packets captured: {self.total_packets}")
        print(f"\nProtocol Distribution:")
        for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        
        print(f"\nTotal anomalies detected: {len(self.anomalies)}")
        if self.anomalies:
            print("\nRecent Alerts:")
            for alert in self.anomalies[-5:]:  # Show last 5 alerts
                print(f"  [{alert['timestamp']}] {alert['type']}: {alert['description']}")
        
        print("="*70)

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer with Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_sniffer.py -c 100              # Capture 100 packets
  sudo python3 packet_sniffer.py -i eth0            # Capture on eth0 interface
  sudo python3 packet_sniffer.py                     # Capture indefinitely
        """
    )
    
    parser.add_argument('-i', '--interface', type=str, 
                       help='Network interface to sniff (e.g., eth0, wlan0)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    
    args = parser.parse_args()
    
    # Create and start sniffer
    sniffer = PacketSniffer(interface=args.interface, packet_count=args.count)
    sniffer.start_sniffing()
    sniffer.print_summary()

if __name__ == "__main__":
    main()
