#!/usr/bin/env python3
"""
GUI Packet Sniffer with Live Traffic Graph
Real-time network monitoring with visual interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import sqlite3
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import time

DB_NAME = "packet_logs.db"
SCAN_THRESHOLD = 10
FLOOD_THRESHOLD = 100
TIME_WINDOW = 10

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - Real-time Monitor")
        self.root.geometry("1200x800")
        
        self.is_sniffing = False
        self.sniffer_thread = None
        self.total_packets = 0
        self.protocol_stats = defaultdict(int)
        self.packet_rate_history = deque(maxlen=60)  # Last 60 seconds
        self.time_stamps = deque(maxlen=60)
        
        # Anomaly detection structures
        self.port_tracker = defaultdict(set)
        self.packet_tracker = defaultdict(lambda: deque(maxlen=FLOOD_THRESHOLD))
        
        self.setup_ui()
        self.init_database()
        self.update_graph()
        
    def init_database(self):
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
        
    def setup_ui(self):
        """Create GUI layout"""
        # Control Panel
        control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Start Sniffing", 
                                    command=self.start_sniffing, width=15)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Sniffing", 
                                   command=self.stop_sniffing, state='disabled', width=15)
        self.stop_btn.pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Clear Logs", 
                  command=self.clear_logs, width=15).pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Export Report", 
                  command=self.export_report, width=15).pack(side='left', padx=5)
        
        # Statistics Panel
        stats_frame = ttk.LabelFrame(self.root, text="Statistics", padding=10)
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        self.stats_label = ttk.Label(stats_frame, text="Total Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0",
                                     font=('Arial', 10))
        self.stats_label.pack()
        
        # Main content area with notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Live Graph Tab
        graph_frame = ttk.Frame(notebook)
        notebook.add(graph_frame, text="Live Traffic Graph")
        
        self.fig = Figure(figsize=(10, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Packet Log Tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Packet Log")
        
        self.packet_log = scrolledtext.ScrolledText(log_frame, height=20, 
                                                    font=('Courier', 9))
        self.packet_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Alerts Tab
        alert_frame = ttk.Frame(notebook)
        notebook.add(alert_frame, text="Alerts")
        
        self.alert_log = scrolledtext.ScrolledText(alert_frame, height=20, 
                                                   font=('Courier', 9), 
                                                   fg='red')
        self.alert_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Status Bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill='x', side='bottom')
        
    def log_packet_db(self, packet_data):
        """Log packet to database"""
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
            pass
            
    def log_anomaly(self, anomaly_type, source_ip, description, severity="MEDIUM"):
        """Log anomaly"""
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
            
            # Display in GUI
            alert_msg = f"[{timestamp}] {severity} - {anomaly_type}\n"
            alert_msg += f"  Source: {source_ip}\n"
            alert_msg += f"  {description}\n\n"
            
            self.alert_log.insert('1.0', alert_msg)
            self.alert_log.see('1.0')
            
        except Exception as e:
            pass
    
    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scanning"""
        if dst_port:
            self.port_tracker[src_ip].add(dst_port)
            if len(self.port_tracker[src_ip]) >= SCAN_THRESHOLD:
                description = f"Port scan: {len(self.port_tracker[src_ip])} unique ports"
                self.log_anomaly("PORT_SCAN", src_ip, description, "HIGH")
                self.port_tracker[src_ip].clear()
    
    def detect_flooding(self, src_ip):
        """Detect packet flooding"""
        current_time = time.time()
        self.packet_tracker[src_ip].append(current_time)
        
        if len(self.packet_tracker[src_ip]) >= FLOOD_THRESHOLD:
            time_diff = current_time - self.packet_tracker[src_ip][0]
            if time_diff <= TIME_WINDOW:
                packets_per_sec = FLOOD_THRESHOLD / time_diff
                description = f"Flooding: {packets_per_sec:.1f} packets/sec"
                self.log_anomaly("FLOODING", src_ip, description, "CRITICAL")
                self.packet_tracker[src_ip].clear()
    
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = "OTHER"
                src_port = None
                dst_port = None
                flags = ""
                
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
                
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                length = len(packet)
                
                # Log to database
                packet_data = (timestamp, src_ip, dst_ip, src_port, dst_port, 
                             protocol, length, flags)
                self.log_packet_db(packet_data)
                
                # Anomaly detection
                self.detect_port_scan(src_ip, dst_port)
                self.detect_flooding(src_ip)
                
                self.total_packets += 1
                
                # Update GUI (every 5 packets to reduce overhead)
                if self.total_packets % 5 == 0:
                    log_msg = f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {protocol} | {length}B\n"
                    self.packet_log.insert('1.0', log_msg)
                    self.update_stats()
                    
        except Exception as e:
            pass
    
    def sniff_packets(self):
        """Packet sniffing thread"""
        try:
            sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.is_sniffing)
        except Exception as e:
            self.status_bar.config(text=f"Error: {e}")
    
    def start_sniffing(self):
        """Start packet capture"""
        self.is_sniffing = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_bar.config(text="Sniffing packets... (Requires root/admin privileges)")
        
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_sniffing = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_bar.config(text="Stopped")
    
    def update_stats(self):
        """Update statistics display"""
        stats_text = f"Total Packets: {self.total_packets} | "
        stats_text += f"TCP: {self.protocol_stats['TCP']} | "
        stats_text += f"UDP: {self.protocol_stats['UDP']} | "
        stats_text += f"ICMP: {self.protocol_stats['ICMP']} | "
        stats_text += f"Other: {self.protocol_stats['OTHER']}"
        self.stats_label.config(text=stats_text)
    
    def update_graph(self):
        """Update live traffic graph"""
        current_time = time.time()
        
        # Calculate packets in last second
        recent_packets = sum(1 for t in self.time_stamps if current_time - t < 1)
        self.packet_rate_history.append(recent_packets)
        
        # Record timestamp for each packet
        if self.is_sniffing:
            self.time_stamps.append(current_time)
        
        # Update plot
        self.ax.clear()
        if len(self.packet_rate_history) > 1:
            self.ax.plot(list(self.packet_rate_history), color='#4ECDC4', linewidth=2)
            self.ax.fill_between(range(len(self.packet_rate_history)), 
                                self.packet_rate_history, alpha=0.3, color='#4ECDC4')
        
        self.ax.set_xlabel('Time (seconds ago)', fontsize=10)
        self.ax.set_ylabel('Packets/sec', fontsize=10)
        self.ax.set_title('Live Packet Rate', fontsize=12, fontweight='bold')
        self.ax.grid(True, alpha=0.3)
        self.ax.set_xlim(0, 60)
        
        self.canvas.draw()
        
        # Schedule next update
        self.root.after(1000, self.update_graph)
    
    def clear_logs(self):
        """Clear log displays"""
        self.packet_log.delete('1.0', tk.END)
        self.alert_log.delete('1.0', tk.END)
        self.status_bar.config(text="Logs cleared")
    
    def export_report(self):
        """Export analysis report"""
        self.status_bar.config(text="Generating report...")
        import subprocess
        subprocess.run(['python3', 'analyze_traffic.py'])
        self.status_bar.config(text="Report exported")

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
