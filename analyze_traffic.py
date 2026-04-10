#!/usr/bin/env python3
"""
Packet Sniffer Analytics & Visualization Tool
Query and visualize captured packet data
"""

import sqlite3
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
from datetime import datetime
import sys

DB_NAME = "packet_logs.db"

class PacketAnalyzer:
    def __init__(self):
        self.conn = None
        
    def connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect(DB_NAME)
            return True
        except Exception as e:
            print(f"[!] Error connecting to database: {e}")
            return False
    
    def get_packet_stats(self):
        """Get overall packet statistics"""
        cursor = self.conn.cursor()
        
        # Total packets
        cursor.execute("SELECT COUNT(*) FROM packets")
        total = cursor.fetchone()[0]
        
        # Protocol distribution
        cursor.execute("""
            SELECT protocol, COUNT(*) as count 
            FROM packets 
            GROUP BY protocol 
            ORDER BY count DESC
        """)
        protocols = cursor.fetchall()
        
        # Top source IPs
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count 
            FROM packets 
            GROUP BY src_ip 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_sources = cursor.fetchall()
        
        # Top destination IPs
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count 
            FROM packets 
            GROUP BY dst_ip 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_destinations = cursor.fetchall()
        
        return {
            'total': total,
            'protocols': protocols,
            'top_sources': top_sources,
            'top_destinations': top_destinations
        }
    
    def get_anomalies(self):
        """Get all anomalies"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT timestamp, anomaly_type, source_ip, description, severity 
            FROM anomalies 
            ORDER BY timestamp DESC
        """)
        return cursor.fetchall()
    
    def get_port_stats(self):
        """Get statistics on most accessed ports"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT dst_port, COUNT(*) as count 
            FROM packets 
            WHERE dst_port IS NOT NULL 
            GROUP BY dst_port 
            ORDER BY count DESC 
            LIMIT 15
        """)
        return cursor.fetchall()
    
    def visualize_traffic(self, output_file="traffic_analysis.png"):
        """Create comprehensive traffic visualization"""
        stats = self.get_packet_stats()
        port_stats = self.get_port_stats()
        
        if stats['total'] == 0:
            print("[!] No packets in database to visualize")
            return
        
        # Create figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Network Traffic Analysis', fontsize=16, fontweight='bold')
        
        # 1. Protocol Distribution (Pie Chart)
        if stats['protocols']:
            protocols = [p[0] for p in stats['protocols']]
            counts = [p[1] for p in stats['protocols']]
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8']
            
            axes[0, 0].pie(counts, labels=protocols, autopct='%1.1f%%', 
                          colors=colors[:len(protocols)], startangle=90)
            axes[0, 0].set_title('Protocol Distribution', fontweight='bold')
        
        # 2. Top Source IPs (Bar Chart)
        if stats['top_sources']:
            sources = [s[0] for s in stats['top_sources'][:10]]
            source_counts = [s[1] for s in stats['top_sources'][:10]]
            
            axes[0, 1].barh(range(len(sources)), source_counts, color='#4ECDC4')
            axes[0, 1].set_yticks(range(len(sources)))
            axes[0, 1].set_yticklabels(sources, fontsize=8)
            axes[0, 1].set_xlabel('Packet Count')
            axes[0, 1].set_title('Top 10 Source IPs', fontweight='bold')
            axes[0, 1].invert_yaxis()
        
        # 3. Top Destination Ports (Bar Chart)
        if port_stats:
            ports = [f"Port {p[0]}" for p in port_stats[:10]]
            port_counts = [p[1] for p in port_stats[:10]]
            
            axes[1, 0].bar(range(len(ports)), port_counts, color='#FF6B6B', alpha=0.7)
            axes[1, 0].set_xticks(range(len(ports)))
            axes[1, 0].set_xticklabels(ports, rotation=45, ha='right', fontsize=8)
            axes[1, 0].set_ylabel('Packet Count')
            axes[1, 0].set_title('Top 10 Destination Ports', fontweight='bold')
        
        # 4. Traffic Summary (Text)
        anomalies = self.get_anomalies()
        summary_text = f"""
TRAFFIC SUMMARY

Total Packets: {stats['total']:,}

Protocol Breakdown:
{chr(10).join([f"  • {p[0]}: {p[1]:,} packets" for p in stats['protocols'][:5]])}

Anomalies Detected: {len(anomalies)}
{chr(10).join([f"  • {a[1]}: {a[3]}" for a in anomalies[:3]]) if anomalies else "  None detected"}

Database: {DB_NAME}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """.strip()
        
        axes[1, 1].text(0.1, 0.5, summary_text, fontsize=9, 
                       verticalalignment='center', fontfamily='monospace',
                       bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
        axes[1, 1].axis('off')
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[+] Visualization saved to: {output_file}")
        
    def print_report(self):
        """Print detailed text report"""
        stats = self.get_packet_stats()
        anomalies = self.get_anomalies()
        
        print("\n" + "="*80)
        print("NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*80)
        
        print(f"\nTotal Packets Captured: {stats['total']:,}")
        
        print("\n--- PROTOCOL DISTRIBUTION ---")
        for protocol, count in stats['protocols']:
            percentage = (count / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {protocol:10s}: {count:6d} packets ({percentage:5.1f}%)")
        
        print("\n--- TOP 10 SOURCE IPs ---")
        for idx, (ip, count) in enumerate(stats['top_sources'], 1):
            print(f"  {idx:2d}. {ip:15s} : {count:6d} packets")
        
        print("\n--- TOP 10 DESTINATION IPs ---")
        for idx, (ip, count) in enumerate(stats['top_destinations'], 1):
            print(f"  {idx:2d}. {ip:15s} : {count:6d} packets")
        
        print(f"\n--- ANOMALIES DETECTED ({len(anomalies)}) ---")
        if anomalies:
            for timestamp, atype, source, desc, severity in anomalies[:10]:
                print(f"  [{timestamp}] {severity:8s} | {atype:15s} | {source:15s}")
                print(f"    └─ {desc}")
        else:
            print("  No anomalies detected")
        
        print("\n" + "="*80)
        print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

def main():
    analyzer = PacketAnalyzer()
    
    if not analyzer.connect():
        print(f"[!] Could not connect to database: {DB_NAME}")
        print("[!] Make sure the packet sniffer has been run first")
        sys.exit(1)
    
    print("[+] Generating analysis report...")
    analyzer.print_report()
    
    print("[+] Creating visualization...")
    analyzer.visualize_traffic()
    
    analyzer.close()
    print("\n[+] Analysis complete!")

if __name__ == "__main__":
    main()
