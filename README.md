# Network Packet Sniffer with Anomaly Detection

A real-time network traffic analysis tool with intelligent anomaly detection, database logging, and alert system.

## Features

✅ **Real-time Packet Capture** - Captures TCP, UDP, ICMP, and other protocols  
✅ **Anomaly Detection** - Detects port scanning and packet flooding attacks  
✅ **Database Logging** - Stores all packets and anomalies in SQLite database  
✅ **Traffic Visualization** - Generates comprehensive traffic analysis charts  
✅ **Email Alerts** - Sends alerts on threshold breaches  
✅ **GUI Interface** - Live traffic monitoring with interactive graphs  
✅ **CLI Interface** - Command-line operation for headless servers  

## Project Structure

```
├── packet_sniffer.py       # CLI packet sniffer (main application)
├── packet_sniffer_gui.py   # GUI version with live graphs
├── analyze_traffic.py      # Traffic analysis and visualization
├── email_alerter.py        # Email alert system
├── packet_logs.db          # SQLite database (created on first run)
└── README.md              # This file
```

## Requirements

- Python 3.8+
- scapy (packet capture)
- matplotlib (visualization)
- tkinter (GUI - usually pre-installed)
- Root/Administrator privileges (for packet capture)

## Installation

```bash
# Install dependencies
pip install scapy matplotlib --break-system-packages

# Or using requirements file
pip install -r requirements.txt --break-system-packages
```

## Usage

### 1. CLI Packet Sniffer (Recommended for servers)

```bash
# Capture 100 packets
sudo python3 packet_sniffer.py -c 100

# Capture on specific interface
sudo python3 packet_sniffer.py -i eth0

# Capture indefinitely (Ctrl+C to stop)
sudo python3 packet_sniffer.py

# Help
python3 packet_sniffer.py -h
```

**Output:**
- Real-time packet logging
- Anomaly alerts (port scans, flooding)
- Traffic summary on exit
- All data stored in SQLite database

### 2. GUI Packet Sniffer (Recommended for desktops)

```bash
sudo python3 packet_sniffer_gui.py
```

**Features:**
- Start/Stop sniffing with buttons
- Live traffic rate graph (updates every second)
- Real-time packet log display
- Separate alerts tab for anomalies
- Protocol statistics
- Export analysis reports

### 3. Traffic Analysis & Visualization

```bash
python3 analyze_traffic.py
```

**Generates:**
- Detailed text report with statistics
- `traffic_analysis.png` - Comprehensive visualization with:
  - Protocol distribution pie chart
  - Top source IPs bar chart
  - Top destination ports bar chart
  - Traffic summary

### 4. Email Alert System

```bash
# First, configure email settings
nano alert_config.json

# Then run the alerter
python3 email_alerter.py
```

**Configuration** (`alert_config.json`):
```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_email@gmail.com",
    "sender_password": "your_app_password",
    "recipient_emails": ["admin@example.com"],
    "alert_on": {
        "PORT_SCAN": true,
        "FLOODING": true
    },
    "min_severity": "MEDIUM"
}
```

## Anomaly Detection

### Port Scanning Detection
- Triggers when a single IP accesses **10+ unique ports**
- Indicates reconnaissance activity
- Severity: **HIGH**

### Packet Flooding Detection
- Triggers when **100+ packets** received in **10 seconds** from one IP
- Indicates DDoS or flooding attack
- Severity: **CRITICAL**

## Database Schema

### Packets Table
```sql
- id (PRIMARY KEY)
- timestamp (TEXT)
- src_ip (TEXT)
- dst_ip (TEXT)
- src_port (INTEGER)
- dst_port (INTEGER)
- protocol (TEXT)
- length (INTEGER)
- flags (TEXT)
```

### Anomalies Table
```sql
- id (PRIMARY KEY)
- timestamp (TEXT)
- anomaly_type (TEXT)
- source_ip (TEXT)
- description (TEXT)
- severity (TEXT)
```

## Example Queries

```bash
# View database
sqlite3 packet_logs.db

# Get all packets
SELECT * FROM packets LIMIT 10;

# Get anomalies
SELECT * FROM anomalies ORDER BY timestamp DESC;

# Protocol statistics
SELECT protocol, COUNT(*) as count 
FROM packets 
GROUP BY protocol;

# Top talkers
SELECT src_ip, COUNT(*) as packet_count 
FROM packets 
GROUP BY src_ip 
ORDER BY packet_count DESC 
LIMIT 10;
```

## Security Considerations

⚠️ **Root Privileges Required** - Packet capture requires elevated permissions  
⚠️ **Network Privacy** - Ensure compliance with local laws  
⚠️ **Email Credentials** - Use app-specific passwords, not main password  
⚠️ **Database Security** - Protect packet_logs.db from unauthorized access  

## Troubleshooting

**"Permission denied"**
- Run with `sudo` or administrator privileges

**"No module named 'scapy'"**
```bash
pip install scapy --break-system-packages
```

**GUI doesn't display**
- Ensure X11 forwarding is enabled (for remote systems)
- Use CLI version instead: `packet_sniffer.py`

**No packets captured**
- Check network interface: `ip addr` or `ifconfig`
- Specify interface: `sudo python3 packet_sniffer.py -i eth0`

**Email alerts not sending**
- Verify SMTP credentials in `alert_config.json`
- For Gmail: Enable 2FA and create app-specific password
- Check firewall allows SMTP traffic (port 587)

## Performance Tips

- For long captures, use CLI version (lower overhead)
- Limit packet count with `-c` flag for testing
- Run analysis separately to avoid impacting capture
- Database grows with traffic - periodic cleanup recommended

## Example Output

```
[+] Starting packet sniffer...
[+] Interface: All
[+] Packet count: Unlimited
[+] Port scan threshold: 10 unique ports
[+] Flood threshold: 100 packets in 10s
[+] Press Ctrl+C to stop

[10] 192.168.1.100:52341 -> 142.250.185.78:443 | TCP | 66 bytes
[20] 192.168.1.100:52342 -> 142.250.185.78:443 | TCP | 1514 bytes

======================================================================
[!] ALERT: PORT_SCAN
[!] Time: 2026-04-09 14:32:15
[!] Source IP: 192.168.1.200
[!] Details: Possible port scan detected: 12 unique ports accessed
[!] Severity: HIGH
======================================================================

^C
[+] Stopping packet capture...

======================================================================
TRAFFIC SUMMARY
======================================================================
Total packets captured: 1250

Protocol Distribution:
  TCP: 980 (78.4%)
  UDP: 210 (16.8%)
  ICMP: 45 (3.6%)
  OTHER: 15 (1.2%)

Total anomalies detected: 3

Recent Alerts:
  [2026-04-09 14:32:15] PORT_SCAN: Possible port scan detected: 12 unique ports accessed
  [2026-04-09 14:35:22] FLOODING: Flooding detected: 125.3 packets/sec
======================================================================
```

## Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] GeoIP location tracking
- [ ] Protocol-specific deep packet inspection
- [ ] Web dashboard for remote monitoring
- [ ] Integration with SIEM systems
- [ ] Custom alert rules engine

## License

MIT License - Educational and research purposes

## Author

Network Security Research Project

## Disclaimer

This tool is for educational purposes and authorized network monitoring only. 
Ensure you have permission before monitoring any network traffic.
