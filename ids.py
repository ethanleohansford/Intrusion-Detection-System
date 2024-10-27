from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration: Customize thresholds
SCAN_THRESHOLD = 20  # Number of ports accessed in a short time for port scanning detection
SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets in a short time for SYN flood detection
TIME_WINDOW = timedelta(seconds=10)  # Time window for counting packets

# Data structures for tracking IP activity
port_scan_tracker = defaultdict(lambda: {"ports": set(), "timestamp": datetime.now()})
syn_flood_tracker = defaultdict(lambda: {"count": 0, "timestamp": datetime.now()})

# Function to detect port scanning
def detect_port_scan(packet):
    src_ip = packet[IP].src
    dst_port = packet[TCP].dport
    
    # Update tracking data for the source IP
    data = port_scan_tracker[src_ip]
    
    # Reset data if the time window has passed
    if datetime.now() - data["timestamp"] > TIME_WINDOW:
        data["ports"].clear()
        data["timestamp"] = datetime.now()
    
    # Add the destination port to the set of accessed ports
    data["ports"].add(dst_port)
    
    # Raise an alert if the threshold for unique ports is exceeded
    if len(data["ports"]) > SCAN_THRESHOLD:
        print(f"[ALERT] Port scan detected from IP {src_ip}")
        data["ports"].clear()  # Reset after alert

# Function to detect SYN flooding
def detect_syn_flood(packet):
    src_ip = packet[IP].src
    
    # Update tracking data for the source IP
    data = syn_flood_tracker[src_ip]
    
    # Reset data if the time window has passed
    if datetime.now() - data["timestamp"] > TIME_WINDOW:
        data["count"] = 0
        data["timestamp"] = datetime.now()
    
    # Increment SYN packet count for the source IP
    data["count"] += 1
    
    # Raise an alert if the SYN packet threshold is exceeded
    if data["count"] > SYN_FLOOD_THRESHOLD:
        print(f"[ALERT] SYN Flood attack detected from IP {src_ip}")
        data["count"] = 0  # Reset after alert

# Main function to process each packet
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Detect port scan by analyzing accessed ports
        detect_port_scan(packet)
        
        # Detect SYN flood by analyzing SYN packet count
        if packet[TCP].flags == "S":  # Check if it's a SYN packet
            detect_syn_flood(packet)

# Start the IDS by sniffing network packets
print("Starting Intrusion Detection System (IDS)...")
sniff(prn=process_packet, filter="tcp", store=0)
