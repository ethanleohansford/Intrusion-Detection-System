# Python Intrusion Detection System (IDS)

A Python-based Intrusion Detection System (IDS) that monitors network traffic for signs of potential attacks, such as **Port Scanning** and **SYN Flooding**. This IDS captures and analyzes TCP packets in real-time, identifying suspicious activity and alerting the user.

## Features
- **Port Scanning Detection**: Detects IP addresses attempting to access multiple ports within a short period, indicating a potential port scan.
- **SYN Flood Detection**: Monitors for an unusually high number of SYN packets from a single IP, which could indicate a SYN flood attack.
- **Real-Time Alerts**: Alerts are printed to the console as soon as potential malicious activity is detected.

## Technologies Used
- **Python**
- **Scapy**: For packet capture and network traffic analysis.

## Requirements
- **Python 3.6+**
- **Scapy** library for Python

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ethanleohansford/Intrusion-Detection-System.git
   cd Intrusion-Detection-System
