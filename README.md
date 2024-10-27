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
   ```

2. Install the required dependencies:
   ```bash
   pip install scapy
   ```

## Usage

1. **Run with Elevated Privileges:** Network sniffing requires root privileges. Run the IDS with `sudo` (Linux/Mac) or as an Administrator (Windows).
2. **Start the IDS:**
   ```bash
   sudo python3 ids.py
   ```
   This will start the IDS, which will begin monitoring network traffic for potential threats.

3. **Simulate Attacks for Testing:**
- **Port Scanning:** Use a tool like Nmap to simulate a port scan:
   ```bash
   nmap -p 1-1000 <your_target_ip>
   ```
* **SYN Flooding:** Use a tool like Hping3 to simulate a SYN flood:
   ```bash
   hping3 -S -p 80 --flood <your_target_ip>
   ```
4. **View Alerts:** Alerts will be printed to the console whenever suspicious activity is detected.

## Configuration

Customize detection thresholds in `ids.py:`

`SCAN_THRESHOLD:` Number of unique ports accessed in a short time to trigger a port scan alert.
`SYN_FLOOD_THRESHOLD:` Number of SYN packets in a short time to trigger a SYN flood alert.
`TIME_WINDOW:` Duration (in seconds) for tracking activity within the detection window.
Example:

```python
SCAN_THRESHOLD = 20
SYN_FLOOD_THRESHOLD = 100
TIME_WINDOW = timedelta(seconds=10)
```
## Example Output

When potential malicious activity is detected, alerts are printed like:

```plaintext
[ALERT] Port scan detected from IP 192.168.1.5
[ALERT] SYN Flood attack detected from IP 10.0.0.2
```

## Limitations

This is a basic IDS with some limitations:

- **False Positives:** High network traffic from legitimate sources may trigger alerts.

* **Scalability:** Designed for learning purposes, it may not perform efficiently on high-traffic networks.
Consider extending with machine learning or logging and alert management for advanced functionality.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests for enhancements.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This IDS is for educational purposes only. Always use network monitoring tools responsibly and only on networks you are authorized to test.

   ```plaintext
   This README includes essential details, instructions, and examples, making it easy for users to understand, install, and use your IDS project.
