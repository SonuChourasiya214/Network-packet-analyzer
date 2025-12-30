# Network-packet-analyzer
A simple and educational **Network Packet Analyzer** built using **Python and Scapy**.  
This tool captures and analyzes live network traffic to help understand **packet-level communication**, commonly used in SOC, CEH, and network security learning.

## 📌 Project Overview

The Network Packet Analyzer monitors live network packets and displays key information such as:
- Source IP
- Destination IP
- Protocol type (TCP, UDP, ICMP)
- Source and destination ports
- Timestamp of capture

Captured packets are also **logged to a file** for later analysis.

## 🎯 Objectives

- Learn how packet sniffing works
- Understand TCP/IP protocols in real time
- Practice SOC-style network monitoring
- Build a practical cybersecurity project for GitHub

## 🛠️ Technologies Used

- Python 3
- Scapy
- Linux / Kali Linux

## ✨ Features

- Live packet capture
- TCP, UDP, ICMP protocol detection
- Source & destination IP analysis
- Port identification
- Packet logging to file
- Single-file clean implementation
- Beginner and interview friendly

---

## 📁 Project Structure

network-packet-analyzer/
│
├── packet_analyzer.py
├── packet_logs.txt (auto-generated)
└── README.md

sudo python3 packet_analyzer.py
🧪 Testing the Analyzer
Generate network traffic in another terminal:
ping google.com
nslookup openai.com
Or open any website in a browser.

📊 Sample Output
csharp
Copy code
[TCP] 192.168.1.10 -> 8.8.8.8 Sport:53421 Dport:443
[ICMP] 192.168.1.10 -> 8.8.8.8 Sport:- Dport:-
[UDP] 192.168.1.10 -> 192.168.1.1 Sport:54012 Dport:53
📝 Log File
All captured packets are stored in:
packet_logs.txt
Example:
2025-01-01 13:10:22 | 192.168.1.10 -> 8.8.8.8 | TCP | Sport:53421, Dport:443
🔐 Ethical Disclaimer
This project is strictly for educational purposes only.
Do NOT capture or analyze network traffic without proper authorization.
Unauthorized packet sniffing may be illegal.


🎓 Learning Outcome
This project helps in understanding:
Packet sniffing
Network protocols
SOC monitoring basics
Real-time traffic analysis

👤 Author
Sonu Choursiya
Cybersecurity Learner | SOC & CEH Aspirant

