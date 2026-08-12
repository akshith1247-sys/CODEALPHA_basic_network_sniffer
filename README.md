#CODEALPHA- Basic Network Sniffer
## BASIC NETWORK SNIFFER
- A beginner-friendly python-based network sniffer developed as a cybersecurity learning project

## PROJECT OVERVIEW
This project demonstrates how network packets can be captured and analyzed using 'python' and the 'scapy' library
The sniffer captures packets from the computer's network interface and displays useful information such as:
-source IP address
-destination IP address
-network protocol
-source port
-destination port
-payload length
-payload preview
-packet capture time
The captured packets are also saved in PCAP format for further analysis using tools such as 'wireshark'

## TECHNOLOGIES USED
-python 3
-scapy
-NPCAP (windows)
-wireshark (optional for analyzing PCAP files)

## PROJECT STRUCTURE
NetworkSniffer/
├── sniffer.py
└── README.md
