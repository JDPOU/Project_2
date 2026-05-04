WireMegalo: Enhanced Network Forensic Analyzer

A professional-grade, real-time network forensic tool built with Python, Flask, and Scapy. This project provides live packet capture, automated DNS forensic analysis, and performance-optimized monitoring.



🚀 Key Features

Real-Time Capture \& Analysis: Start/Stop packet capture via the web dashboard with live-updating traffic statistics.



DNS Forensic Module (pap.py): Automatically classifies DNS queries for potential threats, flagging suspicious TLDs (e.g., .xyz, .top) and high-entropy domain strings often used in C2 traffic.



Sliding-Window Buffer: Implements a strict 100-packet FIFO buffer, ensuring stable memory usage during 24/7 capture sessions.



Dynamic UI Architecture: Features a "Global Modal" system for stable, non-intrusive viewing of raw packet forensics.



Protocol-Aware Filtering: Toggle between "All" traffic and "DNS Only" views in real-time.



PCAP Forensic Analysis: Upload saved .pcap files for offline parsing and risk reporting.



🧰 Prerequisites

Python 3.x



Network Driver:



Windows: You must install Npcap. During installation, ensure the box "Install Npcap in WinPcap API-compatible mode" is checked.



Linux: Ensure libpcap-dev is installed (sudo apt-get install libpcap-dev).



⚙️ Setup Instructions

1\. Clone \& Setup Environment

Bash

git clone https://github.com/JDPOU/Project/_2.git

cd Project\_2\_updated/app



2\. Create Virtual Environment

Windows:



Bash

python -m venv venv

venv\\Scripts\\activate



Linux/macOS:



Bash

python3 -m venv venv

source venv/bin/activate



3\. Install Dependencies

Bash

pip install flask scapy

🖥️ Running the Application

Launch the server:



Windows (Command Prompt/PowerShell):



Bash

python app.py

Linux (Requires root for packet sniffing):



Bash

sudo venv/bin/python app.py

Access the dashboard:

Open your browser and navigate to http://127.0.0.1:5000



📁 Folder Structure

Plaintext

Project\_2\_updated/

└── app/

&#x20;   ├── app.py              # Main Flask server \& API routes

&#x20;   ├── packetAnalyzer.py   # Sniffing logic \& sliding window buffer

&#x20;   ├── pap.py              # DNS Forensic parser \& risk classifier

&#x20;   ├── analysis.log        # System logs

&#x20;   ├── static/

&#x20;   │   └── style.css       # Custom UI styling

&#x20;   └── templates/

&#x20;       ├── base.html       # Shared navigation and layout

&#x20;       ├── index.html      # Main dashboard with real-time graph

&#x20;       ├── dns.html        # DNS specific forensic view

&#x20;       └── upload.html     # PCAP upload interface



📝 Troubleshooting \& Notes

Administrative Privileges: Scapy requires raw socket access to read network traffic. On Windows, ensure you run your terminal as Administrator. On Linux, you must run the application with sudo.



Memory Management: The system is hard-coded to maintain only the 100 most recent packets to prevent browser and server performance degradation.



No Dependencies on SocketIO: This version uses efficient fetch() polling, eliminating the need for flask-socketio or eventlet.

