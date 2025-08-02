# jojo-ids-tool
# Intrusion Detection System – Python IDS Tool

## 🔒 About the Project

This is a Python-based Intrusion Detection System (IDS) designed for coursework submission. It supports:

- File system monitoring (creation, deletion, renaming, modifications)
- Network anomaly detection (ICMP, TCP, UDP scans)
- SSH and user login tracking
- Email alerting system
- Signature-based and anomaly-based detection
- Logging to files and/or databases

## 🛠 Features

- Real-time detection and alerts
- Modular Python functions with docstrings and comments
- Email alerts for file changes and suspicious packets
- Uses third-party libraries like `scapy`, `watchdog`, and `sklearn`
- Built-in anomaly detection using Isolation Forest

## 📁 File Structure
/ids_project/
├── main.py
├── file_monitor.py
├── network_monitor.py
├── ssh_login_tracker.py
├── utils/
│ ├── logger.py
│ └── email_alert.py
└── requirements.txt


## ⚙️ Setup & Run

1. Clone the repo:
```bash
git clone https://github.com/jojo-madan/jojo-ids-tool.git
pip install -r requirements.txt
python main.py

