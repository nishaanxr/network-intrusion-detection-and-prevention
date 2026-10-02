# 🛡️ Network Intrusion Detection & Prevention System

## Real-Time Network Intrusion Detection and Automated Prevention System

> A Python-based real-time IDPS that performs packet-level network traffic analysis, detects suspicious activity using rule- and threshold-based techniques, logs security events, and automatically blocks malicious IP addresses.

---

## 🚀 Project Overview

Modern networks are continuously exposed to threats such as port scanning, SYN floods, and ICMP-based flooding attacks.

This project implements a **Real-Time Intrusion Detection and Prevention System (IDPS)** capable of monitoring network packets, identifying suspicious traffic patterns, generating security alerts, and automatically preventing malicious activity through firewall-based IP blocking.

The system combines **Scapy-based packet analysis**, **Flask-powered monitoring**, **SQLite event logging**, and **Linux firewall controls** to provide a practical security monitoring solution.

---

## ⚡ Key Features

- 🔍 **Real-Time Packet Monitoring**
  - Captures and analyzes network packets using Scapy.

- 🛡️ **Intrusion Detection**
  - Rule-based detection
  - Threshold-based anomaly detection

- 🔎 **Port Scan Detection**
  - Identifies suspicious port scanning activity.

- 🌊 **SYN Flood Detection**
  - Detects abnormal TCP SYN traffic patterns.

- 📡 **ICMP Flood Detection**
  - Identifies excessive ICMP traffic associated with flooding attacks.

- 🚫 **Automated Prevention**
  - Automatically blocks suspicious IP addresses using firewall rules.

- 📋 **IP Whitelisting**
  - Allows trusted IP addresses to be excluded from automated blocking.

- 📊 **Real-Time Monitoring Dashboard**
  - Flask-based dashboard for monitoring security activity.

- 📝 **Security Event Logging**
  - Stores detected events and alerts using SQLite.

- 🔔 **Real-Time Alerts**
  - Generates alerts when suspicious network activity is detected.

---

## 🏗️ System Architecture

```text
                    Network Traffic
                           │
                           ▼
                 ┌──────────────────┐
                 │  Packet Capture  │
                 │     Scapy        │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Traffic Analysis │
                 │   TCP / ICMP     │
                 └────────┬─────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │ Intrusion Detection    │
              │                        │
              │ • Port Scan Detection │
              │ • SYN Flood Detection │
              │ • ICMP Flood Detection│
              │ • Threshold Rules      │
              └───────────┬────────────┘
                          │
                 ┌────────┴─────────┐
                 │                  │
                 ▼                  ▼
          ┌─────────────┐    ┌─────────────┐
          │   SQLite    │    │   Alerts    │
          │ Event Logs  │    │ & Monitoring│
          └─────────────┘    └─────────────┘
                 │
                 ▼
          ┌────────────────┐
          │ Prevention     │
          │ Firewall       │
          │ IP Blocking    │
          └────────────────┘
---

## 🧠 Detection Methodology

The system uses a combination of **rule-based detection** and **threshold-based anomaly detection**.

### Port Scanning

The system monitors network traffic for patterns associated with attempts to probe multiple ports on a target system.

### SYN Flood

TCP SYN traffic is monitored for abnormal patterns that may indicate a SYN flood attack.

### ICMP Flood

Excessive ICMP traffic is analyzed to identify potential ICMP flooding activity.

### Threshold-Based Detection

Traffic activity is evaluated against configured thresholds to identify abnormal network behavior.

---

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Packet Capture & Analysis | Scapy |
| Network Monitoring | Raw Packet Inspection, TCP/IP, ICMP |
| Intrusion Detection | Rule-Based Detection, Threshold-Based Anomaly Detection |
| Attack Detection | Port Scanning, SYN Flood, ICMP Flood / DDoS Patterns |
| Prevention | iptables / Windows Firewall (`netsh`) |
| Backend / API | Flask |
| Database / Logging | SQLite |
| Dashboard | HTML, CSS, JavaScript, Flask |
| Alerts | Python Real-Time Alerts & Logging |
| Operating System | Linux / Ubuntu |
| Development Tools | VS Code, Git, GitHub |

---

## 📁 Project Structure

```text
network-intrusion-detection-and-prevention/
│
├── ids.py
├── dashboard.py
│
├── templates/
│   └── index.html
│
├── static/
│   └── app.js
│
├── .gitignore
└── README.md
```

> `ids_alerts.log` is generated during execution and is excluded from version control.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/nishaanxr/network-intrusion-detection-and-prevention.git
cd network-intrusion-detection-and-prevention
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate the Virtual Environment

**Linux / Ubuntu:**

```bash
source .venv/bin/activate
```

**Windows:**

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```bash
pip install scapy flask
```

### 5. Run the IDS

```bash
python ids.py
```

### 6. Start the Dashboard

Open another terminal:

```bash
python dashboard.py
```

---

## 🔐 Prevention

When suspicious activity is detected, the system can automatically block the corresponding IP address using firewall controls.

### Linux

```text
iptables
```

### Windows

```text
netsh / Windows Firewall
```

---

## 📊 Monitoring Dashboard

The Flask-based dashboard provides a monitoring interface for viewing security activity and system information.

The frontend uses:

- HTML
- CSS
- JavaScript
- Flask

---

## 📝 Security Logging

Detected security events are recorded through the system's logging mechanism.

Example event categories include:

```text
Port Scan
SYN Flood
ICMP Flood
Blocked IP
Suspicious Traffic
```

Runtime logs are stored locally and excluded from the Git repository.

---

## 🎯 Project Objectives

- Monitor network traffic in real time
- Detect common network-based attack patterns
- Identify abnormal traffic using configurable thresholds
- Generate security alerts
- Automatically block malicious IP addresses
- Provide a web-based monitoring interface
- Maintain security event records

---

## 🔮 Future Scope

- Machine-learning-based anomaly detection
- Advanced behavioral traffic analysis
- Centralized security event management
- Email / messaging-based alerts
- Cloud-based deployment
- Integration with SIEM platforms
- Distributed network monitoring
- Advanced attack classification

---

## 💡 Learning Outcomes

Through this project, the following areas were explored:

- Network packet analysis
- TCP/IP and ICMP traffic
- Intrusion detection concepts
- Intrusion prevention mechanisms
- Firewall-based security controls
- Python network programming
- Flask web development
- SQLite-based event logging
- Real-time security monitoring

---

## ⭐ Project Highlights

**Python** • **Scapy** • **Flask** • **SQLite** • **TCP/IP** • **IDS/IPS** • **Linux** • **iptables** • **HTML** • **CSS** • **JavaScript**
