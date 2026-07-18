Aegis is a fully localized, air-gapped hybrid security auditing platform designed for enterprise environments. It combines deep host-level configuration checks with active network reconnaissance and live packet heuristic analysis.

Built with a modern, multithreaded GUI, Aegis translates raw telemetry and vulnerability data into a severity-ranked, human-readable executive PDF report—all without relying on external cloud APIs, ensuring strict data privacy and GDPR/HIPAA compliance.

✨ Core Features

1. Host Security Auditing: Queries native Windows configurations (PowerShell/WMI/Registry) to audit Firewall states, Antivirus protection, password policies, and USB mass storage controls.

2. Network Surface Reconnaissance: Leverages Nmap to dynamically map local network topology and identify high-risk exposed ports and services.

3. Live Traffic Analysis: Utilizes TShark and Scapy for continuous, background packet sniffing to detect clear-text credential leaks (FTP/Telnet) and high-volume traffic anomalies (e.g., ICMP floods).

4. Admin Security Vault: An authenticated configuration panel (secured via SHA-256) allowing administrators to dynamically adjust multithreading limits, scan timeouts, and deep-audit toggles.

5. Hardware Telemetry: Real-time CPU and RAM monitoring integrated directly into the dashboard to ensure system stability during heavy heuristic parsing.

6. Executive PDF Reporting: Automatically aggregates and sorts findings by severity (Critical, High, Medium, Info) into a professional, downloadable report.

⚙️ Prerequisites & System Requirements

Because Aegis interfaces directly with network hardware and OS-level configurations, it requires a few external system tools to be installed on your Windows machine before running the Python script.

A) System Level Dependencies (Required)
You must download and install the following tools. Ensure you check the box to "Add to System PATH" during their installation.

1. Nmap: Required for the Network Reconnaissance module.

2. Wireshark / TShark: Required for the Live Traffic Analysis module. Ensure Npcap is installed during the Wireshark setup.

3. Administrative Privileges: The application must be run as an Administrator to execute WMI/PowerShell queries and capture live network packets.

B) Python Dependencies

The project requires Python 3.8+. The following Python libraries are required:

1. customtkinter (Modern UI framework)

2. psutil (Hardware telemetry)

3. fpdf2 (PDF report generation)

4. python-nmap (Python wrapper for Nmap)

5. scapy (Deep packet inspection)

🚀 Installation & Setup Instructions
Follow these steps to get Aegis running on your local machine:

Step 1: Clone the Repository

Bash

-> git clone https://github.com/YourUsername/Aegis-Security-Suite.git

-> cd Aegis-Security-Suite

Step 2: Create a Virtual Environment (Recommended)

Bash

-> python -m venv sec_scanner_env

-> sec_scanner_env\Scripts\activate

Step 3: Install Python Packages

Bash

-> pip install -r requirements.txt

(Alternatively, install them manually: pip install customtkinter psutil fpdf2 python-nmap scapy)

Step 4: Launch the Application

Ensure you are running your command prompt or terminal as an Administrator, then launch the suite:

Bash

-> python gui_app.py

🛠️ Usage Guide

Dashboard: Upon launching, enter your Target IP (or leave the default) and select your desired Scan Profile (Full Hybrid, Network Only, or Host Only).

Admin Vault: Click the "⚙️ Admin Settings" button to configure engine limits.

Default Master Key: admin123

Here you can adjust the multithreading process limit (50-500) and port scan timeouts.

Initiate Audit: Click start. The chained execution engine will route the tasks, update the live terminal, and populate the dashboard upon completion.

Export: Once the scan is complete, click Export PDF Report to save a permanent, severity-sorted copy of the findings.

⚠️ Disclaimer
Educational & Ethical Use Only: Aegis is developed strictly for authorized auditing, academic research, and defensive cybersecurity operations. The developers assume no liability and are not responsible for any misuse or damage caused by this software. Never scan targets without explicit, written permission.
