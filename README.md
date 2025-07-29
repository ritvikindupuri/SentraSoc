# 🔒 SentraSOC

**SentraSOC** is a containerized, simulated Security Operations Center (SOC) platform that detects real-time cyber threats mapped to the [MITRE ATT&CK framework](https://attack.mitre.org/). It is designed for hands-on learning, detection engineering, and cybersecurity demo environments using safely simulated attack traffic.

---

## 📊 Project Overview

SentraSOC is composed of three modular Docker containers:
- **threat-detector**: Monitors logs and behaviors to generate real-time alerts
- **soc-dashboard**: A browser-based triage UI that maps alerts to MITRE techniques
- **soc-demo-contr**: Simulates adversarial behaviors like DNS tunneling and privilege escalation

All components communicate over isolated ports and simulate a working SOC pipeline.

---

## 🛡️ Key Features

- ✅ **Real-Time Alerting** – Behavioral detection engine processes live log events
- 🧠 **MITRE ATT&CK Mapping** – Each alert is tagged with corresponding TTPs (e.g., T1548, T1005)
- 📈 **SOC Dashboard** – Displays alert severity, types (Behavioral, DNS), timestamps, and triage options
- ⚙️ **Containerized Microservices** – Built with Docker for reproducibility and portability
- 💡 **Educational Use** – Safe, offline environment ideal for blue team training or interviews

---

## 🧪 Simulated Threat Types

| Threat Type              | MITRE Technique | Description |
|--------------------------|-----------------|-------------|
| DNS Tunneling            | T1041           | Simulated C2 beaconing to `evil.com`, `botnet-controller.biz` |
| Privilege Escalation     | T1548           | Emulates shell commands or root-level access |
| Multi-Stage Attack Flow  | T1190 → T1005   | Shows progression from exploitation to data access |
| Script Execution         | T1059           | Python and shell command triggers with anomalous behavior |

> ⚠️ _All attacks are **simulated** and meant for safe lab/demonstration use only._

---


## 🧱 System Architecture

```text
+-----------------+        +--------------------+       +-----------------+
| soc-demo-contr  | -----> |  threat-detector   | --->  |  soc-dashboard  |
| (Attack Sim)    |        | (Log Parsing &     |       | (Alert Display) |
|                 |        |  Alert Generation) |       |                 |
+-----------------+        +--------------------+       +-----------------+
            Docker Network / Shared Volumes / Port Bindings






🚀 How to Run Locally
🔧 Prerequisites
Docker installed: https://www.docker.com/products/docker-desktop

🛠️ Build & Start Containers
bash
Copy
Edit
git clone https://github.com/your-username/sentra-soc.git
cd sentra-soc
docker-compose up --build
🌐 Access the Dashboard
Once all containers are running, open:

arduino
Copy
Edit
http://localhost:8080
Replace 8080 with the mapped port if customized in docker-compose.yml.

📂 Project Structure
plaintext
Copy
Edit
sentra-soc/
├── docker-compose.yml
├── threat-detector/
│   └── detector.py
├── soc-dashboard/
│   └── dashboard.html
├── soc-demo-contr/
│   └── simulate_attacks.py
└── README.md
🌟 Future Enhancements
🔒 Add authentication to the dashboard

📤 Enable alert export (CSV, JSON, email)

📊 Integrate with Prometheus/Grafana for container telemetry

🔁 Add more attack simulations (e.g., brute-force, lateral movement)

☁️ Optional cloud deployment (AWS/GCP-ready)

