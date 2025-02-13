Cloud DDoS Mitigation & Detection System:

Overview:
This project provides a DDoS Mitigation Architecture (Mermaid diagram) and a DDoS Detection Tool (Python script) for analyzing traffic, detecting attacks, and applying mitigation strategies.

1. DDoS Mitigation Architecture
Located in cloud-ddos-architecture.mermaid, this diagram outlines:

Security Layer: WAF, Load Balancer, DDoS Detection Engine
Application Layer: Web Servers handling traffic
Monitoring Layer: Metrics Collection, Alerts, Auto Scaling
Traffic flows through WAF → Load Balancer → Web Servers, with real-time analytics identifying threats and triggering mitigations.

2. DDoS Detection Tool
Found in ddos-detection-tool.py, this tool:
✅ Tracks request rates, error codes, and behavior anomalies
✅ Logs traffic metrics to InfluxDB
✅ Blocks malicious IPs & applies rate limiting
✅ Triggers auto-scaling for endpoint flooding

Usage
Install dependencies:
bash
pip install numpy scikit-learn influxdb-client

Run the detection script:
bash:
python ddos-detection-tool.py
