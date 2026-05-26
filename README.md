# Network Intrusion Detection & Security Simulation Suite (Major Project)

An integrated, Python-powered network security ecosystem designed for live network scanning, packet capture, intrusion detection (IDS), vulnerability assessment, and controlled attack simulation. The platform features an extensible JSON-based rule engine, statistical threshold filtering, real-time logging/alerting, and a tabbed Graphical User Interface (GUI) alongside evaluation tools to visualize system performance.

## 🚀 Key Features

- **Live Traffic Capture & Inspection**: Monitors network interfaces in real time, dissects packet layers, and normalizes incoming headers and payloads for processing.
- **Dual-Engine Detection**:
  - **Rule-Based & Signatures**: Evaluates active connections against user-defined patterns (`rules.json`) to catch known malicious vectors.
  - **Advanced Payload Detection**: Deeply inspects packet data fields for indicators of compromise (IoCs), malformed structures, or shellcode scripts.
- **Volumetric Anomaly Analysis**: Flags high-rate events like DDoS attacks, brute-force attempts, or stealthy port scans by calculating signature-based traffic thresholds.
- **Network & Vulnerability Scanning**: Discovers active network hosts, fingerprints open ports, and checks targeted entities for potential security weaknesses.
- **Interactive Tabbed GUI**: A multi-tab dashboard that unifies traffic feeds, historical alert logs, scanner triggers, and settings into an accessible interface.
- **Controlled Attack Simulator**: A comprehensive testing module that reliably generates synthetic attack traffic to validate and benchmark the IDS detection accuracy.
- **Performance Evaluation**: Logs detailed `.txt` validation reports and evaluates precision, recall, and accuracy via an offline confusion matrix analysis notebook.

---

## 📂 Project Architecture

```text
├── attacks/                       # Templates and scripts for specific attack models
├── logs/                          # Automatically generated runtime logs and threat alerts
├── mdfile/                        # Supplemental project documentation assets
├── advanced_payload_detection.py  # Deep packet inspection (DPI) and heuristic payload matching
├── alert.py                       # Core alert data modeling and classification
├── confusion_matrix_analysis.ipynb# Evaluation metrics (Accuracy, Precision, Recall, Confusion Matrix)
├── detection.py                   # Main IDS engine combining signatures and statistical rules
├── example_complete_workflow.py   # Step-by-step pipeline example (Scan -> Capture -> Detect -> Alert)
├── gui.py                         # Application main window initialization and loop
├── gui_tabs.py                    # Modular UI tab layout configurations (Logs, Scanners, Monitors)
├── hotspot_monitor.py             # Dedicated tracking module for wireless interfaces and hostspots
├── integration_adapter.py         # Broker module orchestrating communication between UI and backend threads
├── main.py                        # System entry point
├── network_scanner.py             # ARP/ICMP discovery tools to map local subnets
├── normalization.py               # Sanitization and structural alignment of raw packet headers
├── notifications.py               # Dispatcher for OS desktop alerts or external notification streams
├── packet_capture.py              # Interface sniffer handling multi-threaded packet queuing (Scapy-driven)
├── requirements.txt               # Software dependencies
├── rule_engine.py                 # Conditional engine evaluating packets against rules
├── rules.json                     # Customizable JSON database containing attack signatures
├── signature_based_thresholds.py  # Tracks dynamic limits for traffic spikes and packet volume drops
├── simulate_attacks.py            # Executable engine for spinning up synthetic security threats
└── vuln_scanner.py                # Port auditor and signature-based vulnerability scanner
