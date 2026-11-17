# VigiCore
### Automated Network Discovery & Vulnerability Assessment Platform for CCTV Cameras and DVR/NVR Systems

**VigiCore** is an enterprise-grade cybersecurity assessment and penetration testing (VAPT) framework designed to automatically discover network-connected devices, fingerprint CCTV cameras and DVR/NVR surveillance infrastructure, assess exposed services, analyze security vulnerabilities, and generate professional audit reports.

Built with an offline-first architecture, VigiCore combines dynamic local network telemetry, multi-vendor device identification, deterministic CVE intelligence, explainable risk scoring, and a modern Apple-inspired dashboard interface.

---

### Key Capabilities

- **Zero-Configuration Dynamic Network Discovery:** Automatically detects the active network interface, Wi-Fi SSID, default gateway, and local subnet CIDR on macOS and Linux without hardcoded addresses.
- **Dual-Mode Discovery Engine:** Supports privileged Layer-2 raw ARP discovery when elevated permissions exist, with seamless automatic fallback to unprivileged kernel-ARP discovery for unprivileged user environments.
- **Multi-Vendor CCTV Fingerprinting:** Accurate classification of IP CCTV Cameras, DVRs, NVRs, Routers, and Workstations across leading surveillance vendors (Hikvision, Dahua, CP Plus, TP-Link VIGI, Uniview, Axis, Reolink, Bosch, Hanwha) using transparent confidence scoring.
- **Comprehensive Service & Vulnerability Assessment:** Detects exposed management interfaces, default ports, RTSP streams, ONVIF endpoints, and matches identified services against CVE databases.
- **Explainable CVSS Risk Scoring:** Provides deterministic risk metrics (0–100) and actionable remediation strategies tailored to surveillance hardening.
- **Persistent Asset Inventory:** SQLite-backed asset repository maintaining state, historical scan records, and user classification overrides across application restarts.
- **Client-Ready PDF Reporting Engine:** Server-side ReportLab reporting system generating publication-ready multi-page audit reports with executive summaries, technical findings, and compliance checklists.
- **Apple-Inspired Web Interface:** Clean light-mode web dashboard (FastAPI + React + Vite + Tailwind CSS) inspired by macOS and iOS design aesthetics.

---

### Architecture

```text
       Authorized Local Network
                  │
                  ▼
   Dynamic Network Telemetry (macOS/Linux)
                  │
                  ▼
   Dual-Engine Host Discovery (ARP / Kernel-ARP)
                  │
                  ▼
   Nmap Service & Version Scanning
                  │
                  ▼
   Multi-Vendor CCTV Fingerprinting & Scoring
                  │
                  ▼
   Vulnerability Assessment & CVE Correlation
                  │
                  ▼
   Explainable Risk Engine (CVSS-Aligned)
                  │
                  ▼
    Persistent SQLite Asset & History DB
                  │
         ┌────────┴────────┐
         ▼                 ▼
   VigiCore Web UI    ReportLab PDF Engine
 (React / Tailwind)   (Audit Documentation)
```

---

### Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Engine** | Python 3, FastAPI, Uvicorn | Core assessment orchestration, REST API, asynchronous worker queue |
| **Network Discovery** | Nmap, Native BSD/Linux Sockets, ARP Cache | Layer-2 / Layer-3 host discovery and service detection |
| **Device Identification** | Custom Multi-Source Rule Engine | OUI lookup, HTTP/RTSP banner inspection, vendor signature analysis |
| **Database** | SQLite 3 (`data/scan_history.db`) | Persistent asset inventory, scan history, and risk tracking |
| **Reporting** | ReportLab | Professional multi-page customer PDF generation |
| **Frontend UI** | React 18, TypeScript, Vite, Tailwind CSS | Responsive, Apple-inspired management and scanning interface |
| **Testing** | Python `unittest` | Rigorous test suite covering API, discovery, database, and reporting |

---

### Current Features

- **Dynamic Network Telemetry:** Automatically identifies active interfaces (`en0`, `eth0`), default gateways, and subnet CIDRs.
- **Resilient Host Discovery:** Executes full ARP scans or unprivileged socket-triggered ARP discoveries with zero-padded MAC normalization.
- **Surveillance Vendor Fingerprinting:** Detects proprietary management ports (e.g., Hikvision 8000, Dahua 37777), RTSP (554), and web interfaces.
- **Asset Inventory Management:** Tracks active, online, and offline devices; supports manual category overrides with persistent storage.
- **Risk Assessment & Scoring:** Computes risk severity (INFO, LOW, MEDIUM, HIGH, CRITICAL) based on open attack surface and CVE matching.
- **Exportable PDF & JSON Reports:** Generates executive-level audit PDFs with compliance verification and raw JSON exports for integration.

---

### Getting Started

#### Prerequisites
- **Operating System:** macOS (Apple Silicon / Intel) or Linux (Ubuntu / Debian / WSL2)
- **Python:** 3.10 or higher
- **Node.js:** 18 or higher (for frontend build)
- **Nmap:** Installed and accessible in system PATH (`/usr/bin/nmap` or `/opt/homebrew/bin/nmap`)

Install Nmap on your system:
- **macOS:** `brew install nmap`
- **Ubuntu/Debian:** `sudo apt update && sudo apt install -y nmap python3 python3-venv python3-pip git`

#### 1. Clone the Repository
```bash
git clone https://github.com/changer0006/cctv-security-scanner.git
cd cctv-security-scanner
```

#### 2. Set Up Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### 3. Build Frontend Assets
```bash
cd frontend
npm install
npm run build
cd ..
```

#### 4. Run the Platform
Start the VigiCore backend server:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

For development with live reloading:
```bash
# Terminal 1: Backend API
source .venv/bin/activate
uvicorn backend.main:app --reload --port 8000

# Terminal 2: Frontend Dev Server
cd frontend
npm run dev
```

Open your browser and navigate to `http://localhost:5173` (or `http://127.0.0.1:8000` when served via backend static files).

---

### Running Tests

Execute the comprehensive test suite to verify discovery, database persistence, fingerprinting, and reporting:
```bash
.venv/bin/python3 -m unittest discover tests
```

---

### Security & Responsible Use

- **Authorized Audits Only:** VigiCore is built for authorized defensive security assessments, penetration testing, and educational audits.
- Only assess networks, CCTV cameras, and DVR/NVR infrastructure that you own or have explicit written authorization to test.
- Keep audit logs, discovered credentials, and generated PDF reports protected against unauthorized access.
- Always verify vulnerability findings against vendor release notes and firmware advisories before implementing configuration changes.

---

### Author

**Sree Ram Kumar**  
B.Tech Computer Science and Engineering — Cybersecurity  
GitHub: [@changer0006](https://github.com/changer0006)

---

### License

All rights reserved. Contact the author for licensing, commercial deployment, or redistribution permissions.
