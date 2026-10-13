# 🛡️ QuishGuard: QR Code Malware, Phishing & Dangerous Website Detection Platform

[![QuishGuard CI](https://github.com/MukundSupekar/quishguard-/actions/workflows/ci.yml/badge.svg)](https://github.com/MukundSupekar/quishguard-/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/CyberSOC-Safe--by--Default-00e5ff.svg)](README.md)
[![Tests](https://img.shields.io/badge/Tests-21%20Passed-green.svg)](tests/)

> **A Defense-in-Depth CyberSOC Platform against Quishing (QR Phishing), Evasive Redirects, and Malicious Payload Delivery.**

---

## 📌 1. Project Overview & Problem Statement

**Quishing** (QR Code Phishing) is an evasive cyberattack technique where malicious actors embed dangerous links inside physical or digital QR codes to bypass traditional email gateways, text-based filters, and endpoint detection. Because the malicious payload is rendered visually as a 2D matrix of dark/light modules, conventional network inspection layers fail to evaluate the target URL until a user scans and navigates to the destination on an unmanaged or mobile device.

**QuishGuard** solves this critical security vulnerability by providing an automated, multi-tiered security gateway:
1. **Multi-Strategy QR Decoding**: Uses dual engines (`ZXing-CPP` + `OpenCV`) with adaptive preprocessing (inverted white-on-dark, CLAHE contrast enhancement, Otsu & Gaussian thresholding, and image sharpening) to decode normal, damaged, blurred, or fancy stylized QR codes.
2. **Embedded Document Extraction**: Automatically scans multi-page PDF documents and invoices to discover covertly embedded QR codes.
3. **Deep Lexical & Anomaly Analysis**: Detects IP-based hostnames, decimal/hexadecimal IP obfuscation, Punycode/IDN homograph attacks, Shannon entropy spikes (DGA domains), and suspicious ports.
4. **Safe Redirect Chain Tracing**: Safely unmasks URL shorteners and multi-hop cloaking redirects without executing browser JavaScript or downloading arbitrary binaries.
5. **Brand Impersonation & Typosquatting Heuristics**: Fuzzy matching (Levenshtein distance) against 80+ high-value targets (PayPal, Microsoft, Apple, Chase, Google, Steam, etc.) and credential-harvesting keyword inspection.
6. **Malware & Dangerous File Detection**: Flags high-risk executables, double extensions (e.g. `invoice.pdf.exe`), APKs, macros, and MOTW-bypass disk images (`.iso`, `.vhd`).
7. **Modular Threat Intelligence**: Integrates VirusTotal, Google Safe Browsing, and an offline curated IOC database (100% operational out of the box with zero external API key requirements).
8. **Explainable 0–100 Risk Scoring**: Generates an itemized breakdown of detected risk signals with clear recommendations (`ALLOW`, `CAUTION`, `WARN`, `BLOCK`).
9. **Safe-by-Default Interstitial Warning**: Prevents immediate navigation, presenting an interstitial barrier with technical findings and return-to-safety guidance.
10. **SOC Analytics & SIEM Integration**: Provides real-time dashboard telemetry, Common Event Format (CEF) log exports, and automated containment playbooks.

---

## 🏗️ 2. System Architecture

```
                       [ Input Sources ]
             ┌─────────────┬─────────────┬─────────────┐
             │ Live Camera │ Image Upload│ PDF Document│ URL String  │
             └──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┘
                    │             │             │             │
                    ▼             ▼             ▼             │
             ┌─────────────────────────────────────────┐      │
             │       Multi-Strategy QR Decoder         │      │
             │ - ZXing-CPP Engine                      │      │
             │ - OpenCV Dual Detector                  │      │
             │ - CLAHE / Inverted / Otsu Preprocessing │      │
             └────────────────────┬────────────────────┘      │
                                  │                           │
                                  └─────────────┬─────────────┘
                                                ▼
                             ┌──────────────────────────────────────┐
                             │       URL Normalization Engine       │
                             │ - Punycode / Homograph Detection     │
                             │ - Obfuscated IP (Dec/Hex) Detection  │
                             │ - Shannon Entropy Calculation        │
                             └──────────────────┬───────────────────┘
                                                ▼
                             ┌──────────────────────────────────────┐
                             │      Safe Redirect Chain Tracer      │
                             │ - Safe HEAD/GET Streaming Probe      │
                             │ - URL Shortener Unmasking            │
                             │ - Loop & Cross-Domain Hop Detection  │
                             └──────────────────┬───────────────────┘
                                                ▼
            ┌───────────────────────────────────┴───────────────────────────────────┐
            ▼                                   ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────┐           ┌───────────────────────┐
│   Phishing Engine     │           │    Malware Engine     │           │ Threat Intelligence   │
│ - Brand Impersonation │           │ - Weaponized .exe/.scr│           │ - VirusTotal v3       │
│ - Typosquatting Fuzzy │           │ - Double Extension    │           │ - Google Safe Browsing│
│ - Credential Keywords │           │ - Drive-By Patterns   │           │ - Curated IOC DB      │
│ - Coercive Urgency    │           │ - EICAR Test Marker   │           │ - Local SOC Blocklist │
└───────────┬───────────┘           └───────────┬───────────┘           └───────────┬───────────┘
            └───────────────────────────────────┼───────────────────────────────────┘
                                                ▼
                             ┌──────────────────────────────────────┐
                             │      Multi-Factor Risk Engine        │
                             │ - 0 to 100 Calibrated Score          │
                             │ - Tier: Safe / Low / Susp / Phish/Mal│
                             │ - Itemized Forensic Explanations     │
                             └──────────────────┬───────────────────┘
                                                ▼
     ┌──────────────────────────────────────────┼──────────────────────────────────────────┐
     ▼                                          ▼                                          ▼
┌──────────────────────┐              ┌──────────────────────┐              ┌──────────────────────┐
│  Safe Interstitial   │              │   SOC Analytics &    │              │ Forensic Reporting   │
│  - Threat Warning    │              │   Threat Management  │              │ - Downloadable PDF   │
│  - Block Navigation  │              │ - Metric KPIs        │              │ - Structured JSON    │
│  - Return to Safety  │              │ - Chart.js Telemetry │              │ - CEF / SIEM Export  │
└──────────────────────┘              │ - Response Playbooks │              └──────────────────────┘
                                      └──────────────────────┘
```

---

## 🚀 3. Quickstart & Installation

### Prerequisites
- Python 3.10+ (Tested on Python 3.11 Windows/Linux/macOS)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### Installation Steps

1. **Clone or Navigate to the Project Directory**:
   ```bash
   cd c:\Users\Admin\Documents\Project
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate Demonstration Test Assets**:
   ```bash
   python generate_test_samples.py
   ```
   *Generates sample QR images representing Safe, Shortener, Brand Phishing, Malware Dropper, Inverted Stylized QR, and an invoice PDF with embedded QR code.*

4. **Run the Application**:
   ```bash
   python app.py
   ```

5. **Access the Web Interface**:
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 🛡️ 4. Key Capabilities & Walkthrough

### 1. Live Camera Scanner
- Directly uses the client-side device camera via WebRTC.
- Renders an interactive viewfinder reticle with real-time scanline animation.
- Triggers a clear audio confirmation tone upon QR decoding.
- Automatically pauses the camera and performs deep threat inspection without exposing the user's browser.

### 2. File Upload & Fancy/Inverted QR Decoding
- Accepts PNG, JPG, JPEG, BMP, and WEBP formats.
- Preprocesses images through histogram equalization, Otsu binarization, Gaussian adaptive thresholding, and color inversion (supporting dark-mode stylized QR codes).

### 3. PDF Document Extraction
- Parses multi-page PDF documents to isolate raster image streams.
- Scans each image with the dual QR engine to detect embedded phishing QR codes hidden in invoices, delivery slips, or payment requests.

### 4. Direct URL Analyzer
- Allows direct submission of suspect links.
- Includes 5 one-click scenario presets for immediate demonstration:
  - 🟢 **Safe University**: `https://www.ox.ac.uk/research` (Score: 0 / Safe)
  - 🟡 **Shortener Chain**: `https://tinyurl.com/quish-test-doc` (Score: 30 / Low Risk)
  - 🔴 **PayPal Typosquat**: `https://paypa1-security-check.xyz/login/verify?account=urgent` (Score: 85 / Phishing)
  - 🔴 **Malware Dropper**: `http://evil-payload-dist.org/downloads/setup_invoice.pdf.exe` (Score: 90 / Malware)
  - ⛔ **EICAR Test Site**: `https://www.eicar.org/download-anti-malware-testfile/` (Score: 85 / Critical)

### 5. Safe Browsing Interstitial Barrier
- Whenever a destination scores $\ge 40$, QuishGuard intercepts the navigation flow.
- Displays an interstitial warning screen explaining why the destination is dangerous and provides a single-click "🛡️ Back to Safety" option.

### 6. Forensic Reporting (PDF & JSON)
- Downloads printable PDF reports styled with executive summaries, risk score badges, indicator tables, hop details, and SOC signatures.

### 7. SOC Analytics & SIEM Integration
- Real-time Chart.js graphs tracking threat distributions and frequently targeted domains.
- ArcSight / Microsoft Sentinel Common Event Format (CEF) log feed via `/api/siem/events?format=cef`.
- One-click containment playbooks to blacklist domains and create SOC Incident tickets.

---

## 📡 5. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan/image` | Upload image file (`multipart/form-data`) and execute security pipeline. |
| `POST` | `/api/scan/camera` | Submit base64 video frame or decoded payload string from camera. |
| `POST` | `/api/scan/pdf` | Upload PDF document and scan embedded images for QR codes. |
| `POST` | `/api/scan/url` | Direct URL deep inspection (`{"url": "https://..."}`). |
| `GET` | `/api/scan/<id>` | Fetch detailed scan result JSON. |
| `GET` | `/api/history` | Retrieve historical scan telemetry with optional filters. |
| `GET` | `/api/report/<id>` | Download forensic report (`?format=pdf` or `?format=json`). |
| `GET` | `/api/dashboard` | Retrieve live SOC KPI metrics and chart telemetry. |
| `GET` | `/api/siem/events` | Stream SIEM events (`?format=cef` or `?format=json`). |
| `POST` | `/api/playbook/action`| Execute incident response actions (`BLOCK_DOMAIN`, `CREATE_INCIDENT`). |

---

## 🧪 6. Automated Testing

To run the complete automated test suite:

```bash
# Run unit tests for detection and heuristic engines
python -m unittest tests/test_detection.py

# Run API integration tests
python -m unittest tests/test_api.py

# Or discover all tests
python -m unittest discover tests
```

---

## 🎓 7. Project Presentation & Viva Defense Points

1. **Why is Quishing different from standard Email Phishing?**
   - QR codes are images, completely opaque to conventional text-based Natural Language Processing (NLP) email filters. Attackers use this to evade Secure Email Gateways (SEGs) and transfer the attack surface onto mobile devices.
2. **How does QuishGuard handle URL obfuscation?**
   - It performs IP-address deobfuscation (decimal/hex IP tricks), Punycode/IDN homograph analysis (detecting lookalike Cyrillic characters), and Shannon entropy calculations on the domain name.
3. **What prevents redirect cloaking?**
   - The safe redirect tracer conducts hop-by-hop analysis with size limits, timeout guards, and loop checks, exposing multi-hop shortener chains before the client visits the final landing page.
4. **Why is Safe-by-Default essential?**
   - Standard mobile camera apps immediately redirect upon QR scan. QuishGuard strictly decouples scanning from navigation: **Scan $\rightarrow$ Decode $\rightarrow$ Analyze $\rightarrow$ Warn $\rightarrow$ User Decision**.

---

## 📄 License
Educational & Cybersecurity Research Project.
