# Contributing to QuishGuard

Thank you for your interest in contributing to **QuishGuard: QR Malware & Phishing Defense Platform**!

We welcome contributions from cybersecurity researchers, students, and open-source developers.

---

## 🛠️ How to Contribute

1. **Fork the Repository** on GitHub.
2. **Clone your fork**:
   ```bash
   git clone https://github.com/<your-username>/quishguard.git
   cd quishguard
   ```
3. **Create a new feature branch**:
   ```bash
   git checkout -b feature/awesome-detection-module
   ```
4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
5. **Implement your changes** and add unit tests under `tests/`.
6. **Run the test suite** to ensure all tests pass:
   ```bash
   python -m unittest discover tests
   python verify_samples.py
   ```
7. **Commit with conventional commit messages**:
   ```bash
   git commit -m "feat(phishing): add new brand lookalike heuristics"
   ```
8. **Push to your fork** and submit a **Pull Request**.

---

## 🛡️ Coding Guidelines

- **Safety First**: Never commit live malicious payloads or real malware samples. Use test domains or EICAR standard patterns.
- **Privacy & Security**: Never log or store credentials. Follow Safe-by-Default architecture.
- **Explainability**: Every detection rule or risk factor must include clear, itemized forensic explanations.
