import os
from pathlib import Path

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLES_DIR = BASE_DIR / "test_samples"

for directory in (DATA_DIR, UPLOADS_DIR, REPORTS_DIR, SAMPLES_DIR):
    directory.mkdir(parents=True, exist_ok=True)

# Application Config
SECRET_KEY = os.environ.get("SECRET_KEY", "quishguard-soc-secret-key-2026-secure")
DATABASE_URI = os.environ.get("DATABASE_URI", f"sqlite:///{DATA_DIR / 'quishguard.db'}")
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB max

# Threat Intelligence API Keys (optional; falls back to offline curated IOC DB)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

# Redirect Analysis Config
MAX_REDIRECT_HOPS = int(os.environ.get("MAX_REDIRECT_HOPS", 6))
HTTP_TIMEOUT_SECONDS = int(os.environ.get("HTTP_TIMEOUT_SECONDS", 5))
USER_AGENT = os.environ.get(
    "USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 QuishGuard-Security-Scanner/1.0"
)

# Risk Thresholds
RISK_THRESHOLD_SAFE = 20
RISK_THRESHOLD_LOW = 40
RISK_THRESHOLD_SUSPICIOUS = 60
RISK_THRESHOLD_HIGH = 80
# 81-100 is Critical / Dangerous
