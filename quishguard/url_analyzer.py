import re
import math
import base64
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Optional
import tldextract

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "goo.gl",
    "bitly.com", "v.gd", "qr.ae", "rb.gy", "t.ly", "shorte.st"
}

# Suspicious high-risk TLDs commonly abused in phishing/quishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "icu",
    "rest", "country", "click", "link", "cam", "fit", "surf", "vip",
    "cn", "ru", "su", "shop", "club", "mom", "monster", "cfd"
}

# Suspicious port numbers
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
    8080, 8443, 8000, 8081, 8880, 9000
}

# Homograph Cyrillic/Greek characters that mimic Latin letters
HOMOGRAPH_MAP = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0455': 's', '\u0445': 'x', '\u0443': 'y',
    '\u0456': 'i', '\u0458': 'j', '\u03bf': 'o', '\u03c1': 'p',
    '\u03b1': 'a', '\u03bd': 'v'
}

def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def is_ip_address(host: str) -> Optional[str]:
    """Check if host is an IPv4, IPv6, or obfuscated IP format."""
    cleaned_host = host.split(':')[0].strip('[]')
    
    # 1. Standard IPv4/IPv6
    try:
        ip = ipaddress.ip_address(cleaned_host)
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        pass

    # 2. Decimal DWORD IP (e.g., http://2130706433)
    if cleaned_host.isdigit():
        try:
            num = int(cleaned_host)
            if 0 <= num <= 4294967295:
                ip = ipaddress.IPv4Address(num)
                return f"Decimal-IP ({ip})"
        except ValueError:
            pass

    # 3. Hexadecimal IP (e.g., 0x7f000001)
    if cleaned_host.lower().startswith("0x"):
        try:
            num = int(cleaned_host, 16)
            if 0 <= num <= 4294967295:
                ip = ipaddress.IPv4Address(num)
                return f"Hex-IP ({ip})"
        except ValueError:
            pass

    return None

def detect_homographs(domain: str) -> Dict[str, Any]:
    """Detect Punycode and lookalike characters in domain."""
    has_punycode = "xn--" in domain.lower()
    found_lookalikes = []
    
    try:
        # Decode punycode to unicode if applicable
        decoded_domain = domain.encode('ascii').decode('idna')
    except Exception:
        decoded_domain = domain

    for char in decoded_domain:
        if char in HOMOGRAPH_MAP:
            found_lookalikes.append(f"'{char}' (looks like '{HOMOGRAPH_MAP[char]}')")

    return {
        "is_punycode": has_punycode,
        "decoded_domain": decoded_domain,
        "has_homographs": len(found_lookalikes) > 0 or has_punycode,
        "lookalikes": found_lookalikes
    }

def extract_registered_domain(url_or_ext) -> str:
    if isinstance(url_or_ext, str):
        ext = tldextract.extract(url_or_ext)
    else:
        ext = url_or_ext
    top = getattr(ext, 'top_domain_under_public_suffix', None)
    if top:
        return top
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or ""

class URLAnalysisResult:
    def __init__(self, raw_payload: str):
        self.raw_payload = raw_payload.strip()
        self.payload_type = "UNKNOWN"
        self.is_url = False
        self.normalized_url = ""
        self.scheme = ""
        self.netloc = ""
        self.hostname = ""
        self.port = None
        self.path = ""
        self.query_string = ""
        self.query_params: Dict[str, List[str]] = {}
        self.fragment = ""
        self.domain = ""
        self.subdomain = ""
        self.suffix = ""
        self.registered_domain = ""
        
        # Risk indicators specific to URL structure
        self.is_ip = False
        self.ip_type = ""
        self.is_shortener = False
        self.is_suspicious_tld = False
        self.is_suspicious_port = False
        self.has_homograph = False
        self.homograph_details: Dict[str, Any] = {}
        self.url_length = len(self.raw_payload)
        self.domain_entropy = 0.0
        self.path_entropy = 0.0
        self.subdomain_count = 0
        self.embedded_urls: List[str] = []
        self.anomalies: List[str] = []

        self._analyze()

    def _analyze(self):
        payload = self.raw_payload
        
        # Detect payload scheme/type
        if re.match(r'^(https?://)', payload, re.IGNORECASE):
            self.payload_type = "HTTP_URL"
            self.is_url = True
        elif re.match(r'^(ftp|sftp)://', payload, re.IGNORECASE):
            self.payload_type = "FTP_URL"
            self.is_url = True
        elif payload.lower().startswith(("market://", "itms-apps://", "intent://", "tg://", "whatsapp://")):
            self.payload_type = "CUSTOM_DEEP_LINK"
            self.is_url = True
        elif payload.lower().startswith("mailto:"):
            self.payload_type = "MAILTO"
        elif payload.lower().startswith("tel:"):
            self.payload_type = "TEL"
        elif payload.upper().startswith("WIFI:"):
            self.payload_type = "WIFI_CONFIG"
        elif "BEGIN:VCARD" in payload.upper():
            self.payload_type = "VCARD"
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', payload):
            # Domain without http schema
            self.payload_type = "HTTP_URL"
            self.is_url = True
            payload = "https://" + payload
        else:
            self.payload_type = "PLAIN_TEXT"

        if not self.is_url:
            return

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(payload)
            self.scheme = parsed.scheme.lower()
            self.netloc = parsed.netloc.lower()
            self.hostname = parsed.hostname or ""
            self.port = parsed.port
            self.path = parsed.path
            self.query_string = parsed.query
            self.fragment = parsed.fragment
            self.query_params = urllib.parse.parse_qs(parsed.query)
            
            # Normalization
            # Reconstruct clean URL
            port_str = f":{self.port}" if self.port and not (
                (self.scheme == "http" and self.port == 80) or
                (self.scheme == "https" and self.port == 443)
            ) else ""
            
            norm_path = self.path if self.path else "/"
            self.normalized_url = f"{self.scheme}://{self.hostname}{port_str}{norm_path}"
            if self.query_string:
                self.normalized_url += f"?{self.query_string}"
            if self.fragment:
                self.normalized_url += f"#{self.fragment}"
        except Exception:
            self.normalized_url = payload
            return

        # Domain breakdown using tldextract
        ext = tldextract.extract(self.normalized_url)
        self.subdomain = ext.subdomain
        self.domain = ext.domain
        self.suffix = ext.suffix
        self.registered_domain = extract_registered_domain(ext)

        # Subdomain count
        if self.subdomain:
            self.subdomain_count = len(self.subdomain.split('.'))

        # Check IP address
        ip_check = is_ip_address(self.hostname)
        if ip_check:
            self.is_ip = True
            self.ip_type = ip_check
            self.anomalies.append(f"Host uses direct IP address instead of domain: {self.ip_type}")

        # Check Shortener
        if self.registered_domain in URL_SHORTENERS or self.hostname in URL_SHORTENERS:
            self.is_shortener = True
            self.anomalies.append(f"URL uses known shortener service ({self.registered_domain}) to conceal destination")

        # Check Suspicious TLD
        if self.suffix.lower() in SUSPICIOUS_TLDS:
            self.is_suspicious_tld = True
            self.anomalies.append(f"Domain uses high-risk suspicious TLD: .{self.suffix}")

        # Check Suspicious Port
        if self.port and self.port in SUSPICIOUS_PORTS:
            self.is_suspicious_port = True
            self.anomalies.append(f"URL specifies unusual or suspicious port: :{self.port}")

        # Homograph and Punycode check
        homo = detect_homographs(self.hostname)
        self.homograph_details = homo
        if homo["has_homographs"]:
            self.has_homograph = True
            self.anomalies.append(f"Homograph / Punycode characters detected in hostname: {', '.join(homo['lookalikes']) if homo['lookalikes'] else 'Punycode encoding'}")

        # Calculate Shannon Entropy
        self.domain_entropy = calculate_shannon_entropy(self.domain)
        self.path_entropy = calculate_shannon_entropy(self.path)
        if self.domain_entropy > 4.2 and len(self.domain) > 10:
            self.anomalies.append(f"High domain entropy ({self.domain_entropy}) suggests algorithmic generation (DGA) or obfuscation")

        # Check excessive subdomains
        if self.subdomain_count >= 3:
            self.anomalies.append(f"Excessive subdomains ({self.subdomain_count} levels): '{self.subdomain}' often used for brand masking")

        # Check excessive URL length
        if self.url_length > 120:
            self.anomalies.append(f"Abnormally long URL ({self.url_length} characters) potentially hiding payloads")

        # Check '@' in URL (userinfo trick to confuse users about destination)
        if "@" in payload:
            self.anomalies.append("URL contains '@' symbol which can disguise actual destination authority")

        # Check embedded URLs in query parameters (open redirect / proxy trick)
        for key, values in self.query_params.items():
            for v in values:
                if re.match(r'^https?://', v, re.IGNORECASE):
                    self.embedded_urls.append(v)
                    self.anomalies.append(f"Embedded URL found in parameter '{key}': potential open redirect or nested payload")
                # Check base64 encoded URL
                if len(v) > 16 and re.match(r'^[A-Za-z0-9+/=]+$', v):
                    try:
                        decoded_bytes = base64.b64decode(v)
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        if decoded_str.startswith(("http://", "https://")):
                            self.embedded_urls.append(decoded_str)
                            self.anomalies.append(f"Base64-encoded URL detected in parameter '{key}': {decoded_str}")
                    except Exception:
                        pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_payload": self.raw_payload,
            "payload_type": self.payload_type,
            "is_url": self.is_url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query_string": self.query_string,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "suffix": self.suffix,
            "registered_domain": self.registered_domain,
            "is_ip": self.is_ip,
            "ip_type": self.ip_type,
            "is_shortener": self.is_shortener,
            "is_suspicious_tld": self.is_suspicious_tld,
            "is_suspicious_port": self.is_suspicious_port,
            "has_homograph": self.has_homograph,
            "homograph_details": self.homograph_details,
            "url_length": self.url_length,
            "domain_entropy": self.domain_entropy,
            "subdomain_count": self.subdomain_count,
            "embedded_urls": self.embedded_urls,
            "anomalies": self.anomalies
        }

def analyze_url(raw_payload: str) -> URLAnalysisResult:
    return URLAnalysisResult(raw_payload)
