import time
import requests
import urllib.parse
import urllib3
from typing import List, Dict, Any, Optional
import tldextract
from quishguard.config import MAX_REDIRECT_HOPS, HTTP_TIMEOUT_SECONDS, USER_AGENT
from quishguard.url_analyzer import extract_registered_domain

# Disable insecure TLS warnings during active security probes of unknown/suspicious domains
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RedirectTracer:
    """
    Safely traces redirect chains without executing scripts or downloading payloads.
    Uses safe HEAD requests followed by minimal-byte GET probes when HEAD is rejected.
    """
    def __init__(self, max_hops: int = MAX_REDIRECT_HOPS, timeout: int = HTTP_TIMEOUT_SECONDS):
        self.max_hops = max_hops
        self.timeout = timeout
        self.headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        }

    def trace(self, initial_url: str) -> Dict[str, Any]:
        chain: List[Dict[str, Any]] = []
        visited = set()
        current_url = initial_url
        is_loop = False
        error_message = None
        has_cross_domain = False
        initial_domain = extract_registered_domain(initial_url)

        for hop_index in range(self.max_hops):
            if current_url in visited:
                is_loop = True
                chain.append({
                    "hop": hop_index + 1,
                    "status_code": "LOOP",
                    "url": current_url,
                    "domain": tldextract.extract(current_url).registered_domain,
                    "notes": "Redirect loop detected back to this URL"
                })
                break

            visited.add(current_url)
            start_time = time.time()

            try:
                # Attempt HEAD request with redirect disabled
                response = requests.head(
                    current_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False  # Avoid crash on self-signed certs during security probe
                )
                
                # If HEAD fails or gives 405 Method Not Allowed, fallback to a small streaming GET
                if response.status_code in (405, 403, 501):
                    response = requests.get(
                        current_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True,
                        verify=False
                    )
                    # Read max 2KB to prevent malware download
                    _ = response.raw.read(2048)
                    response.close()

                elapsed_ms = round((time.time() - start_time) * 1000, 1)
                status_code = response.status_code
                current_domain = extract_registered_domain(current_url)
                
                if current_domain and initial_domain and current_domain != initial_domain:
                    has_cross_domain = True

                redirect_target = response.headers.get("Location")
                
                hop_info = {
                    "hop": hop_index + 1,
                    "status_code": status_code,
                    "url": current_url,
                    "domain": current_domain,
                    "elapsed_ms": elapsed_ms,
                    "redirect_to": redirect_target or None
                }
                chain.append(hop_info)

                # Check if this status is a redirect
                if status_code in (301, 302, 303, 307, 308) and redirect_target:
                    # Resolve relative redirect URLs
                    next_url = urllib.parse.urljoin(current_url, redirect_target)
                    current_url = next_url
                else:
                    # Reached final destination
                    break

            except requests.exceptions.Timeout:
                chain.append({
                    "hop": hop_index + 1,
                    "status_code": "TIMEOUT",
                    "url": current_url,
                    "domain": extract_registered_domain(current_url),
                    "notes": "Connection timed out"
                })
                error_message = "Connection timed out during redirect inspection"
                break
            except Exception as e:
                chain.append({
                    "hop": hop_index + 1,
                    "status_code": "ERROR",
                    "url": current_url,
                    "domain": extract_registered_domain(current_url),
                    "notes": str(e)[:120]
                })
                error_message = f"Network probe failed: {str(e)[:100]}"
                break

        final_url = chain[-1]["url"] if chain else initial_url
        final_domain = extract_registered_domain(final_url)

        return {
            "initial_url": initial_url,
            "final_url": final_url,
            "final_domain": final_domain,
            "total_hops": len(chain),
            "redirect_count": max(0, len(chain) - 1),
            "is_loop": is_loop,
            "has_cross_domain_redirect": has_cross_domain,
            "chain": chain,
            "error": error_message
        }

redirect_tracer = RedirectTracer()
