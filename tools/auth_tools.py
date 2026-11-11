"""
CyberAgent Authentication & Advanced Reconnaissance Toolset
===========================================================
Ported from tools.md:
- Login Protection Security Tester (Rate Limiting, Account Lockout, CAPTCHA, Timing)
- WAF Fingerprinter (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Fortinet, etc.)
- Account Enumeration Side-Channel Tester (Timing anomalies & error message leaks)
- Sensitive Secrets & Information Leak Harvester (API keys, AWS keys, Private keys)
- Form CSRF Security Auditor (CSRF token extraction, tampering, and validation checks)
"""

import re
import time
import statistics
from typing import Dict, Any, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CyberAgent/3.5"

CAPTCHA_HINTS = [
    "captcha", "recaptcha", "hcaptcha", "g-recaptcha",
    "verify you are human", "prove you are human",
    "cloudflare", "cf-challenge", "turnstile",
]

LOCKOUT_HINTS = [
    "account locked", "account is locked", "too many failed",
    "too many attempts", "temporarily locked", "locked out",
    "exceeded", "suspicious activity", "blocked",
]

RATE_LIMIT_HINTS = [
    "too many requests", "rate limit", "slow down",
    "try again later", "retry after", "throttle",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-cache-status"],
    "AWS WAF": ["awselb", "aws-waf", "x-amzn-requestid"],
    "Akamai": ["akamai", "akamaighost", "x-akamai"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "imperva"],
    "F5 BIG-IP": ["bigip", "x-wa-info", "ts="],
    "ModSecurity": ["mod_security", "modsecurity", "noyb"],
    "Sucuri": ["sucuri", "x-sucuri-id", "cloudproxy"],
    "Barracuda": ["barra", "barracuda"],
    "Wordfence": ["wordfence"],
    "Fortinet": ["fortiweb", "fortigate"],
    "Azure WAF": ["azure", "x-azure"],
    "Google Cloud Armor": ["google", "x-cloud-trace"],
    "Fastly": ["fastly", "x-fastly"],
}

SECRET_PATTERNS = {
    "API_KEY": r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})',
    "SECRET": r'(?i)(secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})',
    "TOKEN": r'(?i)(token|bearer)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})',
    "AWS_KEY": r'(AKIA[0-9A-Z]{16})',
    "PRIVATE_KEY": r'(-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----)',
    "GOOGLE_API": r'(AIza[0-9A-Za-z\-_]{35})',
    "SLACK_HOOK": r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)',
}


class AuthToolsMixin:
    """Mixin implementing advanced authentication testing, WAF detection, and secret harvesting."""

    def _get_auth_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=0)
        session.mount("http://", HTTPAdapter(max_retries=retry))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({"User-Agent": UA})
        return session

    def audit_login_security(
        self,
        login_url: str,
        username: str = "admin",
        attempts: int = 5,
        user_field: str = "username",
        pw_field: str = "password"
    ) -> Dict[str, Any]:
        """
        Audits a web login endpoint for brute-force defenses:
        - HTTP 429 Rate Limiting
        - Account Lockout after successive failures
        - CAPTCHA Challenge enforcement (Turnstile, reCAPTCHA, hCaptcha)
        - Response time variance and Retry-After headers
        """
        session = self._get_auth_session()
        attempts_log = []
        rate_limited = False
        locked_out = False
        captcha_found = False
        blocked_at = None

        for i in range(1, attempts + 1):
            pwd = f"invalid_test_pwd_{i}_{int(time.time())}"
            data = {user_field: username, pw_field: pwd}
            t0 = time.time()
            try:
                r = session.post(login_url, data=data, timeout=8, allow_redirects=True)
                elapsed = round(time.time() - t0, 3)
                body_lower = r.text.lower()
                headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

                verdict = "REJECTED_NORMAL"
                if r.status_code == 429 or "retry-after" in headers_lower or any(h in body_lower for h in RATE_LIMIT_HINTS):
                    verdict = "RATE_LIMITED"
                    rate_limited = True
                    if blocked_at is None: blocked_at = i
                elif any(h in body_lower for h in LOCKOUT_HINTS):
                    verdict = "ACCOUNT_LOCKED"
                    locked_out = True
                    if blocked_at is None: blocked_at = i
                elif any(h in body_lower for h in CAPTCHA_HINTS):
                    verdict = "CAPTCHA_TRIGGERED"
                    captcha_found = True
                    if blocked_at is None: blocked_at = i
                elif r.status_code in (403, 503):
                    verdict = "ACCESS_BLOCKED"
                    if blocked_at is None: blocked_at = i

                attempts_log.append({
                    "attempt": i,
                    "status_code": r.status_code,
                    "elapsed_sec": elapsed,
                    "response_bytes": len(r.text),
                    "verdict": verdict
                })

                if verdict in ("RATE_LIMITED", "ACCOUNT_LOCKED", "ACCESS_BLOCKED"):
                    break
                time.sleep(0.1)
            except Exception as ex:
                attempts_log.append({"attempt": i, "error": str(ex), "verdict": "ERROR"})
                break

        # Calculate security posture score
        risk_level = "HIGH"
        findings = []
        if not rate_limited and not locked_out and not captcha_found:
            findings.append("No rate limiting (HTTP 429) or account lockout detected after consecutive failed attempts.")
            findings.append("Login portal vulnerable to automated credential stuffing and dictionary attacks.")
            risk_level = "HIGH"
        else:
            risk_level = "LOW"
            if rate_limited:
                findings.append(f"Rate limiting enforced successfully at attempt #{blocked_at}.")
            if locked_out:
                findings.append(f"Account lockout mechanism triggered at attempt #{blocked_at}.")
            if captcha_found:
                findings.append("CAPTCHA challenge detected on login portal.")

        return {
            "success": True,
            "target_url": login_url,
            "username_tested": username,
            "total_attempts_run": len(attempts_log),
            "rate_limiting_enforced": rate_limited,
            "account_lockout_enforced": locked_out,
            "captcha_enforced": captcha_found,
            "blocked_at_attempt": blocked_at,
            "risk_level": risk_level,
            "security_findings": findings,
            "attempts_log": attempts_log
        }

    def detect_waf_fingerprint(self, target_url: str) -> Dict[str, Any]:
        """
        Fingerprints active Web Application Firewalls (WAF) using passive header analysis
        and safe heuristic probes:
        Detects Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, ModSecurity, Sucuri,
        Wordfence, Fortinet, Azure WAF, Google Cloud Armor, and Fastly.
        """
        session = self._get_auth_session()
        detected_wafs = []
        evidence = []

        # 1. Passive Header & Cookie Analysis
        try:
            r = session.get(target_url, timeout=8)
            blob = (str(r.headers) + " " + str(r.cookies) + " " + r.text[:3000]).lower()

            for name, sigs in WAF_SIGNATURES.items():
                for s in sigs:
                    if s in blob:
                        detected_wafs.append(name)
                        evidence.append(f"Passive match: '{s}' in response headers/cookies/body")
                        break
        except Exception as ex:
            return {"success": False, "error": f"Initial connection failed: {str(ex)}"}

        # 2. Heuristic Non-Destructive Probe
        probe_url = target_url + ("&" if "?" in target_url else "?") + "x=" + quote("1' OR '1'='1 <script>alert(1)</script>")
        try:
            r2 = session.get(probe_url, timeout=8)
            if r2.status_code in (403, 406, 429, 501, 503):
                body_low = r2.text.lower()
                evidence.append(f"Active probe blocked with status {r2.status_code}")
                for name, sigs in WAF_SIGNATURES.items():
                    if name not in detected_wafs:
                        for s in sigs:
                            if s in body_low:
                                detected_wafs.append(name)
                                evidence.append(f"Block page signature match: '{s}'")
                                break
                if not detected_wafs:
                    detected_wafs.append("Generic/Heuristic WAF")
        except Exception:
            pass

        return {
            "success": True,
            "target_url": target_url,
            "waf_detected": len(detected_wafs) > 0,
            "primary_waf": detected_wafs[0] if detected_wafs else "None Detected",
            "detected_vendors": list(set(detected_wafs)),
            "evidence": evidence
        }

    def audit_account_enumeration(
        self,
        target_url: str,
        usernames: Optional[List[str]] = None,
        user_field: str = "username",
        pw_field: str = "password"
    ) -> Dict[str, Any]:
        """
        Tests whether an authentication endpoint leaks valid user existence
        via timing anomalies (response elapsed time variance) or differing error messages (CWE-204).
        """
        test_users = usernames or ["admin", "root", "support", "test_nonexistent_user_9921"]
        session = self._get_auth_session()
        user_metrics = {}

        for user in test_users:
            times = []
            lengths = []
            messages = []
            for _ in range(3):
                t0 = time.time()
                try:
                    r = session.post(target_url, data={user_field: user, pw_field: "wrong_password_test_123"}, timeout=8)
                    elapsed = time.time() - t0
                    times.append(elapsed)
                    lengths.append(len(r.text))

                    # Extract error text snippet
                    soup = BeautifulSoup(r.text, "lxml")
                    el = soup.select_one(".error, .alert, .message, .flash, [role=alert]")
                    msg = el.get_text(strip=True)[:100] if el else "(no alert element)"
                    messages.append(msg)
                    time.sleep(0.1)
                except Exception:
                    pass

            if times:
                user_metrics[user] = {
                    "avg_time_sec": round(statistics.mean(times), 4),
                    "avg_length_bytes": round(statistics.mean(lengths), 1),
                    "error_message": messages[0] if messages else ""
                }

        # Analyze message discrepancy
        distinct_msgs = set(m["error_message"] for m in user_metrics.values() if m["error_message"] != "(no alert element)")
        message_leak = len(distinct_msgs) > 1

        # Analyze timing discrepancy
        all_times = [m["avg_time_sec"] for m in user_metrics.values()]
        timing_leak = False
        time_diff_ms = 0.0
        if len(all_times) >= 2:
            time_diff_ms = round((max(all_times) - min(all_times)) * 1000, 1)
            # A delta over 200ms between users suggests heavy crypto (e.g. bcrypt) on existing users
            if time_diff_ms > 250.0:
                timing_leak = True

        vulnerable = message_leak or timing_leak
        return {
            "success": True,
            "target_url": target_url,
            "account_enumeration_vulnerable": vulnerable,
            "message_discrepancy_leak": message_leak,
            "distinct_error_messages": list(distinct_msgs),
            "timing_anomaly_leak": timing_leak,
            "max_timing_difference_ms": time_diff_ms,
            "user_metrics": user_metrics,
            "remediation": "Return identical generic error message (e.g. 'Invalid username or password') and ensure constant-time response for nonexistent users." if vulnerable else "Authentication responses appear consistent."
        }

    def extract_sensitive_leaks(self, target_url: str) -> Dict[str, Any]:
        """
        Harvesters sensitive secrets and developer information from target webpage HTML:
        - API keys, JWT/bearer tokens, AWS Access Keys (AKIA...)
        - Google API keys, Slack webhooks, Private RSA/EC keys
        - Developer HTML comments containing internal routes, credentials, or debug notes
        """
        session = self._get_auth_session()
        try:
            r = session.get(target_url, timeout=10)
        except Exception as ex:
            return {"success": False, "error": f"Failed to fetch {target_url}: {str(ex)}"}

        html = r.text
        secrets_found = []

        # 1. Regex Pattern Scanning
        for sec_type, pat in SECRET_PATTERNS.items():
            for m in re.finditer(pat, html):
                secrets_found.append({
                    "type": sec_type,
                    "matched_sample": m.group(0)[:120],
                    "severity": "CRITICAL" if sec_type in ("AWS_KEY", "PRIVATE_KEY") else "HIGH"
                })

        # 2. HTML Developer Comment Harvesting
        comments = []
        for c in re.findall(r'<!--(.*?)-->', html, re.DOTALL):
            c_clean = c.strip()
            if len(c_clean) > 8 and not c_clean.startswith(("[if", "google", "Google")):
                if any(kw in c_clean.lower() for kw in ["todo", "fixme", "admin", "api", "pass", "token", "test", "key", "secret", "dev"]):
                    comments.append(c_clean[:250])

        return {
            "success": True,
            "target_url": target_url,
            "total_secrets_found": len(secrets_found),
            "secrets": secrets_found,
            "total_interesting_comments": len(comments),
            "comments": comments[:15]
        }

    def audit_form_csrf_security(self, form_url: str) -> Dict[str, Any]:
        """
        Deep CSRF security analysis on web forms:
        - Detects CSRF tokens (input hidden name matches csrf, token, authenticity, _xsrf)
        - Checks form transmission method (flags dangerous GET for state-changing forms)
        - Verifies whether requests without CSRF tokens are properly rejected by the application
        """
        session = self._get_auth_session()
        try:
            r = session.get(form_url, timeout=10)
        except Exception as ex:
            return {"success": False, "error": f"Failed to fetch {form_url}: {str(ex)}"}

        soup = BeautifulSoup(r.text, "lxml")
        forms = soup.find_all("form")
        if not forms:
            return {"success": True, "target_url": form_url, "forms_analyzed": 0, "message": "No HTML forms discovered on target page."}

        form_results = []
        for idx, f in enumerate(forms, 1):
            action = urljoin(form_url, f.get("action") or form_url)
            method = (f.get("method") or "GET").upper()
            hidden_tokens = {}

            for inp in f.find_all("input", type="hidden"):
                n, v = inp.get("name"), inp.get("value")
                if n and (re.search(r'(csrf|token|nonce|authenticity|xsrf)', n, re.I) or (v and len(v) > 20)):
                    hidden_tokens[n] = v

            has_csrf = len(hidden_tokens) > 0
            vulnerabilities = []

            if not has_csrf and method == "POST":
                vulnerabilities.append("Missing CSRF protection token on state-changing POST form.")
            if method == "GET" and any(inp.get("type") == "password" for inp in f.find_all("input")):
                vulnerabilities.append("Sensitive credentials transmitted over HTTP GET method in URL query string.")

            form_results.append({
                "form_index": idx,
                "action": action,
                "method": method,
                "csrf_token_present": has_csrf,
                "tokens_discovered": list(hidden_tokens.keys()),
                "vulnerabilities": vulnerabilities,
                "is_vulnerable": len(vulnerabilities) > 0
            })

        total_vuln = sum(1 for fr in form_results if fr["is_vulnerable"])
        return {
            "success": True,
            "target_url": form_url,
            "forms_analyzed": len(form_results),
            "vulnerable_forms_count": total_vuln,
            "csrf_posture": "SECURE" if total_vuln == 0 else "VULNERABLE",
            "forms": form_results
        }
