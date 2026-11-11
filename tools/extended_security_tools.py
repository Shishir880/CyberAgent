"""
CyberAgent Extended Cybersecurity Super-Agent Toolset
=====================================================
Integrates advanced ethical reconnaissance, token auditing, encoding, and network diagnostics:
- Subdomain Enumeration (crt.sh Certificate Transparency + DNS Socket Probing)
- JWT Security & Token Configuration Audit (Alg: none detection, weak HMAC, claim analysis)
- Security Payload Encoding & Obfuscation Generator (URL, Base64, Hex, HTML entities)
- Multi-threaded Proxy Network Health & Latency Diagnostics
"""

import re
import json
import time
import base64
import socket
import urllib.parse
from typing import Dict, Any, List, Optional
import requests


class ExtendedSecurityToolsMixin:
    """Mixin implementing advanced cybersecurity reconnaissance, JWT auditing, and encoding tools."""

    def enumerate_subdomains(self, domain: str, max_results: int = 50) -> Dict[str, Any]:
        """
        Enumerates valid subdomains for a target domain using Certificate Transparency (crt.sh)
        and rapid socket DNS resolution across common infrastructure prefixes.
        """
        # Clean domain
        clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        discovered = set()
        resolved_hosts = []

        # 1. Passive Certificate Transparency via crt.sh
        try:
            url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAgent/3.5"}
            resp = requests.get(url, headers=headers, timeout=8)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{clean_domain}") and not sub.startswith("*"):
                            discovered.add(sub)
        except Exception:
            pass

        # 2. Common Infrastructure Subdomain Wordlist
        common_prefixes = [
            "www", "api", "admin", "dev", "staging", "mail", "portal", "test",
            "vpn", "app", "auth", "login", "cdn", "cloud", "beta", "corp",
            "git", "jenkins", "k8s", "grafana", "sso", "internal"
        ]
        for prefix in common_prefixes:
            discovered.add(f"{prefix}.{clean_domain}")

        # 3. DNS Socket Resolution
        for host in list(discovered)[:max_results]:
            try:
                ip = socket.gethostbyname(host)
                resolved_hosts.append({
                    "subdomain": host,
                    "ip": ip,
                    "status": "resolvable"
                })
            except (socket.gaierror, socket.timeout):
                continue

        return {
            "success": True,
            "domain": clean_domain,
            "total_discovered": len(discovered),
            "total_resolved": len(resolved_hosts),
            "resolved_subdomains": resolved_hosts
        }

    def audit_jwt_security(self, token: str, secret_wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Audits a JSON Web Token (JWT) for critical security misconfigurations:
        - Decodes header and payload without verifying signature
        - Flags 'none' or missing signature algorithm vulnerability
        - Inspects token lifetime expiration ('exp', 'iat', 'nbf')
        - Performs offline dictionary audit against common weak HMAC secrets
        """
        token = token.strip().replace("Bearer ", "")
        parts = token.split(".")
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT format. A valid JWT must consist of 3 base64url parts (header.payload.signature)."}

        def b64_decode(data: str) -> str:
            padded = data + "=" * ((4 - len(data) % 4) % 4)
            return base64.urlsafe_b64decode(padded.encode()).decode(errors="ignore")

        try:
            header_json = json.loads(b64_decode(parts[0]))
            payload_json = json.loads(b64_decode(parts[1]))
        except Exception as e:
            return {"success": False, "error": f"Failed to base64url decode JWT: {str(e)}"}

        findings = []
        severity_score = "LOW"

        # 1. Algorithm check
        alg = str(header_json.get("alg", "")).lower()
        if alg in ("none", "", "null"):
            findings.append({
                "severity": "CRITICAL",
                "title": "Unsigned JWT Algorithm (alg: none)",
                "description": "Token specifies 'alg: none' or lacks an algorithm, allowing attackers to forge arbitrary claims without signature verification."
            })
            severity_score = "CRITICAL"

        # 2. Expiration check
        exp = payload_json.get("exp")
        now_ts = int(time.time())
        if exp is None:
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing Expiration Claim ('exp')",
                "description": "JWT lacks an 'exp' claim and may be valid indefinitely (replay risk)."
            })
            if severity_score != "CRITICAL":
                severity_score = "MEDIUM"
        elif isinstance(exp, (int, float)):
            if exp < now_ts:
                findings.append({
                    "severity": "INFO",
                    "title": "Expired Token",
                    "description": f"Token expired at timestamp {exp} ({int(now_ts - exp)} seconds ago)."
                })

        # 3. Weak HMAC Secret Audit (offline simulation for HS256)
        cracked_secret = None
        if "hs" in alg:
            default_secrets = ["secret", "password", "123456", "admin", "jwt", "key", "test", "development"]
            test_wordlist = (secret_wordlist or []) + default_secrets
            import hmac
            import hashlib
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            actual_sig = parts[2]

            for cand in test_wordlist:
                expected_sig = base64.urlsafe_b64encode(
                    hmac.new(cand.encode(), signing_input, hashlib.sha256).digest()
                ).decode().rstrip("=")
                if actual_sig == expected_sig:
                    cracked_secret = cand
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "Weak HMAC Secret Key Cracked",
                        "description": f"JWT signature verified using trivial weak secret: '{cand}'"
                    })
                    severity_score = "CRITICAL"
                    break

        return {
            "success": True,
            "overall_severity": severity_score,
            "header": header_json,
            "payload": payload_json,
            "findings_count": len(findings),
            "findings": findings,
            "weak_secret_cracked": cracked_secret is not None,
            "cracked_secret": cracked_secret
        }

    def generate_security_payload(
        self,
        payload_type: str = "xss",
        raw_payload: str = "<script>alert(1)</script>",
        encoding: str = "url"
    ) -> Dict[str, Any]:
        """
        Generates security verification payloads with various encoding and obfuscation formats
        for testing input validation, WAF filtering, and sanitize routines on authorized targets.

        Supported encodings:
        - 'url': Single URL percent-encoding (%3Cscript...)
        - 'double_url': Double percent-encoding for path-traversal/WAF filter bypass testing
        - 'base64': Standard Base64 encoded string
        - 'hex': Hexadecimal escaped string (\\x3c\\x73\\x63...)
        - 'html_entity': HTML decimal entity encoded (&#60;&#115;...)
        - 'all': Generates a dictionary of all encoding variations simultaneously
        """
        payload_type = payload_type.lower().strip()
        encoding = encoding.lower().strip()

        # Encoding variations
        url_enc = urllib.parse.quote(raw_payload)
        double_url_enc = urllib.parse.quote(url_enc)
        b64_enc = base64.b64encode(raw_payload.encode()).decode()
        hex_enc = "".join([f"\\x{ord(c):02x}" for c in raw_payload])
        html_ent_enc = "".join([f"&#{ord(c)};" for c in raw_payload])

        encodings = {
            "raw": raw_payload,
            "url_encoded": url_enc,
            "double_url_encoded": double_url_enc,
            "base64_encoded": b64_enc,
            "hex_encoded": hex_enc,
            "html_entity_encoded": html_ent_enc
        }

        selected_variant = encodings.get(f"{encoding}_encoded", encodings.get(encoding, url_enc))
        if encoding == "all":
            selected_variant = encodings

        return {
            "success": True,
            "payload_type": payload_type,
            "requested_encoding": encoding,
            "payload": selected_variant,
            "all_variations": encodings
        }

    def check_proxy_health(self, proxy_list: List[str], timeout: int = 5) -> Dict[str, Any]:
        """
        Audits proxy health, latency, connectivity, and exit IP.
        Useful for verifying network proxies before launching security audits.
        """
        results = []
        for proxy in proxy_list:
            proxy = proxy.strip()
            if not proxy:
                continue
            if not proxy.startswith(("http://", "https://", "socks5://")):
                proxy = f"http://{proxy}"

            t0 = time.time()
            try:
                r = requests.get(
                    "https://httpbin.org/ip",
                    proxies={"http": proxy, "https": proxy},
                    timeout=timeout
                )
                latency_ms = round((time.time() - t0) * 1000, 2)
                if r.status_code == 200:
                    exit_ip = r.json().get("origin", "Unknown")
                    results.append({
                        "proxy": proxy,
                        "alive": True,
                        "latency_ms": latency_ms,
                        "exit_ip": exit_ip
                    })
                else:
                    results.append({
                        "proxy": proxy,
                        "alive": False,
                        "latency_ms": latency_ms,
                        "error": f"HTTP {r.status_code}"
                    })
            except Exception as e:
                latency_ms = round((time.time() - t0) * 1000, 2)
                results.append({
                    "proxy": proxy,
                    "alive": False,
                    "latency_ms": latency_ms,
                    "error": str(e)[:80]
                })

        alive_count = sum(1 for r in results if r["alive"])
        return {
            "success": True,
            "total_tested": len(results),
            "alive_count": alive_count,
            "dead_count": len(results) - alive_count,
            "results": results
        }

    def lookup_whois_and_ip(
        self,
        target: Optional[str] = None,
        include_raw: bool = False
    ) -> Dict[str, Any]:
        """
        Advanced WHOIS Domain Lookup & IP Geolocation Intelligence.
        Upgraded from Bizmatepro WHOIS Checker & What-Is-My-IP tools:
        - Domain WHOIS & Registration Lifecycle (ICANN RDAP & Socket Port 43 lookup)
        - Registrar info, abuse contacts, creation & expiration dates, days remaining
        - Nameservers, domain status codes, and registrant details
        - IP Geolocation & ASN Intelligence (ISP, Autonomous System, City, Region, Coordinates)
        - Cybersecurity Risk Assessment: Phishing age flags, expiry hijack alerts, CDN/WAF detection
        """
        import datetime

        target_clean = (target or "").strip()
        is_self_lookup = not target_clean or target_clean.lower() in ("me", "self", "my_ip", "myip")

        # 1. Resolve Target & IP
        resolved_ip = None
        domain_name = None

        if is_self_lookup:
            try:
                r_ip = requests.get("https://api.ipify.org?format=json", timeout=6)
                if r_ip.status_code == 200:
                    resolved_ip = r_ip.json().get("ip")
            except Exception:
                pass
            if not resolved_ip:
                try:
                    r_ip2 = requests.get("https://httpbin.org/ip", timeout=6)
                    resolved_ip = r_ip2.json().get("origin", "").split(",")[0].strip()
                except Exception:
                    pass
            target_clean = resolved_ip or "127.0.0.1"
        else:
            # Strip URL schemes and paths
            target_clean = re.sub(r"^https?://", "", target_clean, flags=re.I)
            target_clean = target_clean.split("/")[0].split(":")[0].strip()

            # Check if target is an IP address
            is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target_clean)) or ":" in target_clean
            if is_ip:
                resolved_ip = target_clean
            else:
                domain_name = target_clean.lower()
                try:
                    resolved_ip = socket.gethostbyname(domain_name)
                except Exception:
                    resolved_ip = None

        # 2. IP Geolocation & Network Intelligence
        ip_data = {}
        if resolved_ip:
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{resolved_ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse",
                    timeout=7
                )
                if resp.status_code == 200:
                    d = resp.json()
                    if d.get("status") == "success":
                        ip_data = {
                            "ip": resolved_ip,
                            "hostname_reverse": d.get("reverse"),
                            "country": d.get("country"),
                            "country_code": d.get("countryCode"),
                            "region": d.get("regionName"),
                            "city": d.get("city"),
                            "postal_code": d.get("zip"),
                            "latitude": d.get("lat"),
                            "longitude": d.get("lon"),
                            "timezone": d.get("timezone"),
                            "isp": d.get("isp"),
                            "organization": d.get("org"),
                            "asn": d.get("as")
                        }
            except Exception:
                pass

        if not ip_data and resolved_ip:
            ip_data = {"ip": resolved_ip, "note": "Geolocation data unavailable"}

        # 3. Domain WHOIS Lookup (if target is a domain)
        whois_data = {}
        raw_whois_text = ""
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        if domain_name:
            # RDAP (Modern ICANN standard JSON query)
            try:
                rdap_url = f"https://rdap.org/domain/{domain_name}"
                headers = {"User-Agent": "CyberAgent/3.5 (Security Auditor; https://bizmatepro.xyz)"}
                rdap_resp = requests.get(rdap_url, headers=headers, timeout=8)
                if rdap_resp.status_code == 200:
                    rjson = rdap_resp.json()

                    # Parse events (dates)
                    events = {e.get("eventAction"): e.get("eventDate") for e in rjson.get("events", [])}
                    created_date = events.get("registration")
                    expiry_date = events.get("expiration")
                    updated_date = events.get("last changed")

                    # Parse days
                    days_until_expiry = None
                    domain_age_days = None

                    def parse_iso(dt_str):
                        if not dt_str:
                            return None
                        try:
                            clean_str = dt_str.replace("Z", "+00:00")
                            return datetime.datetime.fromisoformat(clean_str)
                        except Exception:
                            return None

                    dt_exp = parse_iso(expiry_date)
                    dt_crt = parse_iso(created_date)

                    if dt_exp:
                        days_until_expiry = (dt_exp - now_utc).days
                    if dt_crt:
                        domain_age_days = (now_utc - dt_crt).days

                    # Parse registrar & entities
                    registrar_name = None
                    abuse_email = None
                    abuse_phone = None
                    for entity in rjson.get("entities", []):
                        roles = entity.get("roles", [])
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        registrar_name = item[3]
                        if "abuse" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "email":
                                        abuse_email = item[3]
                                    elif item[0] == "tel":
                                        abuse_phone = item[3]

                    # Parse nameservers
                    nameservers = [ns.get("ldhName") for ns in rjson.get("nameservers", []) if ns.get("ldhName")]
                    statuses = rjson.get("status", [])

                    whois_data = {
                        "domain": domain_name,
                        "status": statuses,
                        "registrar": registrar_name or "N/A",
                        "abuse_contact_email": abuse_email,
                        "abuse_contact_phone": abuse_phone,
                        "created_date": created_date,
                        "expiration_date": expiry_date,
                        "updated_date": updated_date,
                        "domain_age_days": domain_age_days,
                        "days_until_expiration": days_until_expiry,
                        "nameservers": nameservers
                    }
            except Exception:
                pass

            # Socket Port 43 Fallback for Raw WHOIS Dump
            try:
                tld = domain_name.split(".")[-1]
                server_candidate = f"whois.nic.{tld}"
                if tld == "com" or tld == "net":
                    server_candidate = "whois.verisign-grs.com"
                elif tld == "org":
                    server_candidate = "whois.pir.org"

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((server_candidate, 43))
                query_str = f"= {domain_name}\r\n" if tld in ("com", "net") else f"{domain_name}\r\n"
                s.sendall(query_str.encode("utf-8"))
                sock_resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    sock_resp += chunk
                    if len(sock_resp) > 65536:
                        break
                s.close()
                raw_whois_text = sock_resp.decode(errors="ignore").strip()

                # If RDAP was empty, regex-extract basic fields from raw whois
                if not whois_data.get("registrar") and raw_whois_text:
                    reg_match = re.search(r"Registrar:\s*(.+)", raw_whois_text, re.I)
                    exp_match = re.search(r"Registry Expiry Date:\s*(.+)", raw_whois_text, re.I)
                    crt_match = re.search(r"Creation Date:\s*(.+)", raw_whois_text, re.I)
                    whois_data["domain"] = domain_name
                    if reg_match:
                        whois_data["registrar"] = reg_match.group(1).strip()
                    if exp_match:
                        whois_data["expiration_date"] = exp_match.group(1).strip()
                    if crt_match:
                        whois_data["created_date"] = crt_match.group(1).strip()
            except Exception:
                pass

        # 4. Cybersecurity Risk Posture Assessment
        risk_flags = []
        age_days = whois_data.get("domain_age_days")
        exp_days = whois_data.get("days_until_expiration")

        if age_days is not None and age_days < 30:
            risk_flags.append({
                "severity": "HIGH",
                "tag": "NEWLY_REGISTERED_DOMAIN",
                "detail": f"Domain was registered only {age_days} days ago. Newly registered domains are statistically correlated with phishing or temporary C2 infrastructure."
            })
        elif age_days is not None and age_days > 365 * 3:
            risk_flags.append({
                "severity": "LOW (Good)",
                "tag": "ESTABLISHED_DOMAIN",
                "detail": f"Established domain with {round(age_days / 365, 1)} years of history."
            })

        if exp_days is not None and 0 <= exp_days <= 30:
            risk_flags.append({
                "severity": "MEDIUM",
                "tag": "EXPIRING_SOON",
                "detail": f"Domain will expire in {exp_days} days. High risk of domain abandonment or expiration takeover."
            })

        org_name = (ip_data.get("organization") or "").lower()
        isp_name = (ip_data.get("isp") or "").lower()
        if "cloudflare" in org_name or "cloudflare" in isp_name:
            risk_flags.append({
                "severity": "INFO",
                "tag": "CDN_WAF_PROXY",
                "detail": "Target IP is behind Cloudflare Reverse Proxy / WAF. Direct origin IP is masked."
            })
        elif "amazon" in org_name or "aws" in isp_name or "digitalocean" in org_name:
            risk_flags.append({
                "severity": "INFO",
                "tag": "CLOUD_HOSTED",
                "detail": f"Target is hosted on cloud provider infrastructure ({ip_data.get('organization')})."
            })

        out = {
            "success": True,
            "target": target_clean,
            "resolved_ip": resolved_ip,
            "ip_intelligence": ip_data,
            "whois_data": whois_data or ("Not applicable (IP target)" if not domain_name else "Registry record unavailable"),
            "risk_assessment": {
                "risk_count": len(risk_flags),
                "flags": risk_flags
            }
        }
        if include_raw and raw_whois_text:
            out["raw_whois_preview"] = raw_whois_text[:3000]

        return out

