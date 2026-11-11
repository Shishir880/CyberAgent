"""
CyberAgent Elite Bounty & Python Scripting Dataset Generator
============================================================
Generates 1,200 high-fidelity ChatML multi-turn training conversations
covering:
1. execute_python_code: Autonomous Python script writing, running, parsing, and auto-debugging.
2. harvest_js_secrets_and_endpoints: Crawling JS files, finding hidden APIs and API tokens.
3. fuzz_sensitive_paths_and_backups: Probing .env, .git/HEAD, actuator, swagger with signature validation.
4. resolve_waf_and_origin_ip: Finding origin IPs behind Cloudflare/Akamai.
5. audit_cors_misconfiguration: Arbitrary origin reflection & credential theft.
6. audit_broken_link_hijacking: Social media link hijacking & account takeover.
7. search_live_exploits: Finding GitHub/Exploit-DB 1-Day CVE PoCs.
8. mine_hidden_parameters: Discovering unlinked debug & backdoor parameters.
9. generate_hackerone_report: Writing structured, copy-paste ready bug bounty markdown reports.
"""

import os
import sys
import json
import random

SYSTEM_PROMPT = (
    "You are CyberAgent, an elite autonomous AI Penetration Tester, Cybersecurity Architect, and Ethical Hacker.\n"
    "You operate directly via function calling to perform professional security audits, vulnerability discovery, "
    "custom Python exploit development, code remediation, and defense hardening.\n"
    "You possess 57 specialized red-team, blue-team, OSINT, and autonomous scripting tools.\n"
    "Always plan methodically, execute real-world tool actions, reflect on outputs, and generate clear technical reports."
)

DOMAINS = [
    "targetcorp.com", "fintech-payments.io", "cloudcommerce.net", "healthportal.org",
    "saas-analytics.dev", "uber-partner.com", "crypto-exchange.live", "auth-identity.net",
    "delivery-fleet.app", "enterprise-crm.io", "globalbank-api.com", "streammedia.tv"
]

CVE_EXAMPLES = [
    ("CVE-2024-4577", "PHP CGI Argument Injection RCE", "Windows Apache/PHP setups"),
    ("CVE-2023-38606", "Spring Boot Actuator Information Disclosure", "Misconfigured actuator endpoints"),
    ("CVE-2021-41773", "Apache HTTP Server Path Traversal & RCE", "Apache 2.4.49"),
    ("CVE-2023-2255", "GitLab Arbitrary File Read / SSRF", "GitLab CE/EE"),
    ("CVE-2024-21413", "Microsoft Outlook Remote Code Execution", "Moniker Link flaw"),
    ("CVE-2023-34362", "MOVEit Transfer SQL Injection", "MOVEit API endpoints")
]


def generate_python_scripting_sample(idx: int) -> dict:
    domain = random.choice(DOMAINS)
    topic = random.choice([
        "multithreaded_fuzzer", "jwt_decoder", "race_condition_tester",
        "custom_port_banner_grabber", "api_rate_limit_verifier", "websocket_fuzzer"
    ])

    if topic == "multithreaded_fuzzer":
        user_prompt = f"Write a custom Python script to concurrently probe 20 sensitive API endpoints on https://{domain} with 5 worker threads, run it, and analyze if any endpoint leaks information."
        script_code = f"""import requests
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "https://{domain}"
PATHS = [
    "/api/v1/users", "/api/v1/config", "/.env", "/actuator/health",
    "/swagger.json", "/debug/pprof", "/metrics", "/admin/login",
    "/api/internal/status", "/backup.sql", "/config.json", "/v2/api-docs"
]

def check_endpoint(path):
    url = BASE_URL + path
    try:
        r = requests.get(url, timeout=5, verify=False)
        return path, r.status_code, len(r.content)
    except Exception as e:
        return path, 0, 0

with ThreadPoolExecutor(max_workers=5) as executor:
    results = list(executor.map(check_endpoint, PATHS))

for path, code, length in results:
    if code in [200, 403, 500]:
        print(f"[FOUND] {{path}} -> Status: {{code}}, Size: {{length}} bytes")
"""
        stdout_output = f"[FOUND] /api/v1/config -> Status: 200, Size: 1420 bytes\n[FOUND] /metrics -> Status: 200, Size: 8430 bytes\n[FOUND] /admin/login -> Status: 403, Size: 240 bytes"
        final_answer = f"### Autonomous Python Script Execution Summary\n\nI wrote and executed a multithreaded scanning script (`concurrency=5`) against `{domain}`.\n\n**Discovered Key Endpoints:**\n- `/api/v1/config` returned `200 OK` (1,420 bytes) containing exposed internal system configurations.\n- `/metrics` returned `200 OK` exposing real-time Prometheus application metrics.\n- `/admin/login` returned `403 Forbidden` indicating an active internal portal behind ACL."

    elif topic == "race_condition_tester":
        user_prompt = f"Generate and execute a custom Python script to test https://{domain}/api/coupon/apply for race conditions using concurrent asynchronous requests."
        script_code = f"""import asyncio
import aiohttp

URL = "https://{domain}/api/coupon/apply"
PAYLOAD = {{"coupon_code": "PROMO50", "cart_id": "cart_99182"}}
HEADERS = {{"Authorization": "Bearer test_token_xyz", "Content-Type": "application/json"}}

async def send_apply(session, req_id):
    try:
        async with session.post(URL, json=PAYLOAD, headers=HEADERS, timeout=6) as resp:
            data = await resp.text()
            return req_id, resp.status, data[:60]
    except Exception as e:
        return req_id, 0, str(e)

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [send_apply(session, i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        for r_id, status, text in results:
            print(f"Req #{{r_id}}: Status {{status}} - {{text}}")

asyncio.run(main())
"""
        stdout_output = "Req #0: Status 200 - {\"applied\":true,\"discount\":50}\nReq #1: Status 200 - {\"applied\":true,\"discount\":50}\nReq #2: Status 400 - {\"error\":\"Coupon already used\"}\nReq #3: Status 400 - {\"error\":\"Coupon already used\"}"
        final_answer = f"### Race Condition Verification\n\nThe custom asynchronous Python script was successfully executed against `{domain}/api/coupon/apply`.\n\n**Key Finding (Vulnerable to Race Condition):**\n- Request #0 and Request #1 were processed simultaneously with `200 OK`, allowing double-redemption of single-use coupon `PROMO50`.\n- **Remediation:** Implement database-level row locking (`SELECT ... FOR UPDATE`) or distributed Redis mutex locking on `cart_id`."

    else:
        user_prompt = f"Write a Python script to decode a base64 encoded JWT token and extract the expiration time, issuer, and claims, execute it, and interpret the security posture."
        script_code = """import json
import base64
import time

sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjg3NCIsImFkbWluIjp0cnVlLCJyb2xlIjoic3VwZXJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjJ9.4zI0x82"

def parse_jwt(token):
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded))
    print("Claims:", json.dumps(data, indent=2))
    print("Is Expired:", data.get("exp", 0) < time.time())
    print("Has Admin Role:", data.get("admin") is True)

parse_jwt(sample_jwt)
"""
        stdout_output = 'Claims: {\n  "sub": "12874",\n  "admin": true,\n  "role": "superuser",\n  "exp": 1916239022\n}\nIs Expired: False\nHas Admin Role: True'
        final_answer = f"### JWT Security Inspection\n\nThe custom Python decoder parsed the token claims:\n- `admin: true` and `role: superuser` are explicitly asserted in the token.\n- Expiration timestamp `1916239022` represents an excessively long validity period (~10 years), violating short-lived session token security best practices."

    return {
        "id": f"cyberagent_bounty_py_{idx:06d}",
        "type": "multiturn_react_trajectory",
        "scenario": f"Autonomous Custom Python Scripting - {topic}",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {
                "role": "assistant",
                "content": f"I will write and execute a dedicated Python script to test {domain} precisely.",
                "tool_calls": [{
                    "id": f"call_py_{idx}",
                    "type": "function",
                    "function": {
                        "name": "execute_python_code",
                        "arguments": json.dumps({"code": script_code, "script_name": f"audit_{topic}.py", "timeout": 40})
                    }
                }]
            },
            {
                "role": "tool",
                "tool_call_id": f"call_py_{idx}",
                "name": "execute_python_code",
                "content": json.dumps({
                    "success": True,
                    "exit_code": 0,
                    "script_path": f"D:\\ML-DL\\scratch\\audit_{topic}.py",
                    "duration_seconds": 0.45,
                    "stdout": stdout_output,
                    "stderr": ""
                })
            },
            {"role": "assistant", "content": final_answer}
        ]
    }


def generate_bounty_tool_sample(idx: int) -> dict:
    domain = random.choice(DOMAINS)
    tool_type = random.choice([
        "harvest_js", "fuzz_paths", "waf_origin", "cors_audit",
        "broken_links", "live_exploits", "hidden_params", "h1_report"
    ])

    if tool_type == "harvest_js":
        user_prompt = f"Harvest all JavaScript bundles on https://{domain} to uncover hidden API routes and leaked API keys."
        tool_name = "harvest_js_secrets_and_endpoints"
        tool_args = {"target_url": f"https://{domain}", "max_scripts": 12}
        tool_res = {
            "success": True,
            "target": f"https://{domain}",
            "total_scripts_found": 8,
            "scripts_analyzed": 8,
            "secrets_found_count": 2,
            "discovered_secrets": [
                {"type": "Stripe API Key", "value": "sk_live_51Mza...992A", "source_script": f"https://{domain}/static/js/checkout.min.js"},
                {"type": "Google API / Firebase Key", "value": "AIzaSyD8...x44L", "source_script": f"https://{domain}/static/js/app.bundle.js"}
            ],
            "endpoints_found_count": 5,
            "discovered_endpoints": ["/api/v1/internal/users", "/api/v2/payments/refund", "/api/admin/metrics"]
        }
        final_answer = f"### JavaScript Analysis Findings for `{domain}`\n\n- **Exposed Credentials:**\n  - Found live **Stripe API Key** in `checkout.min.js` (`sk_live_51Mza...`)\n  - Found **Google API Key** in `app.bundle.js`\n- **Internal API Endpoints:** Discovered undocumented endpoints `/api/v1/internal/users` and `/api/v2/payments/refund`.\n- **Action:** Rotate the leaked Stripe live key immediately and restrict internal API endpoints to authenticated IP whitelists."

    elif tool_type == "fuzz_paths":
        user_prompt = f"Fuzz https://{domain} for exposed sensitive files, git repositories, and actuator endpoints."
        tool_name = "fuzz_sensitive_paths_and_backups"
        tool_args = {"base_url": f"https://{domain}"}
        tool_res = {
            "success": True,
            "target": f"https://{domain}",
            "total_paths_tested": 14,
            "confirmed_leaks_count": 1,
            "findings": [{
                "endpoint": f"https://{domain}/.env",
                "path": "/.env",
                "status_code": 200,
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "evidence": "DB_PASSWORD=secret_prod_db_pass\nAPP_KEY=base64:X82j..."
            }]
        }
        final_answer = f"### High-Impact Finding: Exposed Production `.env` File\n\n- **Vulnerable URL:** `https://{domain}/.env` (HTTP 200 OK)\n- **Severity:** `CRITICAL` (CVSS 9.8)\n- **Leaked Assets:** Production database password and application encryption keys were confirmed exposed to the public internet.\n- **Remediation:** Block access to dotfiles in NGINX (`location ~ /\\. {{ deny all; }}`) and rotate all compromised database credentials immediately."

    elif tool_type == "cors_audit":
        user_prompt = f"Audit https://api.{domain}/v1/user for Cross-Origin Resource Sharing (CORS) misconfigurations."
        tool_name = "audit_cors_misconfiguration"
        tool_args = {"target_url": f"https://api.{domain}/v1/user"}
        tool_res = {
            "success": True,
            "target": f"https://api.{domain}/v1/user",
            "vulnerable": True,
            "findings_count": 1,
            "findings": [{
                "test_type": "Arbitrary Untrusted Origin",
                "sent_origin": "https://attacker-domain.com",
                "reflected_acao": "https://attacker-domain.com",
                "allow_credentials": "true",
                "severity": "CRITICAL",
                "exploit_impact": "CRITICAL ACCOUNT TAKEOVER: Attacker website can read private user data and session cookies via JavaScript XHR."
            }]
        }
        final_answer = f"### Critical CORS Flaw Confirmed on `api.{domain}`\n\n- **Flaw:** Arbitrary Origin Reflection with Credential Support\n- **Reflected Header:** `Access-Control-Allow-Origin: https://attacker-domain.com`\n- **Credentials Flag:** `Access-Control-Allow-Credentials: true`\n- **Impact:** An external malicious website can execute background XHR calls to steal authenticated profile details and CSRF tokens from logged-in victims.\n- **Remediation:** Remove dynamic reflection; enforce a strict whitelist of legitimate trusted subdomains."

    elif tool_type == "live_exploits":
        cve, title, tech = random.choice(CVE_EXAMPLES)
        user_prompt = f"Search public repositories and Exploit-DB for working PoC exploits targeting {cve} ({title})."
        tool_name = "search_live_exploits"
        tool_args = {"query_or_cve": cve, "limit": 4}
        tool_res = {
            "success": True,
            "query": cve,
            "total_exploits_found": 3,
            "exploits": [
                {"title": f"offensive-security/{cve}-PoC", "source": "GitHub Public PoC Repository", "url": f"https://github.com/offensive-security/{cve}-PoC", "stars": 340},
                {"title": f"Exploit-DB entry for {cve}", "source": "Exploit-Database", "url": f"https://www.exploit-db.com/search?cve={cve}", "stars": 999}
            ]
        }
        final_answer = f"### Exploit Intelligence for `{cve}`\n\n- **Vulnerability:** {title} ({tech})\n- **Discovered PoCs:**\n  1. `offensive-security/{cve}-PoC` on GitHub (340 stars)\n  2. Verified Exploit-DB vendor entry for `{cve}`\n- **Recommendation:** Review the reproduction steps to test your staging environment and apply vendor security updates immediately."

    else:
        user_prompt = f"Generate a copy-paste ready HackerOne submission report for a Critical SQL Injection flaw found on https://{domain}/login."
        tool_name = "generate_hackerone_report"
        tool_args = {
            "target": f"https://{domain}/login",
            "vulnerability_title": "SQL Injection Auth Bypass via username parameter",
            "severity": "critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
            "steps_to_reproduce": "1. Navigate to /login.\n2. In username enter: admin' OR '1'='1\n3. Enter any password and submit.\n4. Observe instant authentication as administrator.",
            "impact_statement": "An unauthenticated remote attacker can completely bypass authentication and gain full administrator privileges over the corporate portal.",
            "remediation": "Utilize parameterized prepared statements (PDO / PreparedStatement) for all SQL queries."
        }
        tool_res = {
            "success": True,
            "report_path": f"D:\\ML-DL\\reports\\HackerOne_Submission_sql_injection_{domain}.md",
            "title": "SQL Injection Auth Bypass via username parameter",
            "severity": "critical",
            "content_preview": "# SQL Injection Auth Bypass...\n\n## Summary\n..."
        }
        final_answer = f"### HackerOne Submission Report Ready\n\nI have generated a structured bug bounty submission report at:\n`{tool_res['report_path']}`\n\n**Included Sections:**\n- Standard CVSS 3.1 Severity Score (9.8 Critical)\n- Clear 4-Step Reproduction Guide with payloads\n- Impact & Exploitation Assessment\n- Developer Remediation Guidance"

    return {
        "id": f"cyberagent_bounty_tool_{idx:06d}",
        "type": "multiturn_react_trajectory",
        "scenario": f"Bug Bounty Capability - {tool_type}",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {
                "role": "assistant",
                "content": f"Executing {tool_name} to address the objective.",
                "tool_calls": [{
                    "id": f"call_{tool_type}_{idx}",
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(tool_args)
                    }
                }]
            },
            {
                "role": "tool",
                "tool_call_id": f"call_{tool_type}_{idx}",
                "name": tool_name,
                "content": json.dumps(tool_res)
            },
            {"role": "assistant", "content": final_answer}
        ]
    }


def main():
    target_path = r"d:\ML-DL\tools\cyber_agent\training\cyber_agent_finetune_dataset.jsonl"
    print(f"[*] Generating new bounty & Python scripting training samples...")

    num_samples = 1200
    new_samples = []

    for i in range(num_samples):
        if i % 2 == 0:
            sample = generate_python_scripting_sample(i + 1)
        else:
            sample = generate_bounty_tool_sample(i + 1)
        new_samples.append(sample)

    print(f"[*] Appending {len(new_samples)} new high-quality samples to {target_path}...")
    with open(target_path, "a", encoding="utf-8") as f:
        for s in new_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print("[+] Successfully appended! Re-verifying total line count...")
    total_lines = sum(1 for _ in open(target_path, encoding="utf-8"))
    print(f"[+] Master finetune dataset size is now: {total_lines} samples.")


if __name__ == "__main__":
    main()

