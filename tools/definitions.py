"""
CyberAgent Tool Specifications & Function Calling Schemas
========================================================
Defines standard OpenAI/JSON Schema definitions for all 28 tools
supported by the CyberAgent ReAct autonomous execution engine.
"""

from typing import List, Dict, Any


def get_tool_definitions() -> List[Dict[str, Any]]:
    """Returns standard OpenAI/JSON Schema tool specifications for function calling."""
    return [
        {
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "Executes a PowerShell or shell command in the terminal. Use to run scripts, compilers, tests, git, package managers, or inspect system state. Note: Destructive or mutating commands against CyberAgent's project folder are strictly forbidden.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The exact shell command line string to run."},
                        "cwd": {"type": "string", "description": "Optional working directory for the command."},
                        "timeout": {"type": "integer", "description": "Command timeout in seconds (default: 60)."}
                    },
                    "required": ["command"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "create_folder",
                "description": "Creates a directory and any parent folders required. Cannot target CyberAgent's own project folder.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "folder_path": {"type": "string", "description": "The path of the folder to create."}
                    },
                    "required": ["folder_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Reads the text content of a file with line numbers. Use before editing to understand code and line context.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file to view."},
                        "start_line": {"type": "integer", "description": "Starting line number (1-indexed)."},
                        "end_line": {"type": "integer", "description": "Ending line number (inclusive)."}
                    },
                    "required": ["file_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Creates a new file or completely overwrites an existing file with provided code content. Note: Cannot target CyberAgent's own project directory (tools/cyber_agent) which is read-only and immutable.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file to create or overwrite."},
                        "content": {"type": "string", "description": "The complete text content of the file."}
                    },
                    "required": ["file_path", "content"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": "Surgically replaces a specific code block in an existing file. Use to fix bugs without rewriting entire files. Note: Cannot target CyberAgent's own project directory (tools/cyber_agent) which is read-only and immutable.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file to edit."},
                        "target_snippet": {"type": "string", "description": "The exact character-for-character snippet to find and replace."},
                        "replacement_snippet": {"type": "string", "description": "The new replacement code snippet."}
                    },
                    "required": ["file_path", "target_snippet", "replacement_snippet"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_directory",
                "description": "Lists contents of a directory (files and folders).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "dir_path": {"type": "string", "description": "Directory path to inspect (default: .)."}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_code",
                "description": "Searches for text, function names, error keywords, or imports across files in a directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Keyword or substring to find."},
                        "dir_path": {"type": "string", "description": "Directory to search within (default: .)."}
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_website_security",
                "description": "Runs full WebShield security posture audit on any URL or domain. Audits WAF, TLS, DNS SPF/DMARC/CAA, open ports, OWASP security headers, and exposure leaks.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The URL or domain to audit (e.g. 'http://demo.testfire.net' or 'example.com')."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_security_remediation",
                "description": "Fetches tested OWASP security hardening rules, NGINX/Apache configs, and code remediation snippets for fixing security header or exposure issues.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "rule_or_header_name": {"type": "string", "description": "Name of header or vulnerability (e.g. 'content-security-policy', 'strict-transport-security', '.env', 'cors')."}
                    },
                    "required": ["rule_or_header_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "probe_service_ports",
                "description": "Fast multi-threaded socket scan on common ports (21 FTP, 22 SSH, 80 HTTP, 443 HTTPS, 3306 MySQL, 5432 Postgres, 6379 Redis, 8080/8443) with latency ms.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "The target hostname or IP to scan (e.g. 'demo.testfire.net')."}
                    },
                    "required": ["hostname"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "scan_codebase_sast",
                "description": "Performs Static Application Security Testing (SAST) on source code. Finds SQL injections, hardcoded secrets, dangerous eval/exec, shell=True command injections, and path traversals.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_dir": {"type": "string", "description": "Directory path to scan for code security vulnerabilities (default: .)."}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_hardening_config",
                "description": "Generates complete production security configs for a domain: nginx_hardened.conf (HSTS, CSP, ciphers), cloudflare_waf_rules.json, dns_records.txt (SPF/DMARC/CAA), and .htaccess.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "The domain name to generate hardening configurations for (e.g. 'example.com')."}
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "lookup_cve_advisory",
                "description": "Searches CVE vulnerability advisories and official mitigations for a detected software/server banner (e.g. 'Apache-Coyote/1.1', 'nginx 1.18', 'PHP 7.4', 'Express', 'Spring').",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tech_string": {"type": "string", "description": "The software name and version to search (e.g. 'Apache-Coyote/1.1')."}
                    },
                    "required": ["tech_string"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_pdf_report",
                "description": "Performs security audit on target URL and generates a comprehensive, client-ready executive & technical PDF assessment report in reports/ folder.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The target URL or domain to audit and generate PDF report for."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "recall_memory",
                "description": "Recalls security findings, target intelligence, and vulnerability progression from persistent Cognitive Memory using Hybrid Stemmed BM25 + Dense Vector Cosine Similarity.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query or natural language question (e.g. 'SQL injection vulnerabilities', 'open ports', 'PHP CVE'). Uses NLTK morphological stemming."},
                        "target": {"type": "string", "description": "Optional target domain or IP (e.g. 'bizmatepro.xyz', 'demo.testfire.net') to retrieve its full security dossier."},
                        "category": {"type": "string", "description": "Optional category filter: 'vulnerability', 'audit', 'leak', 'port', 'recon'."},
                        "top_k": {"type": "integer", "description": "Maximum number of most relevant findings to return (default: 5)."}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "remember_memory",
                "description": "Explicitly commits a critical finding, credential, vulnerability proof, or technical intelligence into persistent Cognitive Memory with NLTK stemming and dense vector embeddings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "The exact fact, vulnerability finding, leaked secret, or intelligence note to remember."},
                        "target": {"type": "string", "description": "Optional target host or domain associated with this memory."},
                        "category": {"type": "string", "description": "Category: 'vulnerability', 'credential', 'leak', 'port', 'architecture', 'note'."},
                        "metadata": {"type": "object", "description": "Optional structured metadata (severity, cve, port, cwe)."}
                    },
                    "required": ["content"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_target_dossier",
                "description": "Retrieves the complete historical intelligence dossier for a target: first/last seen, security score progression, open ports, confirmed vulnerabilities, and MITRE ATT&CK techniques.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target domain or IP (e.g. 'demo.testfire.net', 'bizmatepro.xyz')."}
                    },
                    "required": ["target"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "crawl_attack_surface",
                "description": "Active Web Spider & Attack Surface Form Extractor. Recursively crawls a target web application to discover pages, extract HTML forms (login, search, file upload), extract parameterized GET query strings, and map internal REST APIs for security testing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The base URL or domain of the target to spider (e.g. 'http://demo.testfire.net')."},
                        "max_depth": {"type": "integer", "description": "Maximum link crawl depth (default: 2)."},
                        "max_pages": {"type": "integer", "description": "Maximum total pages to spider (default: 20)."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "fuzz_web_endpoints",
                "description": "Rapid non-destructive path discovery and sensitive endpoint fuzzing. Probes for .env secrets, git leaks (/.git/HEAD), database dumps, admin portals, and Swagger APIs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The target URL or domain to fuzz (e.g. 'http://demo.testfire.net')."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "verify_target_vulnerability",
                "description": "Executes safe, non-destructive vulnerability verification probes on authorized targets. Probes for SQL injection syntax errors/auth bypass, reflected XSS, or CORS misconfiguration.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "Target URL to probe."},
                        "vuln_type": {"type": "string", "description": "Type of vulnerability to verify: 'sqli', 'xss', 'cors'."},
                        "parameter": {"type": "string", "description": "Optional query parameter or endpoint to test."}
                    },
                    "required": ["target_url", "vuln_type"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_full_pentest_audit",
                "description": "Master Autonomous Penetration Testing Playbook. Executes 5-phase assessment (OSINT, Ports, CVEs, Endpoint Fuzzing, Exploit Probes) and synthesizes attack surface score and risk level.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The target website or domain to perform full penetration testing audit on."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "map_mitre_attack",
                "description": "Maps detected security flaws to the MITRE ATT&CK Enterprise Framework (Tactics, Technique IDs like T1190, T1059, T1552, and official Mitigations).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vulnerabilities": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of vulnerability titles or keywords (e.g. ['sqli', 'xss', 'secret_leak'])."
                        }
                    },
                    "required": ["vulnerabilities"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_php_threats",
                "description": "Dedicated diagnostic scanner for the latest high-severity PHP vulnerability taking down government sites: CVE-2024-4577 (Windows PHP-CGI Argument Injection RCE). Detects vulnerability and generates emergency Apache/NGINX/Cloudflare mitigation rules.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "Target website or government portal URL to test."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "browser_navigate",
                "description": "Navigates to URL using autonomous Playwright Chromium headless browser. Renders full client-side JavaScript (React, Vue, Angular SPAs), extracts page title, status code, interactive buttons, links, inputs, and clean text preview.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL to navigate to (e.g. 'http://demo.testfire.net')."},
                        "wait_until": {"type": "string", "description": "Wait condition: 'load', 'domcontentloaded', or 'networkidle' (default: 'load')."}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "browser_interact",
                "description": "Performs interactive browser actions on the currently active page: click buttons/links, fill forms/inputs, press keys (e.g. 'Enter'), hover, or scroll.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "Interaction action: 'click', 'fill', 'press', 'hover', or 'scroll'."},
                        "selector": {"type": "string", "description": "CSS selector or element identifier to interact with (e.g. '#uid', 'button[type=submit]')."},
                        "value": {"type": "string", "description": "Value to type if action is 'fill', key name if action is 'press' (e.g. 'Enter'), or scroll delta Y."}
                    },
                    "required": ["action", "selector"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "browser_capture_screenshot",
                "description": "Captures a high-resolution PNG screenshot of the currently active browser page and saves it into the screenshots/ directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "Optional custom filename for the screenshot (e.g. 'login_portal.png')."},
                        "full_page": {"type": "boolean", "description": "Whether to capture the entire scrollable page height (default: true)."}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "browser_execute_js",
                "description": "Executes custom JavaScript expression inside the active browser page context to inspect cookies, localStorage, session state, or dynamic DOM elements.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "script": {"type": "string", "description": "The JavaScript code to evaluate (e.g. 'document.cookie' or 'localStorage.getItem(\"token\")')."}
                    },
                    "required": ["script"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "browser_get_network_activity",
                "description": "Retrieves recent network requests, XHR / Fetch API calls, and background network traffic made by the web application during browsing.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_login_security",
                "description": "Audits a web login endpoint for brute-force defenses: verifies HTTP 429 rate limiting, account lockout mechanisms, CAPTCHA challenges, and response timing variance.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "login_url": {"type": "string", "description": "The URL of the login endpoint to test."},
                        "username": {"type": "string", "description": "Test username (default: 'admin')."},
                        "attempts": {"type": "integer", "description": "Number of consecutive test attempts to run (default: 5)."},
                        "user_field": {"type": "string", "description": "Form input field name for username (default: 'username')."},
                        "pw_field": {"type": "string", "description": "Form input field name for password (default: 'password')."}
                    },
                    "required": ["login_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "detect_waf_fingerprint",
                "description": "Fingerprints active Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Fortinet, Azure WAF, Google Cloud Armor, Fastly) using passive headers and safe heuristic probes.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The target website URL or domain to fingerprint."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_account_enumeration",
                "description": "Tests whether an authentication endpoint leaks valid user existence via timing side-channels (response elapsed time variance) or differing error messages (CWE-204).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The authentication URL to probe."},
                        "usernames": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of usernames to test (e.g. ['admin', 'root', 'nonexistent_user_9921'])."
                        },
                        "user_field": {"type": "string", "description": "Username field parameter name (default: 'username')."},
                        "pw_field": {"type": "string", "description": "Password field parameter name (default: 'password')."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "extract_sensitive_leaks",
                "description": "Harvesters sensitive secrets and developer information from target webpage HTML: API keys, JWT tokens, AWS Access Keys, Google API keys, private keys, and hidden developer comments.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The target web page URL to inspect for exposed secrets and comments."}
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_form_csrf_security",
                "description": "Analyzes all HTML forms on a page for CSRF protections: discovers CSRF tokens, flags insecure GET transmissions for credentials, and checks if missing token requests are rejected.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "form_url": {"type": "string", "description": "The URL containing HTML forms to audit for CSRF vulnerabilities."}
                    },
                    "required": ["form_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "calculate_datetime",
                "description": "Performs versatile date, time, duration, arithmetic (+/- days/hours/minutes), Unix timestamp conversion, and SSL/JWT expiration calculations.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["now", "add", "subtract", "diff", "convert", "expiry_check"],
                            "description": "Calculation operation to perform: 'now' (current local/UTC time & timezone), 'add' (add offset to date), 'subtract' (subtract offset from date), 'diff' (duration between two dates), 'convert' (timestamp <-> readable date string), 'expiry_check' (evaluate certificate or token expiration)."
                        },
                        "base_date": {
                            "type": "string",
                            "description": "Base date string (e.g. '2026-10-25 14:30:00' or '2026-10-25'). Defaults to current time if omitted for arithmetic."
                        },
                        "target_date": {
                            "type": "string",
                            "description": "Target date string for difference calculation or expiration evaluation."
                        },
                        "days": {
                            "type": "integer",
                            "description": "Number of days to add or subtract (default: 0)."
                        },
                        "hours": {
                            "type": "integer",
                            "description": "Number of hours to add or subtract (default: 0)."
                        },
                        "minutes": {
                            "type": "integer",
                            "description": "Number of minutes to add or subtract (default: 0)."
                        },
                        "seconds": {
                            "type": "integer",
                            "description": "Number of seconds to add or subtract (default: 0)."
                        },
                        "timestamp": {
                            "type": "number",
                            "description": "Unix epoch timestamp to convert into readable date string."
                        },
                        "date_format": {
                            "type": "string",
                            "description": "Output date format string (default: '%Y-%m-%d %H:%M:%S')."
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_internet",
                "description": "Searches the live internet in real-time for cybersecurity advisories, recent CVEs, software documentation, exploit analysis, or technical research.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The search keywords or query phrase (e.g. 'CVE-2024-3094 xz backdoor' or 'Express.js helmet middleware security headers')."
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of search results to retrieve (default: 5, max: 10)."
                        }
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "scrape_web_page",
                "description": "Scrapes and parses a web page URL in real-time, removing boilerplate scripts/ads to return clean, readable text content, title, and key links.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The HTTP or HTTPS URL of the webpage to scrape."
                        },
                        "extract_main_text": {
                            "type": "boolean",
                            "description": "Whether to filter out navigation/footers and retain main article/text content (default: true)."
                        },
                        "max_length": {
                            "type": "integer",
                            "description": "Maximum text length in characters to return (default: 4000)."
                        }
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "enumerate_subdomains",
                "description": "Enumerates valid subdomains of a target domain using Certificate Transparency logs (crt.sh) and multi-threaded DNS resolution.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain name (e.g. 'example.com')."
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of subdomains to resolve and return (default: 50)."
                        }
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_jwt_security",
                "description": "Audits JSON Web Tokens (JWT) for signature vulnerabilities, alg: none bypass, expired claims, and weak HMAC secret cracking.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "token": {
                            "type": "string",
                            "description": "The raw JWT string (with or without 'Bearer ' prefix)."
                        },
                        "secret_wordlist": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of candidate secret keys for HMAC dictionary audit."
                        }
                    },
                    "required": ["token"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_security_payload",
                "description": "Generates security verification payloads with various encoding and obfuscation formats (URL, double-URL, Base64, Hex, HTML entities) for authorized testing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "payload_type": {
                            "type": "string",
                            "description": "Type of vulnerability payload (e.g. 'xss', 'sqli', 'cmdi')."
                        },
                        "raw_payload": {
                            "type": "string",
                            "description": "Raw payload string to encode."
                        },
                        "encoding": {
                            "type": "string",
                            "enum": ["url", "double_url", "base64", "hex", "html_entity", "all"],
                            "description": "Encoding format to apply (default: url)."
                        }
                    },
                    "required": ["raw_payload"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "check_proxy_health",
                "description": "Audits proxy availability, latency in milliseconds, exit IP, and HTTP/HTTPS connectivity.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "proxy_list": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of proxy endpoints (e.g. ['http://127.0.0.1:8080', 'socks5://10.0.0.1:1080'])."
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds per proxy check (default: 5)."
                        }
                    },
                    "required": ["proxy_list"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "lookup_whois_and_ip",
                "description": "Advanced WHOIS Domain Lookup & IP Geolocation Intelligence (from Bizmatepro): extracts domain registration/expiry dates, registrar, abuse contacts, nameservers, plus public IP geolocation, ISP, ASN, and security risk flags.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target domain (e.g. 'example.com'), IP address (e.g. '8.8.8.8'), or 'me' to lookup own public IP connection details."
                        },
                        "include_raw": {
                            "type": "boolean",
                            "description": "Whether to include raw unparsed WHOIS text dump (default: false)."
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "mine_historical_endpoints",
                "description": "Mines Wayback Machine (web.archive.org) CDX API for historical URLs, past API versions, sensitive endpoints (.env, .sql, .bak), and parameters.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target root domain or subdomain to mine historical URLs for (e.g. 'example.com')."
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of archive records to retrieve (default: 50)."
                        }
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "scan_repository_secrets",
                "description": "Recursively scans local codebase and git repositories for exposed API keys, private keys, database connection strings, and tokens using high-precision regex and Shannon entropy.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "dir_path": {
                            "type": "string",
                            "description": "Directory path to scan for secrets (default: '.' for workspace root)."
                        },
                        "max_files": {
                            "type": "integer",
                            "description": "Maximum number of text/code files to scan (default: 250)."
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_cloud_storage_exposure",
                "description": "Probes AWS S3, Google Cloud Storage, and Azure Blob storage endpoints for public exposure, directory listing permissions, and unauthenticated access based on company/brand name.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_name": {
                            "type": "string",
                            "description": "Target brand name or root domain (e.g. 'company' or 'company.com')."
                        },
                        "custom_permutations": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional custom list of bucket name suffixes to probe (e.g. ['-backup', '-data'])."
                        }
                    },
                    "required": ["target_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "parse_network_audit_scan",
                "description": "Parses Nmap / Masscan XML scan files or raw XML strings into structured intelligence: open ports, banner versions, plaintext protocols, and high-risk exposed database/service vectors.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path_or_xml": {
                            "type": "string",
                            "description": "File path to Nmap XML output file, or raw XML string content to parse."
                        }
                    },
                    "required": ["file_path_or_xml"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "detect_subdomain_takeover",
                "description": "Analyzes target subdomains for dangling CNAME DNS records pointing to orphaned third-party cloud services (AWS S3, GitHub Pages, Heroku, Fastly, Shopify, Zendesk) that allow hostile takeover.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain_or_subdomains": {
                            "description": "Target domain (e.g. 'example.com') or array of specific subdomains to test for dangling CNAME takeover."
                        }
                    },
                    "required": ["domain_or_subdomains"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_attack_surface_graph",
                "description": "Generates a rich, interactive, standalone HTML visual knowledge graph (Vis.js Network) of target domains, subdomains, IPs, ports, cloud storage, and confirmed vulnerabilities.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "output_html_path": {
                            "type": "string",
                            "description": "Optional custom file path to save the generated HTML graph report (defaults to reports/attack_surface_graph.html)."
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "remediate_and_verify_vulnerability",
                "description": "Executes an autonomous closed-loop Find -> Patch -> Verify cycle: surgically patches code flaws in target applications, re-executes PoC verification, and auto-reverts if verification fails.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_file": {
                            "type": "string",
                            "description": "Path to the vulnerable target application code file to patch."
                        },
                        "vulnerable_code": {
                            "type": "string",
                            "description": "The exact character-for-character vulnerable code block to find and replace."
                        },
                        "secure_code": {
                            "type": "string",
                            "description": "The hardened, sanitized replacement code block."
                        },
                        "reproduction_command": {
                            "type": "string",
                            "description": "Optional shell/PowerShell test command to re-run and verify the vulnerability is eliminated."
                        },
                        "expected_failure_keyword": {
                            "type": "string",
                            "description": "Optional keyword that indicates vulnerability exploit (should no longer appear after successful patch)."
                        },
                        "test_cwd": {
                            "type": "string",
                            "description": "Optional working directory for reproduction command."
                        }
                    },
                    "required": ["target_file", "vulnerable_code", "secure_code"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "harvest_js_secrets_and_endpoints",
                "description": "Deeply crawls and parses all JavaScript bundles and scripts on a target web application to extract hidden API routes, REST endpoints, and hardcoded API tokens/keys (AWS, Google, Stripe, Slack, JWT).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target web application URL (e.g. 'https://target.com' or 'https://app.target.com')."
                        },
                        "max_scripts": {
                            "type": "integer",
                            "description": "Maximum number of JavaScript files to download and audit (default: 15)."
                        }
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "fuzz_sensitive_paths_and_backups",
                "description": "Actively probes target web servers for high-impact exposed files and credentials (e.g. /.env, /.git/HEAD, /actuator/health, /swagger.json, /wp-config.php.bak) with signature verification to eliminate false 404s.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "base_url": {
                            "type": "string",
                            "description": "Target base URL (e.g. 'https://target.com' or 'https://api.target.com')."
                        },
                        "custom_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional array of custom URI paths to fuzz along with default sensitive targets."
                        }
                    },
                    "required": ["base_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "resolve_waf_and_origin_ip",
                "description": "Uncovers potential direct origin IP addresses behind Cloudflare/Akamai WAFs by evaluating historical DNS, origin-indicating subdomains (direct, dev, origin), and DNS records.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The target domain name (e.g. 'target.com')."
                        }
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_cors_misconfiguration",
                "description": "Tests web endpoints for dangerous Cross-Origin Resource Sharing (CORS) flaws (arbitrary origin reflection, null origin bypass, and Access-Control-Allow-Credentials: true) enabling cross-site data theft and account takeover.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target API or web application endpoint to probe for CORS flaws."
                        }
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "audit_broken_link_hijacking",
                "description": "Scans web pages for abandoned, deleted, or unregistered social media and asset profiles (Twitter/X, GitHub, Discord, Instagram) enabling high-impact Broken Link Hijacking / Account Takeover.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target web application or homepage URL to audit for broken links."
                        }
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_python_code",
                "description": "Autonomously writes and executes custom Python scripts (custom PoC exploits, multithreaded network scanners, deep parameter fuzzers, API payload decoders) in the sandbox workspace, capturing full stdout, stderr, and execution duration.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The complete Python script code to write and execute."
                        },
                        "script_name": {
                            "type": "string",
                            "description": "Optional custom filename for the script (e.g. 'custom_exploit_poc.py')."
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Execution timeout in seconds (default: 45)."
                        }
                    },
                    "required": ["code"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_live_exploits",
                "description": "Searches GitHub and public exploit databases for live 1-Day CVE Proof-of-Concept (PoC) scripts and functional exploit code.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query_or_cve": {
                            "type": "string",
                            "description": "CVE identifier (e.g. 'CVE-2024-4577') or technology name (e.g. 'Apache 2.4.49')."
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of exploits/PoCs to retrieve (default: 8)."
                        }
                    },
                    "required": ["query_or_cve"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "mine_hidden_parameters",
                "description": "Fuzzes target web endpoints for hidden or unlinked query parameters (e.g. ?debug=true, ?admin=1, ?test=1, ?role=admin) that expose stack traces or debug modes.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target web application endpoint to probe for hidden parameters."
                        },
                        "custom_params": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of additional parameter names to test."
                        }
                    },
                    "required": ["target_url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_hackerone_report",
                "description": "Generates a structured, copy-paste ready HackerOne or Bugcrowd markdown submission report including summary, reproduction steps, CVSS vector, and remediation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target domain or application URL."},
                        "vulnerability_title": {"type": "string", "description": "Descriptive title of the vulnerability."},
                        "severity": {"type": "string", "description": "Assessed severity: critical, high, medium, or low."},
                        "cvss_vector": {"type": "string", "description": "CVSS 3.1 vector string or base score."},
                        "steps_to_reproduce": {"type": "string", "description": "Step-by-step reproduction instructions."},
                        "impact_statement": {"type": "string", "description": "Clear explanation of business and security impact."},
                        "remediation": {"type": "string", "description": "Recommended defensive patch or fix."},
                        "output_filename": {"type": "string", "description": "Optional custom filename for the report."}
                    },
                    "required": ["target", "vulnerability_title", "severity", "steps_to_reproduce", "impact_statement", "remediation"]
                }
            }
        }
    ]


