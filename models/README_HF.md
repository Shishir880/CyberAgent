---
language:
- en
license: apache-2.0
tags:
- cybersecurity
- penetration-testing
- agent
- tool-use
- gguf
- qwen2.5
base_model: Qwen/Qwen2.5-3B-Instruct
---

# 🛡️ CyberAgent-3B (Fine-Tuned GGUF)

CyberAgent-3B is an autonomous cybersecurity and penetration testing assistant fine-tuned on multi-turn security auditing, vulnerability assessment, and deterministic tool-calling workflows.

## Model Details
- **Base Architecture:** Qwen2.5-3B-Instruct
- **Quantization:** Q4_K_M (1.93 GB GGUF)
- **Primary Focus:** External attack surface recon, OWASP vulnerability discovery, anti-hallucination evidence parsing, and server hardening (Nginx/Cloudflare WAF).

## Quick Run with Ollama
```bash
# 1. Download the GGUF and Modelfile
# 2. Build the Ollama model:
ollama create cyberagent-3b -f Modelfile

# 3. Run directly:
ollama run cyberagent-3b
```
