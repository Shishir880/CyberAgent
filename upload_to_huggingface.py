"""
CyberAgent - Hugging Face Model Uploader Script
================================================
Automates creating a model repository on Hugging Face and uploading
the quantized GGUF fine-tuned model and Modelfile with a professional Model Card.
"""

import os
import sys
from huggingface_hub import HfApi, create_repo

# Configuration
REPO_NAME = "CyberAgent-3B-GGUF"  # Your model repo name on HF
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
GGUF_FILE = os.path.join(MODEL_DIR, "Qwen2.5-3B-Instruct.Q4_K_M.gguf")
MODELFILE = os.path.join(MODEL_DIR, "Modelfile")

MODEL_CARD = """---
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
"""


def upload():
    # 1. Get Hugging Face Token
    hf_token = os.environ.get("HF_TOKEN")
    if not hf_token:
        print("\n[!] HF_TOKEN not found in environment variables.")
        hf_token = input("Enter your Hugging Face Write Token (from https://huggingface.co/settings/tokens): ").strip()
        if not hf_token:
            print("[-] Token is required to create a repository and upload files.")
            sys.exit(1)

    api = HfApi(token=hf_token)

    # 2. Get Authenticated User
    user_info = api.whoami()
    username = user_info["name"]
    full_repo_id = f"{username}/{REPO_NAME}"
    print(f"\n[+] Authenticated as: {username}")
    print(f"[+] Target Model Repository: https://huggingface.co/{full_repo_id}")

    # 3. Create Repo if it doesn't exist
    try:
        create_repo(repo_id=full_repo_id, repo_type="model", token=hf_token, exist_ok=True)
        print("[+] Repository verified/created.")
    except Exception as e:
        print(f"[-] Error creating repository: {e}")
        sys.exit(1)

    # 4. Upload Model Card (README.md)
    print("[*] Uploading Model Card (README.md)...")
    readme_path = os.path.join(MODEL_DIR, "README_HF.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(MODEL_CARD)

    api.upload_file(
        path_or_fileobj=readme_path,
        path_in_repo="README.md",
        repo_id=full_repo_id,
        repo_type="model"
    )
    print("[+] Model Card uploaded.")

    # 5. Upload Modelfile
    if os.path.exists(MODELFILE):
        print("[*] Uploading Modelfile...")
        api.upload_file(
            path_or_fileobj=MODELFILE,
            path_in_repo="Modelfile",
            repo_id=full_repo_id,
            repo_type="model"
        )
        print("[+] Modelfile uploaded.")

    # 6. Upload GGUF binary
    if os.path.exists(GGUF_FILE):
        file_size_gb = os.path.getsize(GGUF_FILE) / (1024 ** 3)
        print(f"[*] Uploading GGUF binary ({file_size_gb:.2f} GB): {os.path.basename(GGUF_FILE)}...")
        print("    (This will upload with progress tracking directly to Hugging Face LFS)")
        api.upload_file(
            path_or_fileobj=GGUF_FILE,
            path_in_repo=os.path.basename(GGUF_FILE),
            repo_id=full_repo_id,
            repo_type="model"
        )
        print("\n" + "="*60)
        print(f"🎉 SUCCESS! Model successfully published to Hugging Face:")
        print(f"👉 https://huggingface.co/{full_repo_id}")
        print("="*60)
    else:
        print(f"[-] GGUF file not found at: {GGUF_FILE}")


if __name__ == "__main__":
    upload()

