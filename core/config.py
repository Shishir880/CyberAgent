"""
CyberAgent - Configuration & API Provider Manager
Supports Local Ollama, OpenAI, DeepSeek, Groq, Google Gemini, OpenRouter, and Custom Endpoints.
"""

import os
import sys
import json
from typing import Dict, Any, Optional

if getattr(sys, "frozen", False):
    default_dev_dir = r"d:\ML-DL\tools\cyber_agent"
    if os.path.exists(default_dev_dir):
        pkg_dir = default_dev_dir
    else:
        pkg_dir = os.path.join(os.environ.get("USERPROFILE", os.getcwd()), ".cyberagent")
else:
    pkg_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
STORAGE_DIR = os.path.join(pkg_dir, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(STORAGE_DIR, "config.json")

PROVIDER_PRESETS = {
    "ollama": {
        "name": "Local Ollama (Zero Cost / 100% Private)",
        "base_url": "http://localhost:11434/v1",
        "api_key": "ollama",
        "default_model": "cyberagent-3b"
    },
    "gemini": {
        "name": "Google Gemini (via OpenAI compatibility)",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key": "",
        "default_model": "gemini-1.5-flash"
    },
    "deepseek": {
        "name": "DeepSeek (DeepSeek-V3 / R1 Reasoning)",
        "base_url": "https://api.deepseek.com/v1",
        "api_key": "",
        "default_model": "deepseek-chat"
    },
    "anthropic": {
        "name": "Anthropic Claude 3.5 Sonnet (via OpenRouter)",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key": "",
        "default_model": "anthropic/claude-3.5-sonnet"
    },
    "groq": {
        "name": "Groq Ultra-Fast (Qwen 3.8 27B / OSS)",
        "base_url": "https://api.groq.com/openai/v1",
        "api_key": "",
        "default_model": "qwen/qwen3.8-27b"
    },
    "openai": {
        "name": "OpenAI (GPT-4o / GPT-4o-mini)",
        "base_url": "https://api.openai.com/v1",
        "api_key": "",
        "default_model": "gpt-4o"
    },
    "openrouter": {
        "name": "OpenRouter Multi-Model Hub",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key": "",
        "default_model": "anthropic/claude-3.5-sonnet"
    }
}


class AgentConfig:
    def __init__(self):
        self.provider = "ollama"
        self.base_url = "http://localhost:11434/v1"
        self.api_key = "ollama"
        self.model = "cyberagent-3b"
        self.saved_keys: Dict[str, str] = {
            "ollama": "ollama",
            "gemini": "",
            "deepseek": "",
            "anthropic": "",
            "groq": "",
            "openai": "",
            "openrouter": ""
        }
        
        # Smart workspace_root detection: prefer repo root (d:/ML-DL) over tools/cyber_agent
        this_dir = os.path.dirname(os.path.abspath(__file__))
        derived_root = os.path.abspath(os.path.join(this_dir, "..", "..", ".."))
        self.workspace_root = derived_root if os.path.exists(os.path.join(derived_root, "tools")) else os.getcwd()
        self.max_steps = 25
        self.hitl_enabled = True
        self.load()

    def load(self):
        """Loads configuration from config.json or environment variables."""
        this_dir = os.path.dirname(os.path.abspath(__file__))
        derived_root = os.path.abspath(os.path.join(this_dir, "..", "..", ".."))

        target_cfg = CONFIG_FILE if os.path.exists(CONFIG_FILE) else None
        if target_cfg and os.path.exists(target_cfg):
            try:
                with open(target_cfg, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.provider = data.get("provider", self.provider)
                    self.base_url = data.get("base_url", self.base_url)
                    self.api_key = data.get("api_key", self.api_key)
                    self.model = data.get("model", self.model)
                    if "saved_keys" in data and isinstance(data["saved_keys"], dict):
                        self.saved_keys.update(data["saved_keys"])
                    
                    # Also record current key in saved_keys
                    if self.api_key and self.provider:
                        self.saved_keys[self.provider] = self.api_key

                    loaded_ws = data.get("workspace_root")
                    if loaded_ws and str(loaded_ws).strip():
                        self.workspace_root = os.path.abspath(str(loaded_ws).strip())
                    else:
                        self.workspace_root = derived_root if os.path.exists(derived_root) else os.getcwd()
                    self.max_steps = data.get("max_steps", self.max_steps)
                    self.hitl_enabled = data.get("hitl_enabled", self.hitl_enabled)
            except Exception:
                pass

        # Environment variable overrides
        if os.environ.get("OPENAI_API_KEY") and self.provider == "openai":
            self.api_key = os.environ.get("OPENAI_API_KEY")
            self.saved_keys["openai"] = self.api_key
        if os.environ.get("DEEPSEEK_API_KEY") and self.provider == "deepseek":
            self.api_key = os.environ.get("DEEPSEEK_API_KEY")
            self.saved_keys["deepseek"] = self.api_key
        if os.environ.get("GROQ_API_KEY") and self.provider == "groq":
            self.api_key = os.environ.get("GROQ_API_KEY")
            self.saved_keys["groq"] = self.api_key
        if os.environ.get("GEMINI_API_KEY") and self.provider == "gemini":
            self.api_key = os.environ.get("GEMINI_API_KEY")
            self.saved_keys["gemini"] = self.api_key

    def save(self):
        """Persists configuration to config.json."""
        if self.provider and self.api_key:
            self.saved_keys[self.provider] = self.api_key

        data = {
            "provider": self.provider,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "model": self.model,
            "workspace_root": self.workspace_root,
            "max_steps": self.max_steps,
            "hitl_enabled": self.hitl_enabled,
            "saved_keys": self.saved_keys
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def set_provider(self, provider_name: str, api_key: Optional[str] = None, model: Optional[str] = None):
        """Sets and presets provider configurations with saved key restoration."""
        provider_name = provider_name.lower().strip()
        if provider_name in PROVIDER_PRESETS:
            preset = PROVIDER_PRESETS[provider_name]
            self.provider = provider_name
            self.base_url = preset["base_url"]
            self.model = model or preset["default_model"]
            
            # API key resolution: passed > previously saved > preset default
            if api_key:
                self.api_key = api_key
                self.saved_keys[provider_name] = api_key
            elif self.saved_keys.get(provider_name):
                self.api_key = self.saved_keys[provider_name]
            elif preset["api_key"]:
                self.api_key = preset["api_key"]
            else:
                self.api_key = ""
                
            self.save()
            return True
        return False
