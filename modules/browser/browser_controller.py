"""
CyberAgent Autonomous Browser Controller (Playwright Chromium)
==============================================================
Provides full autonomous web browser automation for CyberAgent:
- Headless Chromium navigation & JavaScript rendering (React, Vue, Angular SPAs)
- Interactive element clicking, typing, and form submissions
- Full-page and element screenshot capturing in screenshots/
- Network traffic & API endpoint inspection
- DOM content extraction, cookie & localStorage inspection
"""

import os
import time
import datetime
from typing import Dict, Any, List, Optional
from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page, Playwright


class AutonomousBrowserController:
    """
    Singleton-capable autonomous browser manager maintaining session context.
    """
    def __init__(self, workspace_root: Optional[str] = None, headless: bool = True):
        package_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
        self.workspace_root = workspace_root or package_root
        self.screenshots_dir = os.path.join(self.workspace_root, "screenshots")
        os.makedirs(self.screenshots_dir, exist_ok=True)
        self.headless = headless
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.captured_network_requests: List[Dict[str, Any]] = []

    def _ensure_browser(self):
        """Initializes Playwright Chromium if not already active."""
        if not self.playwright:
            self.playwright = sync_playwright().start()
        if not self.browser or not self.browser.is_connected():
            self.browser = self.playwright.chromium.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
        if not self.context:
            self.context = self.browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CyberAgent/3.0"
            )
            # Setup network request listener
            self.captured_network_requests = []
            self.context.on("request", self._on_request)
        if not self.page or self.page.is_closed():
            self.page = self.context.new_page()

    def _on_request(self, request):
        try:
            url = request.url
            if any(url.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2"]):
                return
            self.captured_network_requests.append({
                "method": request.method,
                "url": url,
                "resource_type": request.resource_type
            })
            if len(self.captured_network_requests) > 50:
                self.captured_network_requests.pop(0)
        except Exception:
            pass

    def navigate(self, url: str, wait_until: str = "load", timeout_ms: int = 15000) -> Dict[str, Any]:
        """
        Navigates to URL, renders JavaScript, and returns page metadata, text summary, and interactive elements.
        """
        if not url.startswith(("http://", "https://", "file://")):
            url = "http://" + url

        try:
            self._ensure_browser()
            self.captured_network_requests.clear()
            response = self.page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            self.page.wait_for_timeout(1000)

            title = self.page.title()
            final_url = self.page.url
            status_code = response.status if response else 200

            # Extract interactive elements for autonomous agent decision-making
            interactive_elements = self._extract_interactive_elements()
            
            # Clean text content preview
            body_text = self.page.inner_text("body")
            lines = [line.strip() for line in body_text.splitlines() if line.strip()]
            preview = "\n".join(lines[:30])

            return {
                "success": True,
                "title": title,
                "final_url": final_url,
                "status_code": status_code,
                "content_preview": preview,
                "interactive_elements": interactive_elements,
                "captured_api_requests_count": len(self.captured_network_requests)
            }
        except Exception as e:
            return {"success": False, "url": url, "error": str(e)}

    def _extract_interactive_elements(self) -> Dict[str, Any]:
        """Extracts clickable links, buttons, and input fields from current page."""
        try:
            links = []
            for a in self.page.query_selector_all("a[href]")[:15]:
                text = (a.inner_text() or "").strip()
                href = a.get_attribute("href") or ""
                if text or href:
                    links.append({"text": text[:40], "href": href[:80]})

            buttons = []
            for b in self.page.query_selector_all("button, input[type='button'], input[type='submit']")[:10]:
                text = (b.inner_text() or b.get_attribute("value") or "").strip()
                b_id = b.get_attribute("id") or b.get_attribute("name") or ""
                buttons.append({"text": text[:30], "selector": f"#{b_id}" if b_id else "button"})

            inputs = []
            for inp in self.page.query_selector_all("input:not([type='hidden']), textarea, select")[:10]:
                inp_name = inp.get_attribute("name") or inp.get_attribute("id") or ""
                inp_type = inp.get_attribute("type") or "text"
                placeholder = inp.get_attribute("placeholder") or ""
                inputs.append({"name": inp_name, "type": inp_type, "placeholder": placeholder[:40]})

            return {
                "links_sample": links,
                "buttons": buttons,
                "inputs": inputs
            }
        except Exception:
            return {}

    def interact(self, action: str, selector: str, value: Optional[str] = None, timeout_ms: int = 5000) -> Dict[str, Any]:
        """
        Performs autonomous browser interaction: 'click', 'fill', 'press', 'hover', 'scroll'.
        """
        action = action.lower().strip()
        try:
            self._ensure_browser()
            
            if action == "click":
                self.page.wait_for_selector(selector, timeout=timeout_ms)
                self.page.click(selector)
                self.page.wait_for_timeout(1000)
                return {"success": True, "action": "click", "selector": selector, "current_url": self.page.url, "title": self.page.title()}

            elif action in ["fill", "type"]:
                if value is None:
                    return {"success": False, "error": "Value required for fill/type action."}
                self.page.wait_for_selector(selector, timeout=timeout_ms)
                self.page.fill(selector, str(value))
                return {"success": True, "action": "fill", "selector": selector, "value_entered": value}

            elif action == "press":
                key = value or "Enter"
                self.page.keyboard.press(key)
                self.page.wait_for_timeout(1000)
                return {"success": True, "action": "press", "key": key, "current_url": self.page.url}

            elif action == "hover":
                self.page.wait_for_selector(selector, timeout=timeout_ms)
                self.page.hover(selector)
                return {"success": True, "action": "hover", "selector": selector}

            elif action == "scroll":
                delta_y = int(value) if value and value.lstrip("-").isdigit() else 500
                self.page.mouse.wheel(0, delta_y)
                self.page.wait_for_timeout(500)
                return {"success": True, "action": "scroll", "delta_y": delta_y}

            else:
                return {"success": False, "error": f"Unsupported browser action: '{action}'. Use click, fill, press, hover, or scroll."}

        except Exception as e:
            return {"success": False, "action": action, "selector": selector, "error": str(e)}

    def capture_screenshot(self, filename: Optional[str] = None, full_page: bool = True) -> Dict[str, Any]:
        """
        Captures full-page high-resolution PNG screenshot and returns the file path.
        """
        try:
            self._ensure_browser()
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = filename or f"screenshot_{ts}.png"
            if not fname.endswith(".png"):
                fname += ".png"
            save_path = os.path.join(self.screenshots_dir, fname)
            self.page.screenshot(path=save_path, full_page=full_page)
            return {
                "success": True,
                "screenshot_path": os.path.abspath(save_path),
                "url": self.page.url,
                "title": self.page.title(),
                "file_size_kb": round(os.path.getsize(save_path) / 1024, 1)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_js(self, script: str) -> Dict[str, Any]:
        """
        Executes arbitrary JavaScript in current page context and returns evaluation result.
        """
        try:
            self._ensure_browser()
            result = self.page.evaluate(script)
            return {
                "success": True,
                "evaluation_result": result,
                "current_url": self.page.url
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_network_activity(self) -> Dict[str, Any]:
        """Returns captured network requests and API calls from current page session."""
        return {
            "success": True,
            "total_requests": len(self.captured_network_requests),
            "requests": self.captured_network_requests[-25:]
        }

    def set_headless(self, headless: bool):
        """Switches between headless (silent background) and headed (visible GUI window) mode."""
        if self.headless != headless:
            self.close()
            self.headless = headless

    def close(self):
        """Closes browser session."""
        try:
            if self.context:
                self.context.close()
                self.context = None
            if self.browser:
                self.browser.close()
                self.browser = None
            if self.playwright:
                self.playwright.stop()
                self.playwright = None
        except Exception:
            pass


# Global singleton controller
_GLOBAL_BROWSER: Optional[AutonomousBrowserController] = None

def get_browser_controller(workspace_root: Optional[str] = None, headless: Optional[bool] = None) -> AutonomousBrowserController:
    global _GLOBAL_BROWSER
    if _GLOBAL_BROWSER is None:
        _GLOBAL_BROWSER = AutonomousBrowserController(workspace_root=workspace_root, headless=True if headless is None else headless)
    elif headless is not None and _GLOBAL_BROWSER.headless != headless:
        _GLOBAL_BROWSER.set_headless(headless)
    return _GLOBAL_BROWSER
