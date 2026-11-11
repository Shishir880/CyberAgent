"""
CyberAgent - Real-Time Web Search & Web Scraping Engine
========================================================
Provides autonomous real-time internet intelligence and web page scraping:
- search_internet: Live search engine queries returning top titles, snippets, and clean destination URLs
- scrape_web_page: Deep content harvesting, stripping boilerplate/scripts and returning structured markdown
"""

import re
import base64
import urllib.parse
from typing import Dict, Any, List, Optional
import requests
from bs4 import BeautifulSoup


class WebSearchToolsMixin:
    """Mixin implementing real-time web search and content scraping capabilities."""

    def search_internet(
        self,
        query: str,
        max_results: int = 5
    ) -> Dict[str, Any]:
        """
        Searches the live internet in real-time for cybersecurity advisories, CVEs, documentation, or intelligence.

        Args:
            query: The search keywords or query phrase (e.g. 'CVE-2024-3094 xz backdoor analysis').
            max_results: Maximum number of search results to return (default: 5, max: 10).

        Returns:
            Dict containing list of results with title, destination URL, and snippet.
        """
        if not query or not query.strip():
            return {"success": False, "error": "Query cannot be empty."}

        max_results = min(max(1, int(max_results)), 10)
        query = query.strip()

        # Engine 1: Bing Search with base64 redirect resolution
        results: List[Dict[str, str]] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            encoded_q = urllib.parse.quote_plus(query)
            bing_url = f"https://www.bing.com/search?q={encoded_q}&count={max_results * 2}"
            r = requests.get(bing_url, headers=headers, timeout=10)

            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for li in soup.select("li.b_algo"):
                    h2 = li.select_one("h2 a")
                    if not h2:
                        continue
                    title = h2.get_text(strip=True)
                    raw_url = h2.get("href", "")

                    # Unmask Bing tracking redirect /ck/a?!...&u=a1<base64>...
                    final_url = raw_url
                    if "/ck/a?" in raw_url and "u=" in raw_url:
                        try:
                            match = re.search(r"[?&]u=a1([A-Za-z0-9_-]+)", raw_url)
                            if match:
                                b64_str = match.group(1)
                                b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                                decoded = base64.urlsafe_b64decode(b64_str).decode("utf-8", errors="ignore")
                                if decoded.startswith("http"):
                                    final_url = decoded
                        except Exception:
                            pass

                    # Extract snippet
                    caption = li.select_one(".b_caption p, .b_algoSlug, p")
                    snippet = caption.get_text(" ", strip=True) if caption else ""

                    if title and final_url.startswith("http"):
                        results.append({
                            "title": title,
                            "url": final_url,
                            "snippet": snippet[:280]
                        })
                        if len(results) >= max_results:
                            break

        except Exception as ex:
            pass

        # Fallback Engine 2: Wikipedia OpenSearch API if query looks like a specific vulnerability or technology
        if not results:
            try:
                wiki_url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={urllib.parse.quote_plus(query)}&limit={max_results}&format=json"
                w_res = requests.get(wiki_url, headers=headers, timeout=6)
                if w_res.status_code == 200:
                    data = w_res.json()
                    if len(data) >= 4:
                        titles, descriptions, links = data[1], data[2], data[3]
                        for t, d, l in zip(titles, descriptions, links):
                            results.append({"title": t, "url": l, "snippet": d[:280]})
            except Exception:
                pass

        if results:
            return {
                "success": True,
                "query": query,
                "total_results": len(results),
                "results": results
            }
        else:
            return {
                "success": False,
                "query": query,
                "total_results": 0,
                "message": f"No web search results found for '{query}' or search was throttled."
            }

    def scrape_web_page(
        self,
        url: str,
        extract_main_text: bool = True,
        max_length: int = 4000
    ) -> Dict[str, Any]:
        """
        Deeply scrapes and parses a web page, stripping useless scripts and CSS to return clean, structured markdown.

        Args:
            url: The HTTP/HTTPS web page URL to scrape.
            extract_main_text: Whether to filter out navigation/footers and keep primary content.
            max_length: Maximum text length in characters to return (default: 4000).

        Returns:
            Dict containing page title, status, clean text content, and extracted links.
        """
        if not url or not url.startswith("http"):
            return {"success": False, "error": "Invalid URL. Must begin with http:// or https://"}

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            r = requests.get(url, headers=headers, timeout=12, verify=False)
            status_code = r.status_code

            soup = BeautifulSoup(r.text, "html.parser")

            # Extract title
            title = soup.title.get_text(strip=True) if soup.title else "Untitled Page"

            # Remove unwanted tags: scripts, styles, iframes, SVGs, noscripts
            for tag in soup(["script", "style", "noscript", "svg", "iframe", "style"]):
                tag.decompose()

            if extract_main_text:
                for boilerplate in soup(["nav", "footer", "header", "aside"]):
                    boilerplate.decompose()

            # Extract links
            found_links = []
            for a in soup.select("a[href]"):
                link_href = a.get("href", "").strip()
                link_text = a.get_text(strip=True)
                if link_href.startswith("http") and link_text:
                    found_links.append({"text": link_text[:50], "url": link_href})
                if len(found_links) >= 15:
                    break

            # Clean readable text
            text_lines = []
            for el in soup.find_all(["h1", "h2", "h3", "h4", "p", "li", "pre", "code"]):
                t = el.get_text(" ", strip=True)
                if len(t) > 10:
                    tag_name = el.name
                    if tag_name in ("h1", "h2", "h3"):
                        prefix = "#" * int(tag_name[1]) + " "
                        text_lines.append(f"\n{prefix}{t}\n")
                    elif tag_name in ("pre", "code"):
                        text_lines.append(f"```\n{t}\n```")
                    else:
                        text_lines.append(t)

            full_text = "\n".join(text_lines)
            full_text = re.sub(r"\n{3,}", "\n\n", full_text).strip()

            truncated = False
            if len(full_text) > max_length:
                full_text = full_text[:max_length] + "\n... [Content Truncated]"
                truncated = True

            return {
                "success": True,
                "url": url,
                "status_code": status_code,
                "title": title,
                "character_count": len(full_text),
                "is_truncated": truncated,
                "content": full_text or "No readable text content found.",
                "sample_links": found_links[:10]
            }

        except Exception as ex:
            return {"success": False, "url": url, "error": f"Failed to scrape webpage: {str(ex)}"}
