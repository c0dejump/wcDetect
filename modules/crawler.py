#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules.utils import requests, BeautifulSoup, time, sys, Colors, random_ua
from urllib.parse import urljoin, urlparse
from collections import deque
import re


class Crawler:
    """
    Autonomous crawler that discovers pages on the target domain,
    checks keyword presence (body/header), and returns pages to test.
    """

    def __init__(self, base_url: str, session: requests.Session, keyword: str = None,
                 max_pages: int = 100, delay: float = 0.0, verbose: bool = True):
        self.base_url = base_url
        self.session = session
        self.keyword = keyword
        self.max_pages = max_pages
        self.delay = delay
        self.verbose = verbose

        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc.lower()
        self.base_scheme = parsed.scheme

        self.visited: set = set()
        self.queue: deque = deque()
        self.pages_with_keyword: list = []   # (url, location) → location: 'body' | 'header' | None
        self.all_pages: list = []            # all crawled (url, status_code)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc.lower() == self.base_domain

    def _is_crawlable(self, url: str) -> bool:
        """Ignore static assets, anchors, mailto, javascript:, etc."""
        skip_exts = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
            ".webm", ".ogg", ".wav", ".pdf", ".zip", ".tar", ".gz", ".rar",
            ".exe", ".bin", ".dll", ".dmg", ".pkg",
        )
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        path_lower = parsed.path.lower().split("?")[0]
        if any(path_lower.endswith(ext) for ext in skip_exts):
            return False
        return True

    def _normalize(self, url: str) -> str:
        """Strip fragment and trailing slash for deduplication."""
        parsed = urlparse(url)
        # drop fragment
        normalized = parsed._replace(fragment="").geturl()
        # strip trailing slash (but not root)
        if normalized.endswith("/") and len(parsed.path) > 1:
            normalized = normalized.rstrip("/")
        return normalized

    def _extract_links(self, html: str, page_url: str) -> list:
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for tag in soup.find_all(["a", "link", "form"]):
            attr = tag.get("href") or tag.get("action")
            if not attr:
                continue
            full = urljoin(page_url, attr)
            norm = self._normalize(full)
            if self._is_same_domain(norm) and self._is_crawlable(norm):
                links.add(norm)
        return list(links)

    def _check_keyword(self, response: requests.Response) -> str | None:
        """Return 'body', 'header', or None depending on keyword location."""
        if not self.keyword:
            return None
        kw = self.keyword.lower()
        if kw in response.text.lower():
            return "body"
        if kw in str(response.headers).lower():
            return "header"
        return None

    def _fetch(self, url: str):
        try:
            self.session.headers.update(random_ua())
            resp = self.session.get(
                url, verify=False, allow_redirects=True,
                timeout=15, stream=False
            )
            if self.delay > 0:
                time.sleep(self.delay)
            return resp
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> list:
        """
        BFS crawl starting from base_url.
        Returns list of tuples: (url, keyword_location)
          keyword_location: 'body' | 'header' | None
        """
        start = self._normalize(self.base_url)
        self.queue.append(start)
        self.visited.add(start)

        print(f"\n{Colors.CYAN} ├ Auto-Crawl{Colors.RESET} — target: {self.base_url}")
        if self.keyword:
            print(f"   Keyword to locate: \"{self.keyword}\"")
        print(f"   Max pages: {self.max_pages}\n")

        page_count = 0

        while self.queue and page_count < self.max_pages:
            url = self.queue.popleft()
            page_count += 1

            resp = self._fetch(url)
            if resp is None:
                continue

            status = resp.status_code
            content_type = resp.headers.get("Content-Type", "")

            # Only follow HTML pages
            is_html = "html" in content_type.lower()

            # Keyword check
            kw_location = self._check_keyword(resp) if resp else None

            self.all_pages.append((url, status))

            if self.verbose:
                kw_info = ""
                if self.keyword and kw_location:
                    kw_info = f"  {Colors.GREEN}[KW:{kw_location.upper()}]{Colors.RESET}"
                elif self.keyword:
                    kw_info = f"  {Colors.YELLOW}[no kw]{Colors.RESET}"
                print(f"   [{page_count:>3}] [{status}]{kw_info}  {url}", end="\r")

            if self.keyword and kw_location:
                self.pages_with_keyword.append((url, kw_location))
                # Always print keyword hits on their own line
                print(
                    f"   [{page_count:>3}] [{status}]  "
                    f"{Colors.GREEN}[KW:{kw_location.upper()}]{Colors.RESET}  {url}          "
                )

            # Enqueue child links only from HTML pages
            if is_html and status == 200:
                for link in self._extract_links(resp.text, url):
                    if link not in self.visited:
                        self.visited.add(link)
                        self.queue.append(link)

        # Clear the \r line
        print(" " * 120, end="\r")

        total = len(self.all_pages)
        hits = len(self.pages_with_keyword)
        print(f"\n   Crawl done — {total} page(s) visited", end="")
        if self.keyword:
            print(f", {Colors.GREEN}{hits} page(s){Colors.RESET} with keyword \"{self.keyword}\"")
        else:
            print(f" (no keyword filter — all pages will be tested)")

        return self.pages_with_keyword if self.keyword else [(url, None) for url, _ in self.all_pages]