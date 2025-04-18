#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules.utils import requests, BeautifulSoup
from urllib.parse import urljoin, urlparse
from modules.payloads import DEFAULT_PATHS, KNOWN_PATHS

class Recon:
    def fetch_robots_txt(base_url, s):
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            resp = s.get(robots_url, verify=False, allow_redirects=False, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                return ''
        except Exception as e:
            return ''

    def search_sensitive_paths_in_robots(robots_txt):
        sensitive_paths = []
        for line in robots_txt.splitlines():
            if line.lower().startswith("disallow"):
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                path = parts[1].strip()
                if any(keyword in path.lower() for keyword in DEFAULT_PATHS):
                    sensitive_paths.append(path)
        return sensitive_paths

    def fetch_html(base_url, s):
        try:
            resp = s.get(base_url, verify=False, allow_redirects=False, timeout=10)
            if resp.status_code == 200:
                return resp.text
            else:
                return ''
        except Exception as e:
            return ''

    def search_sensitive_links_in_html(html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        findings = set()
        base_domain = urlparse(base_url).netloc.lower()

        for tag in soup.find_all(["a", "script", "link", "form"]):
            attr = tag.get("href") or tag.get("src") or tag.get("action")
            if not attr:
                continue
            full_url = urljoin(base_url, attr)
            parsed_url = urlparse(full_url)
            if parsed_url.netloc.lower() != base_domain:
                continue
            if any(kw in parsed_url.path.lower() for kw in DEFAULT_PATHS):
                findings.add(parsed_url.path)
        return list(findings)

    def check_path_accessibility(base_url, paths, s):
        if not paths:
            return
        for path in paths:
            full_url = urljoin(base_url, path)
            try:
                resp = s.get(full_url, verify=False, allow_redirects=False, timeout=10)
                KNOWN_PATHS.append(path)
            except Exception as e:
                print(f"  [ERR] {full_url} → {e}")

    def bruteforce_common_paths(base_url, s):
        paths_to_test = []

        for keyword in DEFAULT_PATHS:
            for suffix in ['', '/']:
                paths_to_test.append(f"{keyword}{suffix}")

        for path in paths_to_test:
            full_url = urljoin(base_url, path)
            try:
                resp = requests.get(full_url, verify=False, allow_redirects=False, timeout=10)
                if resp.status_code in [200, 301, 302, 403]:
                    KNOWN_PATHS.append(path)
            except Exception as e:
                print(f"  [ERR] {full_url} → {e}")