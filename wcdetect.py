#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import json
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import traceback

from modules.payloads import DEFAULT_PATHS, KNOWN_PATHS
from static.banner import print_banner

from modules.recon import Recon
from modules.wcd import wcd_base
from modules.crawler import Crawler

import modules.utils


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def args():
    """
    Parses command-line arguments and returns them.

    Arguments:
        -u, --url (str):     URL to test [required].
        -f, --file (str):    File of URLs.
        -H, --header (str):  Add a custom HTTP Header.
        -p, --path (str):    If you know the path, Ex: -p my-account
        -k, --keyword (str): If a keyword must be present in the poisoned response
        -c, --crawl:         Auto-crawl mode — discover all pages then run WCD tests.
                             Combined with -k, only pages containing the keyword are tested.
        --max-pages (int):   Max pages to crawl in auto-crawl mode (default: 100)
    """
    parser = argparse.ArgumentParser(description=print_banner())
    parser.add_argument(
        "-u", "--url", dest="url", help="URL to test \033[31m[required]\033[0m"
    )
    parser.add_argument(
        "-f", "--file", dest="url_file", help="File of URLs", required=False
    )
    parser.add_argument(
        "-H",
        "--header",
        dest="custom_headers",
        help="Add a custom HTTP Header",
        action="append",
        required=False,
    )
    parser.add_argument(
        "-p", "--path", dest="known_path",
        help="If you know the path, Ex: -p my-account", required=False
    )
    parser.add_argument(
        "-k", "--keyword", dest="keyword",
        help="If a keyword must be present in the poisoned response, Ex: -k codejump",
        required=False
    )
    parser.add_argument(
        "-c", "--crawl", dest="crawl",
        help=(
            "Auto-crawl mode: discover all pages of the site then run WCD tests on each. "
            "When combined with -k, only pages where the keyword is found (body or header) are tested."
        ),
        action="store_true",
        default=False,
        required=False,
    )
    parser.add_argument(
        "--max-pages", dest="max_pages",
        help="Maximum number of pages to crawl in auto-crawl mode (default: 100)",
        type=int,
        default=100,
        required=False,
    )
    parser.add_argument(
        "-d", "--data", dest="post_data",
        help=(
            "Send POST requests with this body (simulates victim fetching personal data). "
            "Supports JSON ('{\"key\":\"val\"}') or form-encoded ('key=val&key2=val2'). "
            "The verify request stays GET so cached responses are detectable."
        ),
        required=False,
        default=None,
    )
    parser.add_argument(
        "-hu",
        "--human",
        dest="human",
        help="Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'",
        default="0",
        required=False,
    )
    parser.add_argument(
        "-ua", "--ua", dest="ua_force",
        help="If need a specific user-agent (Default: random)", default="random"
    )
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def recon_modules(base_url, s):
    robots = Recon.fetch_robots_txt(base_url, s)
    found_paths = Recon.search_sensitive_paths_in_robots(robots)
    html = Recon.fetch_html(base_url, s)

    found_links = []
    if html:
        found_links = Recon.search_sensitive_links_in_html(html, base_url)

    Recon.check_path_accessibility(base_url, found_paths, s)
    Recon.check_path_accessibility(base_url, found_links, s)
    Recon.bruteforce_common_paths(base_url, s)


def parse_post_data(data_str):
    """Parse -d argument into kwargs for requests.post().
    Returns dict with 'json' or 'data' key, or None if no data."""
    if not data_str:
        return None
    stripped = data_str.strip()
    if stripped.startswith('{') or stripped.startswith('['):
        return {'json': json.loads(stripped)}
    parsed = parse_qs(stripped, keep_blank_values=True)
    return {'data': {k: v[0] for k, v in parsed.items()}}


def parse_headers(header_list):
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def process_modules(url, s, custom_headers, keyword, post_data=None):
    url_p = f"{url}{known_path}" if known_path else url
    if post_data is not None:
        req_main = s.post(url_p, verify=False, allow_redirects=False, timeout=20, **post_data)
    else:
        req_main = s.get(url_p, verify=False, allow_redirects=False, timeout=20)

    print("\033[34m⟙\033[0m")
    print(f" URL: {url}")
    print(f" Path: {known_path}")
    if keyword:
        headers_str = str(req_main.headers).lower()
        if keyword.lower() in req_main.text.lower():
            print(f" Keyword: {keyword} (\033[32mFound on page\033[0m)")
        elif keyword.lower() in headers_str:
            print(f" Keyword: {keyword} (\033[32mFound on header\033[0m)")
        else:
            print(f" Keyword: {keyword} (\033[33mNot found on page or header\033[0m)")
    else:
        print(f" Keyword: {keyword}")
    print(f" URL response: {req_main.status_code}")
    print(f" URL response size: {len(req_main.content)} bytes")
    print("\033[34m⟘\033[0m")

    if not known_path:
        print("\033[36m ├ Recon\033[0m")
        recon_modules(url, s)
        print(" └── paths found:")
        for kp in KNOWN_PATHS:
            print(f"    └─ {kp}")

    if post_data is not None:
        print(f" Method: POST")
    print("\n\033[36m ├ WCD Check\033[0m")
    wcd_base(url, s, custom_headers, keyword, human, post_data)
    print("\n======= Scan finish =======\n")


def process_crawl_mode(base_url, s, custom_headers, keyword, max_pages, post_data=None):
    """
    Auto-crawl mode:
      1. Crawl the target site to discover all pages (BFS, same domain).
      2. If -k is set, keep only pages where the keyword was found (body or header).
         Otherwise test every crawled page.
      3. For each selected page, run the full WCD test workflow.
    """
    crawler = Crawler(
        base_url=base_url,
        session=s,
        keyword=keyword,
        max_pages=max_pages,
        delay=0.0,
        verbose=True,
    )
    pages_to_test = crawler.crawl()   # list of (url, kw_location)

    if not pages_to_test:
        if keyword:
            print(f"\n\033[33m[!] No page found containing keyword \"{keyword}\". Nothing to test.\033[0m")
        else:
            print("\n\033[33m[!] No pages were discovered. Nothing to test.\033[0m")
        return

    print(f"\n\033[36m ├ WCD Tests\033[0m — running on {len(pages_to_test)} page(s)\n")

    for idx, (page_url, kw_location) in enumerate(pages_to_test, 1):
        parsed_page = urlparse(page_url)
        rel_path = parsed_page.path
        if parsed_page.query:
            rel_path += "?" + parsed_page.query

        print("\033[34m⟙\033[0m")
        print(f" [{idx}/{len(pages_to_test)}] URL: {page_url}")
        if keyword and kw_location:
            loc_label = "\033[32mBody\033[0m" if kw_location == "body" else "\033[32mHeader\033[0m"
            print(f" Keyword: {keyword} (Found in {loc_label})")
        elif keyword:
            print(f" Keyword: {keyword} (\033[33mNot confirmed on this page\033[0m)")
        print("\033[34m⟘\033[0m")

        # Rebuild KNOWN_PATHS for this specific page only
        KNOWN_PATHS.clear()
        path_for_wcd = rel_path.lstrip("/")
        if path_for_wcd:
            KNOWN_PATHS.append(path_for_wcd)

        print(f"\033[36m ├ WCD Check\033[0m — {page_url}")
        try:
            wcd_base(base_url, s, custom_headers, keyword, human, post_data)
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            sys.exit()
        except Exception as e:
            print(f" [ERR] {e}")

        print()

    print("======= Crawl scan finished =======\n")


if __name__ == '__main__':
    results = args()

    url = results.url
    url_file = results.url_file
    custom_headers = results.custom_headers
    known_path = results.known_path
    keyword = results.keyword
    crawl_mode = results.crawl
    max_pages = results.max_pages
    human = results.human
    ua_force = results.ua_force
    post_data = parse_post_data(results.post_data)

    modules.utils.DEFAULT_UA = ua_force

    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/146.0.0.0 Safari/537.36"
    })

    if custom_headers:
        custom_headers = parse_headers(custom_headers)
        s.headers.update(custom_headers)
    if known_path:
        KNOWN_PATHS.append(known_path)

    # ------------------------------------------------------------------ #
    #  Routing: crawl mode vs. standard mode                              #
    # ------------------------------------------------------------------ #
    if crawl_mode:
        # Auto-crawl: discover pages, locate keyword, run WCD on each hit
        if not url:
            print("\033[31m[!] -c/--crawl requires -u/--url\033[0m")
            sys.exit(1)
        try:
            process_crawl_mode(url, s, custom_headers, keyword, max_pages, post_data)
        except KeyboardInterrupt:
            print("\nExiting")
            sys.exit()
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

    elif not url_file:
        # Standard single-URL mode (unchanged)
        parsed_url = urlparse(url)
        try:
            process_modules(url, s, custom_headers, keyword, post_data)
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            print(f"Error : {e}")
            pass

    else:
        # File of URLs mode (unchanged)
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            try:
                process_modules(url, s, custom_headers, keyword, post_data)
                print(f" {url}", end='\r')
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except Exception as e:
                print(f"Error : {e}")
                pass