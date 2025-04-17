#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random, string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import argparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


extensions = ['.css', '.js', '.jpg', '.png', '.svg', '.gif', '.html', '.txt', '.pdf', '.xml', '.json', '%20.css', '..css', '~.css', '%00.css']
DEFAULT_PATHS = ['account', 'profile', 'dashboard', 'settings', 'user', 'admin', 'private', 'my-account', 'user/profile', 'dashboard/image', 'dashboard/profile', 'account/user', 'address']
KNOWN_PATHS = []

HEADERS = {"User-Agent": "xxxxxx"}


def args():
    """
    Parses command-line arguments and returns them.

    This function uses argparse to define and parse command-line arguments for the script.
    It includes options for specifying a URL, a file of URLs, custom HTTP headers, user agents,
    authentication, verbosity, logging, and threading.

    Returns:
        argparse.Namespace: Parsed command-line arguments.

    Arguments:
        -u, --url (str): URL to test [required].
        -f, --file (str): File of URLs.
        -H, --header (str): Add a custom HTTP Header.
    """
    parser = argparse.ArgumentParser()
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
        "-p", "--path", dest="known_path", help="If you know the path", required=False
    )
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


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

def check_cache_presence(req_ext):
    #print(req_ext.headers)
    hit_tag = False
    for rh in req_ext.headers:
        if "age" in rh.lower() or "hit" in req_ext.headers[rh].lower():
            hit_tag = True
        else:
            pass
    return hit_tag


def wcd_check(upe, req_path, req_base):
    for _ in range(3):
        req_ext = s.get(upe, verify=False, allow_redirects=False, timeout=10)
    cache_status = check_cache_presence(req_ext)
    if custom_headers:
        req_verify = requests.get(upe, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0"}, verify=False, allow_redirects=False, timeout=10)
        if len(req_verify.content) == len(req_ext.content) and req_verify.status_code == req_ext.status_code and len(req_verify.content) != len(req_base.content):
            print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | Cache Deception | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
    else:
        if req_ext.status_code != req_path.status_code and req_ext.status_code not in [410, 404, 403, 308]:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | HL: {len(req_path.headers)}b > {len(req_ext.headers)}b | [{req_path.status_code}] > [{req_ext.status_code}] | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
    """
    elif len(req_ext.headers) != len(req_path.headers) and req_ext.status_code not in [410, 404, 403, 308]:
        print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | HL: {len(req_path.headers)}b > {len(req_ext.headers)}b | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
    """


def wcd_making(s, url_p, req_base):
    req_path = s.get(url_p, verify=False, allow_redirects=False, timeout=10)
    if req_path.status_code not in [410, 404, 308]:
        if req_path.status_code == 403 and req_base.status_code == 403:
            pass
        else:
            for e in extensions:
                buster = ''.join(random.choices(string.ascii_letters, k=random.randint(8, 10)))
                url_p_e = [
                f"{url_p}{e}/", #Ex: toto.com/profile.css/
                f"{url_p}{e}", #Ex: toto.com/profile.css
                f"{url_p}/{buster}{e}", #Ex: toto.com/profile/azdefr.css
                f"{url_p}?{buster}{e}", #Ex: toto.com/profile?azdefr.css
                f"{url_p};{buster}{e}", #Ex: toto.com/profile;azdefr.css
                f"{url_p}?format={e}", #Ex: toto.com/profile?format=pdf
                ]
                for upe in url_p_e:
                    wcd_check(upe, req_path, req_base)

def wcd_base(url, s):
    req_base = s.get(url, verify=False, allow_redirects=False, timeout=10)
    if KNOWN_PATHS:
        for np in KNOWN_PATHS:
            np = np if np[0] != "/" else np[1:]
            url_p = f"{url}{np}"
            wcd_making(s, url_p, req_base)
    for dp in DEFAULT_PATHS:
        url_p = f"{url}{dp}"
        wcd_making(s, url_p, req_base)         

def recon_modules(base_url, s):
    robots = fetch_robots_txt(base_url, s)
    found_paths = search_sensitive_paths_in_robots(robots)
    html = fetch_html(base_url, s)

    found_links = []
    if html:
        found_links = search_sensitive_links_in_html(html, base_url)

    check_path_accessibility(base_url, found_paths, s)
    check_path_accessibility(base_url, found_links, s)
    bruteforce_common_paths(base_url, s)

def parse_headers(header_list):
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


if __name__ == '__main__':
    results = args()

    url = results.url
    url_file = results.url_file
    custom_headers = results.custom_headers
    known_path = results.known_path

    s = requests.Session()
    s.headers.update({"User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    if custom_headers:
        custom_headers = parse_headers(custom_headers)
        s.headers.update(custom_headers)
    if known_path:
        KNOWN_PATHS = known_path

    if not url_file:
        parsed_url = urlparse(url)
        try:
            if not known_path:
                recon_modules(url, s)
            wcd_base(url, s)
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            print(f"Error : {e}")
            pass
    elif url_file:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            try:
                if not known_path:
                    recon_modules(url, s)
                wcd_base(url, s)
                print(f" {url}", end='\r')
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except Exception as e:
                print(f"Error : {e}")
                pass
