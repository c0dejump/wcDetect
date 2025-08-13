#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
from urllib.parse import urljoin, urlparse
import argparse
import traceback

from modules.payloads import DEFAULT_PATHS, KNOWN_PATHS
from static.banner import print_banner

from modules.recon import Recon
from modules.wcd import wcd_base


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


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
        -p, --path (str): If you know the path, Ex: -p my-account
        -k --keyword (str): If a keyword must be present in the poisoned response
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
        "-p", "--path", dest="known_path", help="If you know the path, Ex: -p my-account", required=False
    )
    parser.add_argument(
        "-k", "--keyword", dest="keyword", help="If a keyword must be present in the poisoned response, Ex: -k codejump", required=False
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
    #print(KNOWN_PATHS)


def parse_headers(header_list):
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def process_modules(url, s, custom_headers, keyword):
    url_p = f"{url}{known_path}" if known_path else url
    #print(s.headers)
    req_main = s.get(url_p, verify=False, allow_redirects=False, timeout=10)

    print("\033[34m⟙\033[0m")
    print(f" URL: {url}")
    print(f" Path: {known_path}")
    if keyword:
        print(f" Keyword: {keyword} ({"\033[32mFound on page\033[0m" if keyword in req_main.text else "\033[33mNot found on page\033[0m"})")
    else:
        print(f" Keyword: {keyword}")
    print(f" URL response: {req_main.status_code}")
    print(f" URL response size: {len(req_main.content)} bytes")
    print("\033[34m⟘\033[0m")

    if not known_path:
        print("\033[36m ├ Recon\033[0m")
        recon_modules(url, s)
    print("\n\033[36m ├ WCD Check\033[0m")
    wcd_base(url, s, custom_headers, keyword)
    print("\n======= Scan finish =======\n")

if __name__ == '__main__':
    results = args()

    url = results.url
    url_file = results.url_file
    custom_headers = results.custom_headers
    known_path = results.known_path
    keyword = results.keyword

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"})

    #delete "Accept" header
    #s.headers.pop("Accept", None)
    #original_send = s.send
    #def send_without_accept(request, **kwargs):
        #request.headers.pop("Accept", None)
        #return original_send(request, **kwargs)
    #s.send = send_without_accept

    if custom_headers:
        custom_headers = parse_headers(custom_headers)
        s.headers.update(custom_headers)
    if known_path:
        KNOWN_PATHS.append(known_path)

    if not url_file:
        parsed_url = urlparse(url)
        try:
            process_modules(url, s, custom_headers, keyword)
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            #traceback.print_exc()
            print(f"Error : {e}")
            pass
    elif url_file:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            try:
                process_modules(url, s, custom_headers, keyword)
                print(f" {url}", end='\r')
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except Exception as e:
                #traceback.print_exc()
                print(f"Error : {e}")
                pass
