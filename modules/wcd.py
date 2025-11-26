#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules.utils import requests, BeautifulSoup, random, string, human_time, time, sys, check_cache_presence
from urllib.parse import urljoin, urlparse
from modules.payloads import DEFAULT_PATHS, KNOWN_PATHS, extensions, delimiters
from modules.compare import get_visible_text, compare_words
import traceback

BLOCK_COUNT = 0

def waf_verify(req_verify, s, url, upe):
    global BLOCK_COUNT
    if req_verify.status_code == 429:
        print(f"[I] 429 You appear to have been blocked by a WAF with {upe} url.")
        continue_scan = input("wait 1min & continue ? [y:n]")
        if continue_scan == "y" or continue_scan == "Y":
            time.sleep(60)
            BLOCK_COUNT = 0
        else:
            sys.exit()
    if req_verify.status_code == 403:
        req_403_test = s.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"}, verify=False, allow_redirects=False, timeout=10)
        if BLOCK_COUNT > 3 and req_403_test.status_code == 403:
            print(f"[I] 403 You appear to have been blocked by a WAF with {upe} url.")
            continue_scan = input("wait 1min & continue ? [y:n]")
            if continue_scan == "y" or continue_scan == "Y":
                time.sleep(60)
                BLOCK_COUNT = 0
            else:
                sys.exit()
        else:
            BLOCK_COUNT += 1


def wcd_check(s, url, upe, req_path, req_base, custom_headers, keyword, human):
    for _ in range(3):
        req_ext = s.get(upe, verify=False, allow_redirects=False, timeout=10)
        human_time(human)
    cache_status = check_cache_presence(req_ext)
    try:
        if custom_headers:
            req_verify = requests.get(upe, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"}, verify=False, allow_redirects=False, timeout=10)
            waf_verify(req_verify, s, url, upe)

            if req_verify.status_code == req_ext.status_code and len(req_verify.content) != len(req_base.content):
                words1 = get_visible_text(req_verify)
                words2 = get_visible_text(req_path)
                similarity = compare_words(words1, words2)

                if similarity > 50 and not keyword:
                    print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | Cache Deception | CACHETAG: {cache_status} | [{req_ext.status_code}] | {similarity:.2f}% | \033[34m{upe}\033[0m")
                elif keyword:
                    if keyword in req_verify.text:
                        print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | Cache Deception | CACHETAG: {cache_status} | Keyword [{keyword}] present | \033[34m{upe}\033[0m")
                elif 20 <= similarity <= 50 :
                    print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | [{req_path.status_code}] > [{req_ext.status_code}] | {similarity:.2f}% | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
        else:
            if req_ext.status_code != req_path.status_code and req_ext.status_code not in [410, 404, 403, 308]:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | HL: {len(req_path.headers)}b > {len(req_ext.headers)}b | [{req_path.status_code}] > [{req_ext.status_code}] | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
        """
        elif len(req_ext.headers) != len(req_path.headers) and req_ext.status_code not in [410, 404, 403, 308]:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | HL: {len(req_path.headers)}b > {len(req_ext.headers)}b | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
        """
    except requests.ConnectionError:
        print("\nError, cannot connect to target")
        waiting = input("Wait 5scd and retry ? [y:n]")
        if waiting != "n" and waiting != "N":
            time.sleep(5)
            try:
                req_retest = requests.get(upe, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"}, verify=False, allow_redirects=False, timeout=10)
                pass
            except:
                sys.exit()
        else:
            sys.exit()
    except Exception as e:
        print(f"Error : {e}")
        pass


def path_traversal_confusion(s, url, kp, req_base, req_path, custom_headers, keyword, human):
    url_ptc = [
        f"{url}%2F..%2F{kp}?cb={random.randint(1, 100)}",
        f"{url}%2F..%2F/{kp}?cb={random.randint(1, 100)}",
        f"{url}%2F../{kp}?cb={random.randint(1, 100)}",
        f"{url}%2F../../static/{kp}?cb={random.randint(1, 100)}",
        f"{url}%2F%252e%252e%252f{kp}?cb={random.randint(1, 100)}",
        ]
    for ptc in url_ptc:
        wcd_check(s, url, ptc, req_path, req_base, custom_headers, keyword, human)
        print(f" {ptc}", end='\r')


def tracking_param(s, url, url_p, req_base, req_path, custom_headers, keyword, human):
    url_tp = [
    f"{url_p}?utm_source=abc",
    f"{url_p}?utm_medium=abc",
    f"{url_p}?utm_campaign=abc",
    f"{url_p}?utm_term=abc",
    f"{url_p}?utm_content=abc",
    f"{url_p}?utm_id=abc",
    f"{url_p}?utm_source_platform=abc",
    f"{url_p}?utm_creative_format=abc",
    f"{url_p}?utm_marketing_tactic=abc",
    f"{url_p}?gclid=abc",
    f"{url_p}?gclsrc=abc",
    f"{url_p}?dclid=abc",
    f"{url_p}?gbraid=abc",
    f"{url_p}?wbraid=abc",
    f"{url_p}?msclkid=abc",
    f"{url_p}?ref=abc",
    f"{url_p}?referrer=abc",
    f"{url_p}?source=abc",
    f"{url_p}?campaign=abc",
    f"{url_p}?_ga=abc",
    f"{url_p}?_gl=abc",
    f"{url_p}?aff_id=abc",
    f"{url_p}?affiliate_id=abc",
    f"{url_p}?click_id=abc",
    f"{url_p}?clickid=abc",
    f"{url_p}?transaction_id=abc",
    f"{url_p}?from=abc",
    f"{url_p}?v=1.2.3",
    ]
    for ut in url_tp:
        wcd_check(s, url, ut, req_path, req_base, custom_headers, keyword, human)
        print(f" {ut}", end='\r')
        

def wcd_formatting(s, url_p, req_base, req_path, custom_headers, keyword, human):
    try:
        for e in extensions:
            url_p_e = [
            f"{url_p}{e}/", #Ex: toto.com/profile.css/
            f"{url_p}{e}", #Ex: toto.com/profile.css
            f"{url_p}?format={e}", #Ex: toto.com/profile?format=pdf
            f"{url_p}?type={e}",
            f"{url_p}?callback={e}",
            f"{url_p}?a={e}&a=1",
            ]
            for upe in url_p_e:
                wcd_check(s, url_p, upe, req_path, req_base, custom_headers, keyword, human)
                print(f" {upe}", end='\r')
            for d in delimiters:
                buster = ''.join(random.choices(string.ascii_letters, k=random.randint(8, 10)))
                upe = f"{url_p}{d}{buster}{e}" #Ex: toto.com/profile;dzede.css
                wcd_check(s, url_p, upe, req_path, req_base, custom_headers, keyword, human)
                print(f" {upe}", end='\r')
    except requests.ConnectionError:
        print("Error, cannot connect to target")
    except Exception as e:
        print(f"Error : {e}")
        pass


def wcd_base(url, s, custom_headers, keyword, human):
    req_base = s.get(url, verify=False, allow_redirects=False, timeout=10)
    if KNOWN_PATHS:
        for kp in KNOWN_PATHS:
            kp = kp if kp[0] != "/" else kp[1:]
            url_p = f"{url}{kp}"
            req_path = s.get(url_p, verify=False, allow_redirects=False, timeout=10)
            #print(req_path)
            if req_path.status_code not in [410, 404, 308, 429]:
                if req_path.status_code == 429:
                    print("[I] 429 You appear to have been blocked by a WAF.")
                if req_path.status_code == 403 and req_base.status_code == 403:
                    pass
                else:
                    path_traversal_confusion(s, url, kp, req_base, req_path, custom_headers, keyword, human)
                    tracking_param(s, url, url_p, req_base, req_path, custom_headers, keyword, human)
                    wcd_formatting(s, url_p, req_base, req_path, custom_headers, keyword, human)
    else:
        for dp in DEFAULT_PATHS:
            url_p = f"{url}{dp}"
            wcd_formatting(s, url_p, req_base, custom_headers, keyword, human)