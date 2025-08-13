#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules.utils import requests, BeautifulSoup, random, string
from urllib.parse import urljoin, urlparse
from modules.payloads import DEFAULT_PATHS, KNOWN_PATHS, extensions, delimiters
from modules.compare import get_visible_text, compare_words
import traceback

def check_cache_presence(req_ext):
    #print(req_ext.headers)
    hit_tag = False
    for rh in req_ext.headers:
        if "age" in rh.lower() or "hit" in req_ext.headers[rh].lower():
            hit_tag = True
        else:
            pass
    return hit_tag

def wcd_check(s, upe, req_path, req_base, custom_headers, keyword):
    for _ in range(3):
        req_ext = s.get(upe, verify=False, allow_redirects=False, timeout=10)
    cache_status = check_cache_presence(req_ext)
    try:
        if custom_headers:
            req_verify = requests.get(upe, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0"}, verify=False, allow_redirects=False, timeout=10)
            #if req_verify.status_code == 429: 
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
    except:
        pass
        #traceback.print_exc()


def path_traversal_confusion(s, url, kp, req_base, req_path, custom_headers, keyword):
    url_ptc = [
        f"{url}%2F..%2F{kp}?cb={random.randint(1, 100)}",
        f"{url}%2F..%2F/{kp}?cb={random.randint(1, 100)}",
        f"{url}%2F../{kp}?cb={random.randint(1, 100)}",
        ]
    for ptc in url_ptc:
        wcd_check(s, ptc, req_path, req_base, custom_headers, keyword)
        print(f" {ptc}", end='\r')
        

def wcd_formatting(s, url_p, req_base, req_path, custom_headers, keyword):
    try:
        for e in extensions:
            url_p_e = [
            f"{url_p}{e}/", #Ex: toto.com/profile.css/
            f"{url_p}{e}", #Ex: toto.com/profile.css
            f"{url_p}?format={e}", #Ex: toto.com/profile?format=pdf
            ]
            for upe in url_p_e:
                wcd_check(s, upe, req_path, req_base, custom_headers, keyword)
                print(f" {upe}", end='\r')
            for d in delimiters:
                buster = ''.join(random.choices(string.ascii_letters, k=random.randint(8, 10)))
                upe = f"{url_p}{d}{buster}{e}" #Ex: toto.com/profile;dzede.css
                wcd_check(s, upe, req_path, req_base, custom_headers, keyword)
                print(f" {upe}", end='\r')
    except:
        print(f"{req_path}{url_p}") 
        #traceback.print_exc()


def wcd_base(url, s, custom_headers, keyword):
    req_base = s.get(url, verify=False, allow_redirects=False, timeout=10)
    if KNOWN_PATHS:
        for kp in KNOWN_PATHS:
            kp = kp if kp[0] != "/" else kp[1:]
            url_p = f"{url}{kp}"
            req_path = s.get(url_p, verify=False, allow_redirects=False, timeout=10)
            #print(req_path)
            if req_path.status_code not in [410, 404, 308]:
                if req_path.status_code == 403 and req_base.status_code == 403:
                    pass
                else:
                    path_traversal_confusion(s, url, kp, req_base, req_path, custom_headers, keyword)
                    wcd_formatting(s, url_p, req_base, req_path, custom_headers, keyword)
    else:
        for dp in DEFAULT_PATHS:
            url_p = f"{url}{dp}"
            wcd_formatting(s, url_p, req_base, custom_headers, keyword)   