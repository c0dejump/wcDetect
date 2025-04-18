#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules.utils import requests, BeautifulSoup, random, string
from urllib.parse import urljoin, urlparse
from modules.payloads import DEFAULT_PATHS, KNOWN_PATHS, extensions
from modules.compare import get_visible_text, compare_words

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
    if custom_headers:
        req_verify = requests.get(upe, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0"}, verify=False, allow_redirects=False, timeout=10)
        if req_verify.status_code == req_ext.status_code and len(req_verify.content) != len(req_base.content):
            words1 = get_visible_text(req_verify)
            words2 = get_visible_text(req_path)
            similarity = compare_words(words1, words2)

            if similarity > 30 and not keyword:
                print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | Cache Deception | CACHETAG: {cache_status} | [{req_ext.status_code}] | {similarity:.2f}% | \033[34m{upe}\033[0m")
            elif keyword:
                if keyword in req_verify.text:
                    print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | Cache Deception | CACHETAG: {cache_status} | Keyword [{keyword}] present | \033[34m{upe}\033[0m")
            else:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | [{req_path.status_code}] > [{req_ext.status_code}] | {similarity:.2f}% | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
    else:
        if req_ext.status_code != req_path.status_code and req_ext.status_code not in [410, 404, 403, 308]:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | HL: {len(req_path.headers)}b > {len(req_ext.headers)}b | [{req_path.status_code}] > [{req_ext.status_code}] | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
    """
    elif len(req_ext.headers) != len(req_path.headers) and req_ext.status_code not in [410, 404, 403, 308]:
        print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | Cache Deception | HL: {len(req_path.headers)}b > {len(req_ext.headers)}b | CACHETAG: {cache_status} | \033[34m{upe}\033[0m")
    """


def wcd_formatting(s, url_p, req_base, custom_headers, keyword):
    req_path = s.get(url_p, verify=False, allow_redirects=False, timeout=10)
    #print(req_path)
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
                    #print(upe)
                    wcd_check(s, upe, req_path, req_base, custom_headers, keyword)


def wcd_base(url, s, custom_headers, keyword):
    req_base = s.get(url, verify=False, allow_redirects=False, timeout=10)
    if KNOWN_PATHS:
        for np in KNOWN_PATHS:
            np = np if np[0] != "/" else np[1:]
            url_p = f"{url}{np}"
            wcd_formatting(s, url_p, req_base, custom_headers, keyword)
    if not known_path:
        for dp in DEFAULT_PATHS:
            url_p = f"{url}{dp}"
            wcd_formatting(s, url_p, req_base, custom_headers, keyword)   