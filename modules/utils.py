#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlparse

import random
import string
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# import os
import traceback
import pprint
import re
import time
import sys

import requests
# Local imports
#from static.vuln_notify import vuln_found_notify

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = ""

class Colors:
    """Colors constants for the output messages"""

    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    RESET = "\033[0m"

class Identify:
    behavior = "\033[33m└── [INTERESTING BEHAVIOR]\033[0m"
    confirmed = "\033[31m└── [VULNERABILITY CONFIRMED]\033[0m"



def human_time(human: str) -> None:
    if human.isdigit():
        time.sleep(int(human))
    elif human.lower() == "r" or human.lower() == "random":
        time.sleep(random.randrange(6))  # nosec B311
    else:
        pass


def check_cache_presence(req_ext):
    #print(req_ext.headers)
    hit_tag = False
    for rh in req_ext.headers:
        if "age" in rh.lower() or "hit" in req_ext.headers[rh].lower():
            hit_tag = True
        else:
            pass
    return hit_tag


def random_ua():
    user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6)",
            "curl/7.68.0",
            "PostmanRuntime/7.28.4",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/116.0.1938.62",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Mobile Safari/537.36",
            "Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko) Version/4.0 Safari/537.73",
            "Mozilla/5.0 (Nintendo Switch; WebKit) AppleWebKit/601.5 (KHTML, like Gecko) Version/11.0",
            "Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) OPR/82.0.4227.33",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36 OPR/82.0.4227.33",
            "Mozilla/5.0 (Linux; Android 9; SM-A520F Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
            "Mozilla/5.0 (Linux; U; Android 4.4; en-us; Nexus 5 Build/KRT16M) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
            "Mozilla/5.0 (BlackBerry; U; BlackBerry 10.0; en-US) AppleWebKit/537.35+ (KHTML, like Gecko) Version/10.0.9.1675 Mobile Safari/537.35+",
            "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (X11; Linux i686; rv:78.0) Gecko/20100101 Firefox/78.0",
        ]
    if DEFAULT_UA == "random":
        _user_agent = {"User-Agent": random.choice(user_agents)}
    else:
        _user_agent = {"User-Agent": DEFAULT_UA}
    return(_user_agent)