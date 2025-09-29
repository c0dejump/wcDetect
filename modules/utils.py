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
