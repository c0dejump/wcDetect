#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules.utils import BeautifulSoup, re

def get_visible_text(req):
    soup = BeautifulSoup(req.text, 'html.parser')
    text = soup.get_text(separator=' ')
    words = re.findall(r'\b\w+\b', text.lower())
    return set(words)


def compare_words(set1, set2):
    if not set1 or not set2:
        return 0.0

    common = set1 & set2
    total = set1 | set2

    similarity = (len(common) / len(total)) * 100
    return similarity