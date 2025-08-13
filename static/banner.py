#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Prints a colorful ASCII art banner along with a brief description of the HExHTTP tool.
"""

try:
    from _version import __version__
except ImportError:
    __version__ = "v1.0"



def print_banner() -> None:
    banner_text = """
  / \\ / \\ / \\ / \\ / \\ / \\ / \\ / \\ 
 ( w | c | D | e | t | e | c | t )
  \\_/ \\_/ \\_/ \\_/ \\_/ \\_/ \\_/ \\_/                                                                                                                                                                                              
    """
    print(f"{banner_text}")
    print(
        f"wcdetect v1.0"
    )


if __name__ == "__main__":
    print_banner()
