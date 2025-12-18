#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Prints a colorful ASCII art banner along with a brief description of the HExHTTP tool.
"""

try:
    from _version import __version__
except ImportError:
    __version__ = "v1.2"



def print_banner() -> None:
    banner_text = f"""
┌───────┐ ──╮╭── ┌───────┐
│       │   ││   │       │
│   W   │   ││   │   D   │
│       │   ││   │       │
└───────┘ ──╯╰── └───────┘
      wcdetect {__version__}                                                                                                                                                                   
    """
    print(f"{banner_text}")


if __name__ == "__main__":
    print_banner()
