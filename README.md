# wcDetect
web cache deception detect


<p align="center">
  <img src="./static/wcdetect_logo.png" alt="Logo" width="320">
</p>
<div align="center">
<img src="https://img.shields.io/github/v/release/c0dejump/wcDetect" alt="release version">
<img alt="Python3.7" src="https://img.shields.io/badge/Python-3.7+-informational">
</div>

```bash                  
usage: wcdetect.py [-h] [-u URL] [-f URL_FILE] [-H CUSTOM_HEADERS] [-p KNOWN_PATH] [-k KEYWORD]

options:
  -h, --help            show this help message and exit
  -u, --url URL         URL to test [required]
  -f, --file URL_FILE   File of URLs
  -H, --header CUSTOM_HEADERS
                        Add a custom HTTP Header
  -p, --path KNOWN_PATH
                        If you know the path, Ex: -p my-account
  -k, --keyword KEYWORD
                        If a keyword must be present in the poisoned response, Ex: -k codejump
  -hu HUMAN, --human HUMAN
                        Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'

```
### Arguments

```bash
# With multiple headers
» ./wcdetect.py -u https://0a4f00ae0447a9ce801a03a500ea0097.web-security-academy.net/ -H "Cookie: session=OocpsiwqB6XOUkBkBDuqEHUb2BxYEvbC" -H "x-forwarded-host: toto"

# With specific keyword and path
» ./wcdetect.py -u https://0a4f00ae0447a9ce801a03a500ea0097.web-security-academy.net/ -H "Cookie: session=OocpsiwqB6XOUkBkBDuqEHUb2BxYEvbC" -p my-account -k wiener
```

## Examples

![example 1](./static/exemple.png)

## Features

- Path traversal confusion
- Testing multiple payloads and extensions (modules/payloads.py)

## Informations

If you want to test the script:
- https://portswigger.net/web-security/web-cache-deception

To retrieve the session cookie quickly and easily:
- https://cookie-editor.com/

If you want to add payloads or other items
- modules/payloads.py