# wcdetect
web cache deception detect

```
python3 cache_deception.py -h                          
usage: cache_deception.py [-h] [-u URL] [-f URL_FILE] [-H CUSTOM_HEADERS] [-p KNOWN_PATH]

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

```
