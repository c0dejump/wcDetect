extensions = [
    ".css", ".js", ".CSS", ".JS", ".svg",
    ".asp", ".aspx", ".atom", ".bak", ".backup", ".bin", ".cgi", ".csv", 
    ".do", ".eot", ".exe", ".fake.js", ".gif", ".html", ".ico", 
    ".jpg", ".jpeg", ".json", ".jsonp", ".jsp", ".mp3", ".mp4", ".old", ".pdf", 
    ".php", ".png", ".rss", ".tar.gz", ".tmp", ".ttf", ".txt", 
    ".webm", ".woff", ".woff2", ".xml", ".zip", ".7z",
    ".aac", ".avi", ".bmp", ".cab", ".class", ".dat", ".db", ".dll", ".doc", ".docx",
    ".dwg", ".eps", ".flv", ".gz", ".hqx", ".htc", ".ics", ".jar", ".log", ".m4a",
    ".m4v", ".mid", ".midi", ".mov", ".ogg", ".ogv", ".otf", ".ppt", ".pptx", ".psd",
    ".rar", ".rtf", ".sit", ".sitx", ".swf", ".tar", ".tgz", ".tif", ".tiff", ".wav",
    ".webp", ".xls", ".xlsx", ".xsl", ".xslt",
    ".bak~", ".conf", ".ini", ".php5", ".php7", ".env", ".sh", ".zip.tmp", ".git/config"
]

delimiters = [
    "~", "\\/", "\\", ";", ":", ":443", "//", "/", "..", ".", "_", "-", 
    "@", "?", "=", "#", "##", "!*", "!", "&", "$", "+", ",", "%", "\"",
    "'", "(", ")", "<", ">", "[", "]", "{", "}", "|", "..\\/", "../",
    "%5c", "%3d", "%2f", "%2e", "%26", "%23", "%20", "%0a", "%09", 
    "%00", "%3b", "%3f", "%2b", "%2c", "%7e", "%25", "%0d%0a", "%C2%A0",
    "%5b", "%5d", "%7b", "%7d",
    "%252f", "%252e",
    "*", "^", "`", "\\n", "\\r", "\\t",
    "%40", "%21", "%24", "%27", "%28", "%29", "%2a", "%3a", "%3c", "%3e", "%7c",
    "%80", "%c0%ae", "%e0%80%ae",
    "..;", "..;/", ";/", "/.;/", "/..;/",
    "%252e%252e", "%c0%2f", "%c0%5c", "%c1%1c", "%c1%9c",
    "....//", "..../", ".%00", "..%00", "%2e%2e/", "%2e%2e%2f"
]

DEFAULT_PATHS = ['account', 'profile', 'dashboard', 'settings', 'user', 'admin', 'private', 'my-account', 'user/profile', 'dashboard/image', 'dashboard/profile', 'account/user', 'address']
KNOWN_PATHS = []