import math
import re
from urllib.parse import urlparse

import tldextract

_tld = tldextract.TLDExtract(suffix_list_urls=())

KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "bank", "confirm", "password", "wallet", "billing", "support", "webscr", "authenticate"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


def reg_domain(host):
    ext = _tld(host or "")
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def subdomain_count(host):
    return len([s for s in _tld(host or "").subdomain.split(".") if s])


def entropy(text):
    if not text:
        return 0.0
    total = len(text)
    return -sum((text.count(c) / total) * math.log2(text.count(c) / total) for c in set(text))


def extract(url):
    u = urlparse(url)
    host = (u.hostname or "").lower()
    path = u.path or ""
    query = u.query or ""
    tail = (path + "?" + query).lower()
    try:
        has_port = u.port is not None
    except ValueError:
        has_port = True
    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dots": url.count("."),
        "host_hyphens": host.count("-"),
        "underscores": url.count("_"),
        "at_symbol": int("@" in url),
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
        "slashes": url.count("/"),
        "ampersands": url.count("&"),
        "percent": url.count("%"),
        "equals": url.count("="),
        "is_ip": int(bool(IP_RE.match(host))),
        "subdomains": subdomain_count(host),
        "punycode": int("xn--" in host),
        "keywords_host": sum(k in host for k in KEYWORDS),
        "keywords_path": sum(k in tail for k in KEYWORDS),
        "shortener": int(reg_domain(host) in SHORTENERS),
        "host_entropy": entropy(host),
        "path_depth": path.count("/"),
        "has_port": int(has_port),
        "double_slash_path": int("//" in path),
        "tld_in_subdomain": int(bool(re.search(r"\.(com|net|org|gov|edu)\.", host))),
    }