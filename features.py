import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "paypal", "ebay", "amazon", "apple", "support",
    "wallet", "free", "bonus", "invoice", "webscr", "suspend",
]
KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "wallet", "support", "billing", "payment",
    "recover", "unlock", "suspend",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "support", "country"}
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.za", "com.ng", "org.ng", "edu.ng", "gov.ng", "co.in", "com.br", "co.jp",
    "com.cn", "com.mx", "com.tr", "co.ke",
}


def reg_domain(host):
    host = (host or "").lower().strip(".")
    if not host or IP_RE.match(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def subdomain_count(host):
    host = (host or "").lower().strip(".")
    if not host or IP_RE.match(host):
        return 0
    return max(len(host.split(".")) - len(reg_domain(host).split(".")), 0)


def _entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _has_port(p):
    try:
        return int(p.port is not None)
    except ValueError:
        return 0


def extract_features(url):
    url = str(url).strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        p, host = urlparse("http://invalid"), ""

    path, query = p.path or "", p.query or ""
    parts = [x for x in host.split(".") if x]
    tld = parts[-1] if parts else ""
    domain = parts[-2] if len(parts) >= 2 else host
    subdomains = parts[:-2] if len(parts) > 2 else []
    lowered = url.lower()

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_hyphens_host": host.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equals": url.count("="),
        "num_ampersand": url.count("&"),
        "num_percent": url.count("%"),
        "num_digits": sum(c.isdigit() for c in url),
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
        "num_subdomains": len(subdomains),
        "has_ip_host": int(bool(IP_RE.match(host))),
        "is_https": int(p.scheme == "https"),
        "has_port": _has_port(p),
        "is_shortener": int(host in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "suspicious_word_count": sum(w in lowered for w in SUSPICIOUS_WORDS),
        "brand_in_subdomain": int(any(w in ".".join(subdomains) for w in ("paypal", "apple", "amazon", "google", "microsoft", "bank"))),
        "double_slash_in_path": int("//" in path),
        "domain_entropy": _entropy(domain),
        "url_entropy": _entropy(url),
        "longest_digit_run": max((len(m) for m in re.findall(r"\d+", host)), default=0),
        "has_punycode": int("xn--" in host),
    }