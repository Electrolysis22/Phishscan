import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import whois

from features import IP_RE, KEYWORDS, SHORTENERS, reg_domain, subdomain_count

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PhishScan/1.0; academic research)"}
MAX_BYTES = 1500000
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE") == "1"
REDIRECT_CODES = {301, 302, 303, 307, 308}

FREE_HOSTS = {
    "github.io", "netlify.app", "pages.dev", "web.app", "firebaseapp.com", "weebly.com",
    "wixsite.com", "blogspot.com", "000webhostapp.com", "glitch.me", "vercel.app",
    "herokuapp.com", "workers.dev", "webflow.io", "carrd.co", "godaddysites.com",
}

BRANDS = {
    "paypal": ["paypal.com", "paypalobjects.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "gstatic.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazonaws.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "whatsapp": ["whatsapp.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
}

SENSITIVE_TOKENS = {"cvv", "cvc", "ssn", "otp", "pin", "iban", "passcode", "card", "cardnumber", "routing"}

_pool = ThreadPoolExecutor(max_workers=4)


def add(out, category, severity, points, title, detail):
    out.append({"category": category, "severity": severity, "points": points, "title": title, "detail": detail})


def host_status(url):
    host = urlparse(url).hostname
    if not host:
        return "unresolved"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "unresolved"
    if ALLOW_PRIVATE:
        return "ok"
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return "blocked"
        except ValueError:
            return "blocked"
    return "ok"


def fetch(url):
    chain = [url]
    current = url
    ssl_failed = False

    def fail(error):
        return {"html": None, "chain": chain, "ssl_failed": ssl_failed, "error": error, "final_url": current}

    for _ in range(8):
        status = host_status(current)
        if status != "ok":
            return fail(status)
        try:
            r = requests.get(current, headers=HEADERS, timeout=8, allow_redirects=False, stream=True, verify=not ssl_failed)
        except requests.exceptions.SSLError:
            if ssl_failed:
                return fail("unreachable")
            ssl_failed = True
            continue
        except requests.RequestException:
            return fail("unreachable")
        if r.status_code in REDIRECT_CODES and r.headers.get("Location"):
            current = urljoin(current, r.headers["Location"])
            chain.append(current)
            r.close()
            continue
        if "html" not in r.headers.get("Content-Type", "").lower():
            r.close()
            return fail("not_html")
        body = b""
        for part in r.iter_content(65536):
            body += part
            if len(body) > MAX_BYTES:
                break
        r.close()
        return {
            "html": body.decode(r.encoding or "utf-8", errors="ignore"),
            "chain": chain,
            "ssl_failed": ssl_failed,
            "error": None,
            "final_url": current,
            "status": r.status_code,
        }
    return fail("too_many_redirects")


def _lookup_created(domain):
    created = whois.whois(domain).creation_date
    if isinstance(created, list):
        created = created[0]
    if not isinstance(created, datetime):
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created


def domain_created(domain):
    if not domain or IP_RE.match(domain):
        return None
    try:
        return _pool.submit(_lookup_created, domain).result(timeout=6)
    except Exception:
        return None


def domain_age_days(created):
    if created is None:
        return None
    return max((datetime.now(timezone.utc) - created).days, 0)


def brand_in_host(host):
    tokens = set(re.split(r"[^a-z0-9]+", host))
    for brand in BRANDS:
        if brand in tokens or (len(brand) >= 6 and brand in host):
            return brand
    return None


def url_findings(url, ml_prob):
    out = []
    u = urlparse(url)
    host = (u.hostname or "").lower()
    rd = reg_domain(host)

    if IP_RE.match(host):
        add(out, "url", "high", 20, "IP address used instead of a domain name", "The link points to a raw IP address. Legitimate services almost never ask users to log in on a bare IP.")
    if u.username is not None:
        add(out, "url", "medium", 10, "Credentials-style '@' in the URL", "Text before the '@' is ignored by the browser and is commonly used to disguise the real destination.")
    if "xn--" in host:
        add(out, "url", "medium", 12, "Punycode (look-alike characters) in the domain", "The domain uses internationalized encoding that can imitate well-known names.")
    if subdomain_count(host) >= 3:
        add(out, "url", "low", 8, "Unusually many subdomains", "Long subdomain chains are often used to bury the real domain.")
    if rd in SHORTENERS:
        add(out, "url", "medium", 10, "Link shortener used", "The real destination is hidden behind a shortening service.")
    keywords = [k for k in KEYWORDS if k in host]
    if len(keywords) >= 2:
        add(out, "url", "medium", 8, "Sensitive keywords in the domain name", "The domain contains: " + ", ".join(keywords) + ".")

    brand = brand_in_host(host)
    if brand and rd not in BRANDS[brand]:
        add(out, "url", "high", 25, f"Domain mentions '{brand}' but is not an official {brand} domain", f"The registered domain is {rd}. Official domains include: {', '.join(BRANDS[brand])}.")
    else:
        path_words = set(re.split(r"[^a-z0-9]+", (u.path + " " + u.query).lower()))
        for name, official in BRANDS.items():
            if name in path_words and rd not in official:
                add(out, "url", "medium", 12, f"URL path references '{name}' on an unrelated domain", f"The page lives on {rd}, which is not an official {name} domain.")
                break

    if u.scheme != "https":
        add(out, "url", "medium", 8, "Connection is not encrypted (HTTP)", "The page is served without HTTPS.")
    if ml_prob >= 0.5:
        add(out, "url", "medium", round(ml_prob * 25), "URL structure resembles known phishing URLs", f"The machine-learning model gives this URL a {round(ml_prob * 100)}% phishing probability based on its structure alone.")
    return out


def domain_findings(input_rd, result, age_days):
    out = []
    if age_days is not None:
        if age_days < 30:
            add(out, "domain", "high", 20, "Domain registered less than 30 days ago", f"The domain is only {age_days} days old. Most phishing domains are very new.")
        elif age_days < 180:
            add(out, "domain", "medium", 8, "Domain registered recently", f"The domain is {age_days} days old.")
        elif age_days >= 730:
            add(out, "trust", "info", -10, "Domain has existed for more than two years", "Older domains are less likely to be purpose-built for phishing, though compromised sites are old too.")
    if result["ssl_failed"]:
        add(out, "domain", "medium", 12, "Invalid or untrusted HTTPS certificate", "The server's certificate failed verification.")
    cross = [c for c in result["chain"][1:] if reg_domain((urlparse(c).hostname or "").lower()) != input_rd]
    if cross:
        final = reg_domain((urlparse(cross[-1]).hostname or "").lower())
        add(out, "domain", "medium", 8, "Redirects to a different domain", f"The link started on {input_rd} but ends on {final}.")
    return out


def has_sensitive_input(soup):
    for inp in soup.find_all("input"):
        if str(inp.get("autocomplete", "")).lower().startswith("cc-"):
            return True
        blob = " ".join(str(inp.get(a, "")) for a in ("name", "id", "placeholder", "aria-label")).lower()
        if set(re.split(r"[^a-z]+", blob)) & SENSITIVE_TOKENS:
            return True
    return False


def content_findings(soup, html, final_url):
    out = []
    parsed = urlparse(final_url)
    rd = reg_domain((parsed.hostname or "").lower())
    pw_pattern = re.compile(r"^password$", re.I)
    has_password = bool(soup.find("input", attrs={"type": pw_pattern}))
    asks = has_password or has_sensitive_input(soup)

    for form in soup.find_all("form"):
        if not form.find("input", attrs={"type": pw_pattern}):
            continue
        action = (form.get("action") or "").strip()
        if action.lower().startswith("mailto:"):
            add(out, "content", "high", 20, "Password form sends data by email", "The login form submits to a mailto: address, which no real login system does.")
            break
        if action and not action.startswith("#") and not action.lower().startswith("javascript:"):
            target = reg_domain((urlparse(urljoin(final_url, action)).hostname or "").lower())
            if target and target != rd:
                add(out, "content", "high", 20, "Password form submits to a different domain", f"The page is on {rd} but the form sends the password to {target}. Some single-sign-on flows do this, so it is weighed with other evidence.")
                break

    if asks and parsed.scheme != "https":
        add(out, "content", "high", 15, "Sensitive data requested over an unencrypted connection", "The page asks for a password or payment/ID data without HTTPS.")

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    title_words = re.findall(r"[a-z0-9]+", title.lower())
    body_words = re.findall(r"[a-z0-9]+", soup.get_text(" ", strip=True).lower())[:400]
    best, best_score = None, 0
    for brand in BRANDS:
        s = 3 * title_words.count(brand) + body_words.count(brand)
        if s > best_score:
            best, best_score = brand, s
    if best and best_score >= 3:
        official = BRANDS[best]
        if rd in official:
            add(out, "trust", "info", -10, f"Page is hosted on an official {best} domain", f"{rd} is a known {best} domain.")
        elif asks:
            add(out, "content", "high", 40, f"Page impersonates {best}", f"The page presents itself as {best} and asks for a password or sensitive data, but it is hosted on {rd}, not an official domain ({', '.join(official)}).")
            assets = [t.get("src") or t.get("href") or "" for t in soup.find_all(["img", "link", "script"])]
            hot = [a for a in assets if a and reg_domain((urlparse(urljoin(final_url, a)).hostname or "").lower()) in official]
            if hot:
                add(out, "content", "medium", 10, f"Loads {best} images or files directly from the real site", f"{len(hot)} resource(s) are hotlinked from the genuine {best} website to make the copy look authentic.")

    if asks and rd in FREE_HOSTS:
        add(out, "content", "medium", 10, "Credential page on a free hosting platform", f"{rd} lets anyone publish pages. Free hosts are common for short-lived phishing pages.")

    hidden = 0
    for frame in soup.find_all("iframe"):
        style = (frame.get("style") or "").replace(" ", "").lower()
        if "display:none" in style or "visibility:hidden" in style or str(frame.get("width", "")) in ("0", "1") or str(frame.get("height", "")) in ("0", "1"):
            hidden += 1
    if hidden:
        add(out, "content", "medium", 10, "Hidden iframe on the page", f"{hidden} invisible iframe(s) were found. They can load content or track victims without being seen.")

    if re.search(r"oncontextmenu\s*=\s*[\"']?\s*return\s+false", html, re.I):
        add(out, "content", "low", 6, "Right-click is disabled", "Disabling the context menu is used to stop victims inspecting the page source.")

    if re.search(r"eval\s*\(", html) and re.search(r"atob\s*\(|unescape\s*\(|fromCharCode", html):
        add(out, "content", "medium", 10, "Obfuscated JavaScript", "The page decodes and executes hidden code (eval combined with atob/unescape/fromCharCode).")

    anchors = [(a.get("href") or "").strip() for a in soup.find_all("a")]
    if asks and len(anchors) >= 5:
        dead = sum(1 for h in anchors if h in ("", "#") or h.lower().startswith("javascript:"))
        if dead / len(anchors) > 0.5:
            add(out, "content", "medium", 8, "Most links on the page are dead", f"{dead} of {len(anchors)} links go nowhere, typical of a cloned page.")
    return out