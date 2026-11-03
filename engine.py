import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from bs4 import BeautifulSoup

from analyzer import content_findings, domain_age_days, domain_created, domain_findings, fetch, url_findings
from features import extract, normalize, reg_domain

BASE_DIR = Path(__file__).resolve().parent
MODEL = joblib.load(BASE_DIR / "model" / "model.joblib")
PASSWORD_TYPE = re.compile(r"^password$", re.I)
SCHEME_RE = re.compile(r"^https?://", re.I)

ERRORS = {
    "unresolved": "The domain does not resolve, so the page could not be opened.",
    "blocked": "The address points to a private or internal network and was not fetched for safety.",
    "unreachable": "The site could not be reached (it may be offline or blocking automated visitors).",
    "http_error": "The site refused to show its page to an automated visitor, which many large sites do.",
    "not_html": "The address did not return a web page.",
    "too_many_redirects": "The link redirected too many times to follow.",
    "ssl_error": "The site's security certificate is invalid, so the page was not opened.",
}


def plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def age_phrase(days):
    years = days // 365
    months = (days % 365) // 30
    parts = []
    if years:
        parts.append(plural(years, "year"))
    if months:
        parts.append(plural(months, "month"))
    if not parts:
        parts.append(plural(days, "day"))
    return ", ".join(parts)


def decide(findings, fetched, age_days):
    positive = sum(f["points"] for f in findings if f["points"] > 0)
    negative = sum(f["points"] for f in findings if f["points"] < 0)
    high_content = [f for f in findings if f["category"] == "content" and f["severity"] == "high"]
    trust_ignored = bool(high_content) and negative < 0
    if high_content:
        negative = 0
    raw = max(0, min(100, positive + negative))
    score = raw
    boosted = False
    if len(high_content) >= 2 and raw < 70:
        score = 70
        boosted = True
    categories = {f["category"] for f in findings if f["points"] > 0}
    limited = False
    if fetched and score >= 60 and (len(categories) >= 2 or len(high_content) >= 2):
        verdict = "phishing"
    elif not fetched and score >= 70 and len(categories) >= 2:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    elif fetched:
        verdict = "likely_safe"
    elif age_days is not None and age_days >= 365 and "url" not in categories:
        verdict = "likely_safe"
        limited = True
    else:
        verdict = "inconclusive"
    return {
        "verdict": verdict,
        "score": score,
        "limited": limited,
        "trust_ignored": trust_ignored,
        "boosted": boosted,
        "warning_points": positive,
        "trust_points": negative,
    }


def summarize(verdict, findings, fetched, limited, thin):
    top = [f["title"] for f in sorted(findings, key=lambda f: -f["points"]) if f["points"] > 0][:3]
    if verdict == "phishing":
        text = "This looks like a fake (phishing) site. Main reasons: " + "; ".join(top) + "."
        if not fetched:
            text += " This is based on the link and domain only, because the page could not be opened."
        return text
    if verdict == "suspicious":
        return "This site is suspicious, but the evidence is not strong enough to call it fake. Main reasons: " + "; ".join(top) + "."
    if verdict == "likely_safe" and limited:
        return "This looks legitimate based on the link and its domain, but the page itself could not be opened, so it was not checked in full."
    if verdict == "likely_safe" and thin:
        return "This looks legitimate based on what could be checked, but the page loads most of its content with JavaScript, so the check was only partial."
    if verdict == "likely_safe":
        return "This looks like a legitimate site. No strong warning signs were found. No automatic check is a guarantee, so stay careful with passwords and payments."
    return "The page could not be opened, and the link and domain alone do not give enough evidence to say whether it is fake or real."


def passed_checks(url, ml_prob, result, age_days, soup, findings):
    warned = {f["title"] for f in findings if f["points"] > 0}
    cats = {f["category"] for f in findings if f["points"] > 0}
    out = []
    if "url" not in cats:
        out.append("The link looks ordinary: no IP address, look-alike characters, link shortener or misleading brand name.")
    if ml_prob < 0.5:
        out.append(f"The URL-pattern model scores this link {round(ml_prob * 100)}% phishing-like, which is low.")
    if urlparse(url).scheme == "https" and not result["ssl_failed"]:
        out.append("The connection uses HTTPS with a valid security certificate.")
    if age_days is not None and age_days >= 180:
        out.append(f"The domain has existed for {age_phrase(age_days)}, so it is not a brand-new registration.")
    if "Redirects to a different domain" not in warned:
        out.append("The link does not send you to a different domain.")
    if soup is not None:
        if "content" not in cats:
            out.append("The page showed no hidden frames, disguised code or data-stealing forms.")
        has_password = bool(soup.find("input", attrs={"type": PASSWORD_TYPE}))
        if has_password and not any(t.startswith("Password form") for t in warned):
            out.append("The page has a login form, but it does not send the password to a different domain.")
        if not any(t.startswith("Page impersonates") for t in warned):
            out.append("The page does not pretend to be a well-known brand that it is not hosted by.")
    return out


def analyze(raw):
    cleaned = raw.strip()
    had_scheme = bool(SCHEME_RE.match(cleaned))
    url = normalize(cleaned)
    host = (urlparse(url).hostname or "").lower()
    if "." not in host:
        raise ValueError("invalid url")

    result = fetch(url)
    if result["html"] is None and result["error"] == "unreachable" and not had_scheme and url.startswith("https://"):
        http_url = "http://" + url[len("https://"):]
        retry = fetch(http_url)
        if retry["html"] is not None:
            url, result = http_url, retry
    fetched = result["html"] is not None

    ml_prob = float(MODEL.predict_proba(pd.DataFrame([extract(url)]))[0][1])
    findings = url_findings(url, ml_prob)

    final_url = result["final_url"]
    final_rd = reg_domain((urlparse(final_url).hostname or "").lower())
    created, age_status = domain_created(final_rd)
    age_days = domain_age_days(created)
    findings += domain_findings(reg_domain(host), result, age_days)

    page = {}
    soup = None
    thin = False
    if fetched:
        soup = BeautifulSoup(result["html"], "html.parser")
        findings += content_findings(soup, result["html"], final_url)
        visible = soup.get_text(" ", strip=True)
        thin = len(visible) < 300 and len(soup.find_all("script")) >= 3
        page = {
            "title": soup.title.get_text(" ", strip=True) if soup.title else "",
            "final_url": final_url,
            "status": result["status"],
            "redirects": len(result["chain"]) - 1,
            "forms": len(soup.find_all("form")),
        }

    decision = decide(findings, fetched, age_days)
    verdict = decision["verdict"]

    notes = []
    if not fetched:
        notes.append(ERRORS.get(result["error"], "The page could not be opened."))
        notes.append("The result rests on the link and domain checks only.")
    if thin:
        notes.append("This page builds most of its content with JavaScript, which the scanner does not run, so only part of it could be checked.")
    if decision["trust_ignored"]:
        notes.append("Trust credit was not applied because strong content evidence was found.")
    if decision["boosted"]:
        notes.append("The score was raised to 70 because two strong findings were found on the page itself.")

    return {
        "url": url,
        "verdict": verdict,
        "partial": decision["limited"] or thin,
        "score": decision["score"],
        "summary": summarize(verdict, findings, fetched, decision["limited"], thin),
        "findings": sorted([f for f in findings if f["points"] > 0], key=lambda f: -f["points"]),
        "passed": passed_checks(url, ml_prob, result, age_days, soup, findings),
        "breakdown": {
            "warning": decision["warning_points"],
            "trust": decision["trust_points"],
        },
        "notes": notes,
        "page": page,
        "ml_probability": round(ml_prob, 3),
        "domain": {
            "name": final_rd,
            "age_days": age_days,
            "age_status": age_status,
            "created": created.date().isoformat() if created else None,
        },
    }