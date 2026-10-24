from urllib.parse import urlparse

import joblib
import pandas as pd
from bs4 import BeautifulSoup

from analyzer import content_findings, domain_age_days, domain_findings, fetch, url_findings
from features import extract, normalize, reg_domain

MODEL = joblib.load("model/model.joblib")

ERRORS = {
    "unresolved": "The domain does not resolve, so the page could not be inspected.",
    "blocked": "The address points to a private or internal network and was not fetched for safety.",
    "unreachable": "The site could not be reached (it may be offline or blocking automated requests).",
    "not_html": "The address did not return an HTML page.",
    "too_many_redirects": "The link redirected too many times to follow.",
}


def decide(findings, fetched):
    positive = sum(f["points"] for f in findings if f["points"] > 0)
    negative = sum(f["points"] for f in findings if f["points"] < 0)
    high_content = [f for f in findings if f["category"] == "content" and f["severity"] == "high"]
    trust_ignored = bool(high_content) and negative < 0
    if high_content:
        negative = 0
    score = max(0, min(100, positive + negative))
    if len(high_content) >= 2:
        score = max(score, 70)
    categories = {f["category"] for f in findings if f["points"] > 0}
    if fetched and score >= 60 and (len(categories) >= 2 or len(high_content) >= 2):
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    elif fetched:
        verdict = "likely_safe"
    else:
        verdict = "inconclusive"
    return verdict, score, trust_ignored


def summarize(verdict, findings):
    top = [f["title"] for f in sorted(findings, key=lambda f: -f["points"]) if f["points"] > 0][:3]
    if verdict == "phishing":
        return "Strong evidence from multiple checks: " + "; ".join(top) + "."
    if verdict == "suspicious":
        return "Some warning signs were found, but not enough to confirm phishing: " + "; ".join(top) + "."
    if verdict == "likely_safe":
        return "No strong phishing indicators were found in the URL, domain, or page content. This is not a guarantee of safety."
    return "The page could not be inspected, so only the URL and domain were checked. Nothing alarming was found, but this is not a confirmation of safety."


def analyze(raw):
    url = normalize(raw)
    host = (urlparse(url).hostname or "").lower()
    if "." not in host:
        raise ValueError("invalid url")

    ml_prob = float(MODEL.predict_proba(pd.DataFrame([extract(url)]))[0][1])
    findings = url_findings(url, ml_prob)

    result = fetch(url)
    fetched = result["html"] is not None
    final_url = result["final_url"]
    final_rd = reg_domain((urlparse(final_url).hostname or "").lower())
    findings += domain_findings(reg_domain(host), result, domain_age_days(final_rd))

    page = {}
    if fetched:
        soup = BeautifulSoup(result["html"], "html.parser")
        findings += content_findings(soup, result["html"], final_url)
        page = {
            "title": soup.title.get_text(" ", strip=True) if soup.title else "",
            "final_url": final_url,
            "status": result["status"],
            "redirects": len(result["chain"]) - 1,
            "forms": len(soup.find_all("form")),
        }

    verdict, score, trust_ignored = decide(findings, fetched)

    notes = []
    if not fetched:
        notes.append(ERRORS.get(result["error"], "The page could not be inspected."))
        notes.append("Without page content the verdict cannot exceed Suspicious.")
    if trust_ignored:
        notes.append("Trust signals were not applied because strong content evidence was found.")

    return {
        "url": url,
        "verdict": verdict,
        "score": score,
        "summary": summarize(verdict, findings),
        "findings": sorted([f for f in findings if f["points"] > 0], key=lambda f: -f["points"]),
        "trust": [f for f in findings if f["points"] < 0],
        "notes": notes,
        "page": page,
        "ml_probability": round(ml_prob, 3),
    }