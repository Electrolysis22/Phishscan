import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from analyzer import (add, content_findings, domain_age_days, domain_created,
                      domain_findings, fetch, url_findings)
from features import extract_features, reg_domain

BASE_DIR = Path(__file__).parent

bundle = joblib.load(BASE_DIR / "model" / "model.joblib")
model, FEATURES = bundle["model"], bundle["features"]
app = FastAPI(title="Phishing URL Detector")


class Req(BaseModel):
    url: str


def ml_probability(raw_url):
    feats = extract_features(raw_url)
    return float(model.predict_proba(pd.DataFrame([feats])[FEATURES])[0, 1])


@app.post("/predict")
def predict(req: Req):
    prob = ml_probability(req.url)
    return {
        "url": req.url,
        "verdict": "phishing" if prob >= 0.5 else "legitimate",
        "phishing_probability": round(prob, 4),
    }


@app.post("/analyze")
def analyze(req: Req):
    raw = req.url.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty URL")
    url = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "https://" + raw
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="Invalid URL")

    input_rd = reg_domain(host)
    ml_prob = ml_probability(raw)

    findings = url_findings(url, ml_prob)

    result = fetch(url)
    created, created_status = domain_created(input_rd)
    age = domain_age_days(created)
    findings += domain_findings(input_rd, result, age)

    if result["html"]:
        soup = BeautifulSoup(result["html"], "html.parser")
        findings += content_findings(soup, result["html"], result["final_url"])
    else:
        add(findings, "content", "info", 0, "Page could not be loaded",
            "Only the URL and domain were checked. Reason: " + str(result["error"]) + ".")

    score = max(0, min(100, sum(f["points"] for f in findings)))
    if score >= 50:
        verdict, label = "phishing", "Likely phishing"
    elif score >= 25:
        verdict, label = "suspicious", "Suspicious"
    else:
        verdict, label = "legitimate", "Looks legitimate"

    findings.sort(key=lambda f: f["points"], reverse=True)
    reasons = [f["title"] for f in findings if f["points"] > 0][:3]
    summary = f"{label}. Risk score {score}/100."
    if reasons:
        summary += " " + "; ".join(reasons) + "."
    if not result["html"]:
        summary += " The page could not be loaded, so only the URL and domain were checked."

    return {
        "url": raw,
        "final_url": result["final_url"],
        "verdict": verdict,
        "score": score,
        "phishing_probability": round(score / 100, 4),
        "domain_age_days": age,
        "domain_age_status": created_status,
        "fetch_error": result["error"],
        "findings": findings,
        "summary": summary,
    }


@app.get("/", response_class=HTMLResponse)
def home():
    return (BASE_DIR / "index.html").read_text(encoding="utf-8")