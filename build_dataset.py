import os
import random

import pandas as pd

random.seed(42)

parts = []
if os.path.exists("raw/phishtank.csv"):
    parts.append(pd.read_csv("raw/phishtank.csv")["url"])
if os.path.exists("raw/openphish.txt"):
    with open("raw/openphish.txt") as f:
        parts.append(pd.Series([line.strip() for line in f if line.strip()]))
if not parts:
    raise SystemExit("Put raw/phishtank.csv or raw/openphish.txt in place first.")

phish = pd.concat(parts).dropna().drop_duplicates()
phish = phish.sample(min(len(phish), 15000), random_state=42)
n = len(phish)

domains = pd.read_csv("raw/tranco.csv", header=None, names=["rank", "domain"])["domain"].head(100000)
domains = domains.sample(min(n, len(domains)), random_state=42)

paths = ["", "", "/", "/login", "/signin", "/account", "/about", "/contact", "/products", "/blog/2024/how-it-works", "/search?q=help", "/support/article/1234"]
legit = pd.Series([f"https://{d}{random.choice(paths)}" for d in domains])

out = pd.concat([
    pd.DataFrame({"url": phish.values, "label": 1}),
    pd.DataFrame({"url": legit.values, "label": 0}),
])
out = out.drop_duplicates(subset="url")
out.sample(frac=1, random_state=42).to_csv("data/urls.csv", index=False)
print(out["label"].value_counts())