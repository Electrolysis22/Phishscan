import os

import pandas as pd

N = 50

train = set(pd.read_csv("data/urls.csv")["url"])

if os.path.exists("raw/phishtank_new.csv"):
    fresh = pd.read_csv("raw/phishtank_new.csv")["url"]
elif os.path.exists("raw/openphish_new.txt"):
    with open("raw/openphish_new.txt") as f:
        fresh = pd.Series([line.strip() for line in f if line.strip()])
else:
    raise SystemExit("Put raw/phishtank_new.csv or raw/openphish_new.txt in place first.")

fresh = fresh.dropna().drop_duplicates()
fresh = fresh[~fresh.isin(train)]
fresh = fresh.sample(min(N, len(fresh)), random_state=1)

with open("raw/legit_manual.txt") as f:
    legit = pd.Series([line.strip() for line in f if line.strip()])

out = pd.concat([
    pd.DataFrame({"url": fresh.values, "label": 1}),
    pd.DataFrame({"url": legit.values, "label": 0}),
])
out.to_csv("data/eval_urls.csv", index=False)
print(out["label"].value_counts())