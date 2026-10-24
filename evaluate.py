import pandas as pd

from engine import analyze

df = pd.read_csv("data/eval_urls.csv")
rows = []
for i, (url, label) in enumerate(zip(df["url"], df["label"]), start=1):
    print(f"{i}/{len(df)}  {url}", flush=True)
    try:
        r = analyze(url)
    except Exception:
        continue
    rows.append((url, int(label), int(r["verdict"] == "phishing"), r["verdict"], r["score"]))

out = pd.DataFrame(rows, columns=["url", "label", "pred", "verdict", "score"])
tp = int(((out.label == 1) & (out.pred == 1)).sum())
fp = int(((out.label == 0) & (out.pred == 1)).sum())
fn = int(((out.label == 1) & (out.pred == 0)).sum())
tn = int(((out.label == 0) & (out.pred == 0)).sum())

print()
print("Skipped (could not analyze):", len(df) - len(out))
print("TP", tp, "FP", fp, "FN", fn, "TN", tn)
print("False positive rate:", round(fp / max(fp + tn, 1), 3))
print("Recall:", round(tp / max(tp + fn, 1), 3))
print("Precision:", round(tp / max(tp + fp, 1), 3))
print()
print(pd.crosstab(out["label"], out["verdict"]))
out.to_csv("data/eval_results.csv", index=False)