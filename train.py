import json
import os
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import extract, normalize, reg_domain

df = pd.read_csv("data/urls.csv").dropna().drop_duplicates(subset="url")

rows, labels, groups = [], [], []
for url, label in zip(df["url"], df["label"]):
    try:
        full = normalize(url)
        rows.append(extract(full))
        labels.append(int(label))
        groups.append(reg_domain((urlparse(full).hostname or "").lower()))
    except ValueError:
        continue

X = pd.DataFrame(rows)
y = pd.Series(labels)
g = pd.Series(groups)

splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=g))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
print("train rows:", len(X_train), "test rows:", len(X_test))
print("domains shared between train and test:", len(set(g.iloc[train_idx]) & set(g.iloc[test_idx])))

models = {
    "random_forest": RandomForestClassifier(n_estimators=300, class_weight="balanced", n_jobs=-1, random_state=42),
    "decision_tree": DecisionTreeClassifier(max_depth=12, class_weight="balanced", random_state=42),
    "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
}

metrics = {}
for name, model in models.items():
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    scores = model.predict_proba(X_test)[:, 1]
    metrics[name] = {
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, scores), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }
    print(name, metrics[name])

forest = models["random_forest"]
importance = sorted(zip(X.columns, forest.feature_importances_), key=lambda p: -p[1])
metrics["random_forest"]["top_features"] = [[n, round(float(v), 4)] for n, v in importance[:10]]

os.makedirs("model", exist_ok=True)
joblib.dump(forest, "model/model.joblib")
with open("model/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)