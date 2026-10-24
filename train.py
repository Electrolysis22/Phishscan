import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import extract, normalize

df = pd.read_csv("data/urls.csv").dropna().drop_duplicates(subset="url")

rows, labels = [], []
for url, label in zip(df["url"], df["label"]):
    try:
        rows.append(extract(normalize(url)))
        labels.append(int(label))
    except ValueError:
        continue

X = pd.DataFrame(rows)
y = pd.Series(labels)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

models = {
    "random_forest": RandomForestClassifier(n_estimators=300, class_weight="balanced", n_jobs=-1, random_state=42),
    "decision_tree": DecisionTreeClassifier(max_depth=12, class_weight="balanced", random_state=42),
    "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
}

metrics = {}
for name, model in models.items():
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    metrics[name] = {
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
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