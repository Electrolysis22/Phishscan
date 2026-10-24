import json
import sqlite3

from flask import Flask, jsonify, request, send_from_directory

from engine import analyze

app = Flask(__name__, static_folder="static")
DB = "history.db"


def db():
    con = sqlite3.connect(DB)
    con.execute("create table if not exists scans (id integer primary key autoincrement, url text, verdict text, score integer, created text default current_timestamp)")
    return con


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url or len(url) > 2048:
        return jsonify({"error": "Enter a valid URL."}), 400
    try:
        result = analyze(url)
    except ValueError:
        return jsonify({"error": "Enter a valid URL."}), 400
    except Exception:
        app.logger.exception("analysis failed")
        return jsonify({"error": "Analysis failed. Try again."}), 500
    con = db()
    with con:
        con.execute("insert into scans (url, verdict, score) values (?, ?, ?)", (result["url"], result["verdict"], result["score"]))
    con.close()
    return jsonify(result)


@app.get("/api/history")
def history():
    con = db()
    rows = con.execute("select url, verdict, score, created from scans order by id desc limit 15").fetchall()
    counts = dict(con.execute("select verdict, count(*) from scans group by verdict").fetchall())
    con.close()
    return jsonify({
        "recent": [{"url": r[0], "verdict": r[1], "score": r[2], "created": r[3]} for r in rows],
        "counts": counts,
    })


@app.get("/api/metrics")
def metrics():
    with open("model/metrics.json") as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    app.run(port=5000)