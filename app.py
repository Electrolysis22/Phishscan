import json
import traceback
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from engine import analyze

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(BASE_DIR / "static"))


@app.after_request
def no_cache(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    return send_from_directory(BASE_DIR / "static", "index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True)
    url = data.get("url") if isinstance(data, dict) else None
    if not isinstance(url, str):
        return jsonify({"error": "Enter a valid URL."}), 400
    url = url.strip()
    if not url or len(url) > 2048 or any(ord(c) < 32 for c in url):
        return jsonify({"error": "Enter a valid URL."}), 400
    try:
        result = analyze(url)
    except ValueError:
        return jsonify({"error": "Enter a valid URL."}), 400
    except Exception as e:
        frames = "".join(traceback.format_tb(e.__traceback__))
        app.logger.error("analysis failed: %s\n%s", type(e).__name__, frames)
        return jsonify({"error": "Analysis failed. Try again."}), 500
    return jsonify(result)


@app.get("/api/metrics")
def metrics():
    try:
        with open(BASE_DIR / "model" / "metrics.json") as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({})


if __name__ == "__main__":
    app.run(port=5000)