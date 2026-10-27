import json

from flask import Flask, jsonify, request, send_from_directory

from engine import analyze

app = Flask(__name__, static_folder="static")


@app.after_request
def no_cache(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


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
    except Exception as e:
        app.logger.error("analysis failed: %s", type(e).__name__)
        return jsonify({"error": "Analysis failed. Try again."}), 500
    return jsonify(result)


@app.get("/api/metrics")
def metrics():
    with open("model/metrics.json") as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    app.run(port=5000)