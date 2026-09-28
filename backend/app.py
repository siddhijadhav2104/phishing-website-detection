import os
import re
import math
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
FALLBACK_PATH = os.path.join(BASE_DIR, "predictions.json")

for env_file in [os.path.join(BASE_DIR, ".env"), os.path.join(BASE_DIR, "..", ".env")]:
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

app = Flask(__name__)
CORS(app)

bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
FEATURES = bundle["features"]

SUSPICIOUS_WORDS = [
    "login","verify","verification","secure","account","update",
    "confirm","password","signin","bank","wallet","bonus","free",
    "payment","unlock","security","support"
]

SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly",
    "buff.ly","cutt.ly","rb.gy","shorturl.at"
}

def entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def extract_features(raw_url):
    url = raw_url.strip()
    test_url = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
    p = urlparse(test_url)

    host = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""

    digits = sum(c.isdigit() for c in url)
    special = sum(not c.isalnum() for c in url)
    subdomains = max(0, len(host.split(".")) - 2)

    try:
        has_ip = int(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)))
    except Exception:
        has_ip = 0

    values = [
        len(url), len(host), len(path), len(query),
        digits, special, url.count("-"), url.count("@"),
        url.count("//"), url.count("?"), url.count("="),
        subdomains, int(p.scheme.lower() == "https"),
        int(host.startswith("www.")),
        int(host in SHORTENERS or any(host.endswith("." + x) for x in SHORTENERS)),
        sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
        has_ip, int("xn--" in host),
        entropy(host), len(set(host))
    ]
    return values

def indicator_data(raw_url):
    f = extract_features(raw_url)
    return {
        "urlLength": f[0],
        "https": bool(f[12]),
        "hasIp": bool(f[16]),
        "shortener": bool(f[14]),
        "suspiciousKeywords": f[15],
        "subdomains": f[11]
    }

_mongo_client = None
_mongo_col = None

def get_mongo():
    global _mongo_client, _mongo_col
    if MongoClient is None:
        return None
    if _mongo_col is not None:
        return _mongo_col

    uri = (
        os.getenv("MONGO_URI")
        or os.getenv("MONGO_URL")
        or os.getenv("MONGODB_URI")
        or "mongodb://localhost:27017/"
    )
    # Strip template angle brackets if user copied <password> from Atlas
    uri = re.sub(r":<([^@>]+)>@", r":\1@", uri)

    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        _mongo_client = client

        db_name = os.getenv("MONGO_DB", "phishing_detector")
        try:
            db = client.get_default_database()
            if db is None:
                db = client[db_name]
        except Exception:
            db = client[db_name]

        col_name = os.getenv("MONGO_COLLECTION", "predictions")
        _mongo_col = db[col_name]
        print(f"[MongoDB] Successfully connected to database '{db.name}', collection '{col_name}'")
        return _mongo_col
    except Exception as e:
        print(f"[MongoDB] Connection notice: {e}. Using JSON fallback.")
        return None

def save_record(record):
    collection = get_mongo()
    if collection is not None:
        collection.insert_one(dict(record))
        return "MongoDB"
    data = []
    if os.path.exists(FALLBACK_PATH):
        try:
            with open(FALLBACK_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
    data.insert(0, record)
    with open(FALLBACK_PATH, "w", encoding="utf-8") as f:
        json.dump(data[:100], f, indent=2)
    return "Local JSON"

def get_history():
    collection = get_mongo()
    if collection is not None:
        docs = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(20))
        return docs, "MongoDB"
    if os.path.exists(FALLBACK_PATH):
        try:
            with open(FALLBACK_PATH, "r", encoding="utf-8") as f:
                return json.load(f)[:20], "Local JSON"
        except Exception:
            pass
    return [], "Local JSON"

@app.get("/api/health")
def health():
    collection = get_mongo()
    return jsonify({
        "status": "ok",
        "modelLoaded": True,
        "database": "MongoDB" if collection is not None else "Local JSON fallback"
    })

@app.post("/api/predict")
def predict():
    body = request.get_json(silent=True) or {}
    raw_url = str(body.get("url", "")).strip()

    if not raw_url:
        return jsonify({"error": "Please enter a URL."}), 400
    if len(raw_url) > 2048:
        return jsonify({"error": "URL is too long."}), 400

    features = extract_features(raw_url)
    prediction = int(model.predict([features])[0])
    probabilities = model.predict_proba([features])[0]
    phishing_probability = float(probabilities[1])
    confidence = float(max(probabilities)) * 100

    result = "Phishing" if prediction == 1 else "Legitimate"
    record = {
        "url": raw_url,
        "result": result,
        "confidence": round(confidence, 2),
        "phishingProbability": round(phishing_probability * 100, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "indicators": indicator_data(raw_url)
    }
    storage = save_record(record)

    return jsonify({
        "result": result,
        "confidence": round(confidence, 2),
        "phishingProbability": round(phishing_probability * 100, 2),
        "indicators": record["indicators"],
        "storage": storage
    })

@app.get("/api/history")
def history():
    records, storage = get_history()
    return jsonify({"history": records, "storage": storage})

FRONTEND_DIST = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "dist"))

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    # Do not intercept API routes
    if path.startswith("api/") or path == "api":
        return jsonify({"error": "Endpoint not found"}), 404

    target_file = os.path.join(FRONTEND_DIST, path)
    if path != "" and os.path.exists(target_file):
        return send_from_directory(FRONTEND_DIST, path)

    index_file = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(index_file):
        return send_from_directory(FRONTEND_DIST, "index.html")

    return jsonify({
        "status": "ok",
        "message": "Phishing Website Detection API is running.",
        "endpoints": ["/api/health", "/api/predict", "/api/history"]
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Backend running at http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
