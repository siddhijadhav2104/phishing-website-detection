import os
import re
import math
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
FALLBACK_PATH = os.path.join(BASE_DIR, "predictions.json")

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

def get_mongo():
    if MongoClient is None:
        return None
    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=800)
        client.admin.command("ping")
        db = client[os.getenv("MONGO_DB", "phishing_detector")]
        return db[os.getenv("MONGO_COLLECTION", "predictions")]
    except Exception:
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

if __name__ == "__main__":
    print("Backend running at http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
