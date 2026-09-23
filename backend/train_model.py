import os
import random
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

FEATURES = [
    "url_length","domain_length","path_length","query_length",
    "digit_count","special_count","hyphen_count","at_count",
    "double_slash_count","question_count","equal_count",
    "subdomain_count","has_https","has_www","has_shortener",
    "suspicious_keyword_count","has_ip","has_punycode",
    "entropy","unique_domain_chars"
]

def make_sample(phishing):
    if phishing:
        domain_len = random.randint(8, 45)
        path_len = random.randint(5, 90)
        query_len = random.randint(0, 100)
        digit_count = random.randint(2, 18)
        special_count = random.randint(3, 22)
        hyphen_count = random.randint(0, 6)
        at_count = random.choice([0, 0, 1])
        double_slash_count = random.choice([1, 1, 2])
        question_count = random.choice([0, 1, 1])
        equal_count = random.randint(0, 5)
        subdomain_count = random.randint(1, 5)
        has_https = random.choice([0, 0, 1])
        has_www = random.choice([0, 1])
        has_shortener = random.choice([0, 1])
        suspicious = random.randint(1, 6)
        has_ip = random.choice([0, 0, 1])
        has_punycode = random.choice([0, 0, 1])
        entropy = random.uniform(3.7, 5.8)
        unique = random.randint(5, min(30, domain_len))
    else:
        domain_len = random.randint(5, 28)
        path_len = random.randint(0, 45)
        query_len = random.randint(0, 45)
        digit_count = random.randint(0, 5)
        special_count = random.randint(0, 8)
        hyphen_count = random.randint(0, 2)
        at_count = 0
        double_slash_count = 1
        question_count = random.choice([0, 0, 1])
        equal_count = random.randint(0, 2)
        subdomain_count = random.randint(0, 2)
        has_https = random.choice([1, 1, 1, 0])
        has_www = random.choice([0, 1])
        has_shortener = 0
        suspicious = random.choice([0, 0, 1])
        has_ip = 0
        has_punycode = 0
        entropy = random.uniform(2.5, 4.4)
        unique = random.randint(5, min(22, domain_len))

    return [
        random.randint(domain_len + path_len + query_len + 10, domain_len + path_len + query_len + 60),
        domain_len, path_len, query_len, digit_count, special_count,
        hyphen_count, at_count, double_slash_count, question_count,
        equal_count, subdomain_count, has_https, has_www, has_shortener,
        suspicious, has_ip, has_punycode, entropy, unique
    ]

def main():
    X, y = [], []
    for _ in range(6000):
        phishing = random.randint(0, 1)
        X.append(make_sample(phishing))
        y.append(phishing)

    X = np.array(X)
    y = np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=250, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    acc = accuracy_score(y_test, model.predict(X_test))
    os.makedirs("models", exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES}, "models/phishing_model.pkl")
    print(f"Model created successfully. Synthetic validation accuracy: {acc:.4f}")
    print("Note: this model is for project demonstration and should not be treated as real-world accuracy.")

if __name__ == "__main__":
    main()
