# 🔐 Phishing Link Detector

### Heuristic-Based, Backend-Integrated Phishing Signal Engine

A production-oriented phishing detection engine built using structured heuristics, brand intelligence, and adaptive domain analysis.

This project is designed as a modular security component and is fully compatible with a centralized event-correlation architecture (PHEMA – Phishing & Hybrid Event Monitoring Architecture).

---

## 🚀 Overview

Modern phishing attacks rely on:

* Typosquatting
* Brand impersonation
* Homograph attacks
* Subdomain deception
* Suspicious TLD abuse
* URL obfuscation
* High-entropy payload injection

This engine detects those signals using layered heuristic logic and emits structured detection events for backend correlation systems.

It does **not perform final risk classification**, but instead produces standardized security signals for higher-level threat intelligence systems.

---

## 🏗 Architecture

```
User Input
    ↓
URL Normalization
    ↓
Domain Parsing
    ↓
Layered Heuristic Engine
    ↓
Brand Intelligence Engine
    ↓
Signal Emission Adapter (PHEMA Contract)
    ↓
Backend Correlation
```

---

## 🧠 Core Detection Layers

### 1️⃣ Structural Analysis

* IP-based URLs
* Excessive subdomain depth
* Suspicious / high-risk TLDs
* URL shorteners
* Multiple hyphen abuse
* Digit density anomalies

---

### 2️⃣ Brand Intelligence Engine

A dynamic brand-classification system that detects:

* Exact brand matches (legitimate domains)
* Typosquatting (Levenshtein distance ≤ 1)
* Prefix/suffix impersonation (`amazon-login.com`)
* Brand embedding inside malicious domains
* Subdomain misuse (`amazon.secure-login.xyz`)

This prevents false positives for legitimate brand domains while aggressively flagging impersonations.

---

### 3️⃣ Obfuscation & Linguistic Signals

* Authentication keywords (`login`, `verify`, `update`)
* Urgency indicators (`urgent`, `immediate`)
* Shannon entropy analysis (path/query randomness)
* Unicode / homograph detection

---

### 4️⃣ Domain Intelligence

* Domain age lookup (WHOIS-based)
* Lightweight reputation scoring
* Adaptive heuristic dampening for trusted domains

---

## 🔄 Event-Based Output (Backend Contract)

Instead of returning “safe” or “phishing”, the engine emits standardized detection signals:

```json
{
  "entity_id": "hash_of_url",
  "entity_type": "session",
  "module": "phishing",
  "signal": "brand_impersonation",
  "confidence": 0.85,
  "severity": "high",
  "metadata": {}
}
```

This allows:

* Multi-module correlation
* Risk aggregation
* Behavioral linking
* Dynamic risk scoring by backend systems

---

## 🌐 Web Interface

A lightweight Tailwind-based frontend provides:

* Real-time URL submission
* Live “Analyzing…” state feedback
* Structured signal visualization
* Severity-based UI highlighting

Designed for clarity, not gimmicks.

---

## 🛠 Tech Stack

Backend:

* FastAPI
* Uvicorn
* tldextract
* python-whois
* Custom heuristic modules

Frontend:

* TailwindCSS
* Minimal JS (fetch-based API interaction)

Deployment:

* Render (production-ready)
* GitHub CI-based deployment

---

## 📁 Project Structure

```
core/
    analyzer.py
    parser.py
    normalizer.py
    scorer.py

rules/
    brands.py
    brand_domains.py
    keywords.py
    tlds.py
    shorteners.py

utils/
    brand_engine.py
    domain_age.py
    entropy.py
    reputation.py
    string_utils.py

api/
    server.py

web/
    templates/
    static/
```

---

## 🧩 Engineering Decisions

✔ No hardcoded “safe/unsafe” verdicts
✔ Modular detection layers
✔ Separation of signal emission from risk scoring
✔ Designed for backend correlation compatibility
✔ Reduced false positives on verified brand domains
✔ Scalable brand classification engine

---

## ⚠ Known Limitations

* WHOIS reliability varies across providers
* No external threat intelligence API integration (intentional design choice)
* No machine learning layer (heuristic-focused engine)
* Zero-day phishing sites may bypass detection without brand resemblance

This system prioritizes explainability and deterministic logic over black-box ML models.

---

## 🎯 Use Cases

* Security research projects
* Academic cybersecurity demonstrations
* Backend threat correlation systems
* Lightweight enterprise phishing filter prototype
* Resume-grade system design showcase

---

## 📦 Deployment

### Run Locally

```bash
pip install -r requirements.txt
uvicorn api.server:app --reload
```

Then open:

```
http://127.0.0.1:8000
```

---

### Production Deployment

Designed for deployment on:

* Render
* Railway
* Fly.io
* Docker environments

---

## 🔬 Sample Test Cases

### Legitimate

* [https://amazon.in](https://amazon.in)
* [https://google.com](https://google.com)
* [https://microsoft.com](https://microsoft.com)

### Phishing

* [https://amazon-login-secure.com](https://amazon-login-secure.com)
* [https://amazom.com](https://amazom.com)
* [https://paypal.verify-account.xyz](https://paypal.verify-account.xyz)
* [http://192.168.1.1/login](http://192.168.1.1/login)

---

## 🧠 Future Improvements

* Public phishing database integration
* Async WHOIS caching
* Threat intelligence API hooks
* Graph-based brand similarity engine
* Passive DNS enrichment
* Behavioral correlation expansion

---

## 👨‍💻 Author

~Rugved Suryawanshi
rugved0149@gmail.com
https://github.com/rugved0149

*Built as part of a modular cybersecurity architecture project focused on real-world phishing       detection strategies and backend event correlation design.


---

# ⭐ Final Note

This is not a beginner-level phishing checker.

It is an engineered, modular detection component designed for scalable security architectures.

---
## License

This project is licensed under the MIT License – see the LICENSE file for details.