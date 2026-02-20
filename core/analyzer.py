from utils.ip_check import is_ip_address
from utils.string_utils import tokenize, levenshtein_distance
from utils.unicode_check import contains_unicode, is_punycode
from utils.entropy import shannon_entropy
from utils.reputation import calculate_reputation
from utils.domain_age import get_domain_age_days
from rules.keywords import AUTH_KEYWORDS, URGENCY_KEYWORDS
from rules.brands import BRANDS
from rules.shorteners import SHORTENERS
from rules.tlds import SUSPICIOUS_TLDS, COUNTRY_TLDS
from rules.brand_domains import BRAND_DOMAINS
from utils.brand_engine import classify_brand_relation

def analyze(parsed: dict) -> list:
    """
    Structured phishing heuristic engine.
    Layered logic:
        1. Hard structural checks
        2. Brand classification engine
        3. Generic structural / linguistic checks
        4. Entropy & obfuscation
    """

    triggers = []

    host = parsed.get("netloc", "")
    path = parsed.get("path", "")
    query = parsed.get("query", "")
    full_domain = parsed.get("full_domain", "")
    subdomain = parsed.get("subdomain", "")
    domain = parsed.get("domain", "")
    suffix = parsed.get("suffix", "")
    url_length = parsed.get("url_length", 0)
    registered_domain = parsed.get("registered_domain", "")

    is_verified_brand_domain = any(
        registered_domain in domains
        for domains in BRAND_DOMAINS.values()
    )

    age_days = get_domain_age_days(registered_domain)
    reputation_score = calculate_reputation(parsed, age_days)

    # -------------------------------------------------
    # 1️⃣ HARD STRUCTURAL CHECKS (ALWAYS APPLY)
    # -------------------------------------------------

    if is_ip_address(host):
        triggers.append({"rule": "IP address used", "category": "structural"})

    if contains_unicode(full_domain) or is_punycode(full_domain):
        triggers.append({"rule": "Unicode / homograph domain", "category": "obfuscation"})

    if domain and suffix:
        reg = f"{domain}.{suffix}"
        if reg in SHORTENERS:
            triggers.append({"rule": "URL shortener used", "category": "hosting"})

    if suffix in SUSPICIOUS_TLDS:
        triggers.append({"rule": "Suspicious TLD", "category": "hosting"})

    if suffix in COUNTRY_TLDS:
        triggers.append({"rule": "High-risk country TLD", "category": "hosting"})

    if subdomain:
        depth = subdomain.count(".") + 1
        if depth > 5:
            triggers.append({"rule": "Excessive subdomains (>5)", "category": "structural"})
        elif depth > 3:
            triggers.append({"rule": "Many subdomains (>3)", "category": "structural"})

    # -------------------------------------------------
    # 2️⃣ BRAND CLASSIFICATION ENGINE
    # -------------------------------------------------

    attack_type, matched_brand = classify_brand_relation(
        domain, subdomain, registered_domain
    )

    if attack_type == "typosquatting":
        triggers.append({
            "rule": "Typosquatted domain",
            "category": "brand"
        })

    elif attack_type == "impersonation":
        triggers.append({
            "rule": "Brand impersonation",
            "category": "brand"
        })

    elif attack_type == "subdomain_misuse":
        triggers.append({
            "rule": "Brand in subdomain misuse",
            "category": "brand"
        })

    # exact_match → do nothing

        # -------------------------------------------------
    # 3️⃣ GENERIC STRUCTURAL / LINGUISTIC CHECKS
    # Apply ONLY to non-verified domains
    # -------------------------------------------------

    if not is_verified_brand_domain:

        domain_tokens = tokenize(domain.replace("-", " "))
        tokens = domain_tokens + tokenize(subdomain) + tokenize(path) + tokenize(query)

        # URL length
        if reputation_score < 25:
            if url_length > 120:
                triggers.append({"rule": "Very long URL", "category": "structural"})
            elif url_length > 75:
                triggers.append({"rule": "Long URL", "category": "structural"})

        # Keyword clustering
        auth_count = sum(1 for t in tokens if t in AUTH_KEYWORDS)
        urgency_count = sum(1 for t in tokens if t in URGENCY_KEYWORDS)

        if reputation_score < 25:
            if auth_count >= 1:
                triggers.append({"rule": "Authentication keyword", "category": "keyword"})
            if urgency_count >= 1:
                triggers.append({"rule": "Urgency keyword", "category": "keyword"})

        # Hyphen abuse
        if reputation_score < 25:
            if domain.count("-") >= 2:
                triggers.append({"rule": "Multiple hyphen usage", "category": "structural"})

        # Digit density heuristic
        if reputation_score < 25:
            digits = sum(c.isdigit() for c in domain)
            if len(domain) > 0 and digits / len(domain) > 0.3:
                triggers.append({"rule": "High digit density in domain", "category": "structural"})

        # Entropy check
        entropy_target = path + query
        if reputation_score < 30:
            if shannon_entropy(entropy_target) > 4.0:
                triggers.append({"rule": "High entropy URL", "category": "obfuscation"})
    return triggers