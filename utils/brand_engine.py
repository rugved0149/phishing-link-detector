from utils.string_utils import levenshtein_distance
from rules.brands import BRANDS
from rules.brand_domains import BRAND_DOMAINS


def is_length_close(domain: str, brand: str) -> bool:
    return abs(len(domain) - len(brand)) <= 2


def is_high_overlap(domain: str, brand: str) -> bool:
    common = sum(1 for c in domain if c in brand)
    ratio = common / max(len(domain), len(brand))
    return ratio >= 0.7


def classify_brand_relation(domain: str, subdomain: str, registered_domain: str):
    """
    Returns:
        (attack_type, matched_brand)
    attack_type can be:
        - exact_match
        - typosquatting
        - impersonation
        - subdomain_misuse
        - None
    """

    for brand in BRANDS:
        official_domains = BRAND_DOMAINS.get(brand, set())

        # ---- Exact official match ----
        if registered_domain in official_domains:
            return "exact_match", brand

        # ---- Subdomain misuse ----
        if brand in subdomain and registered_domain not in official_domains:
            return "subdomain_misuse", brand

        # ---- Embedded brand impersonation ----
        if brand in domain and domain != brand:
            return "impersonation", brand

        # ---- Possible typosquatting gate ----
        if (
            is_length_close(domain, brand)
            and domain[0] == brand[0]
            and is_high_overlap(domain, brand)
        ):
            distance = levenshtein_distance(domain, brand)
            if distance <= 1:
                return "typosquatting", brand

    return None, None
