def calculate_reputation(parsed: dict, age_days: int | None) -> int:
    """
    Returns reputation score (0–50).
    Higher = more trustworthy.
    """

    reputation = 0

    registered_domain = parsed.get("registered_domain", "")
    suffix = parsed.get("suffix", "")
    subdomain = parsed.get("subdomain", "")
    domain = parsed.get("domain", "")

    # --- Domain Age Boost ---
    if age_days:
        if age_days > 365 * 5:
            reputation += 20
        elif age_days > 365 * 2:
            reputation += 15
        elif age_days > 365:
            reputation += 10

    # --- Clean TLD Boost ---
    if suffix in {"com", "org", "edu", "gov", "ac", "in"}:
        reputation += 5

    # --- No suspicious subdomain depth ---
    if subdomain.count(".") <= 1:
        reputation += 5

    # --- Domain not hyphenated ---
    if "-" not in domain:
        reputation += 5

    return reputation
