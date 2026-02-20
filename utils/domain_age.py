import whois
from datetime import datetime


def get_domain_age_days(domain: str) -> int | None:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        return (datetime.utcnow() - creation_date).days

    except Exception:
        return None
