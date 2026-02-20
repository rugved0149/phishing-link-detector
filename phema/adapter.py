import hashlib
from phema.signals import SIGNAL_MAP


def generate_entity_id(normalized_url: str) -> str:
    """
    Deterministic entity_id for correlation.
    Backend can correlate across modules using this.
    """
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def adapt_phishing_triggers(triggers: list, normalized_url: str) -> list:
    """
    Convert phishing detector triggers into PHEMA backend events.
    """
    events = []
    entity_id = generate_entity_id(normalized_url)

    for trigger in triggers:
        rule = trigger.get("rule")
        mapping = SIGNAL_MAP.get(rule)

        if not mapping:
            continue  # ignore unmapped signals

        event = {
            "entity_id": entity_id,
            "entity_type": "session",
            "module": "phishing",
            "signal": mapping["signal"],
            "confidence": mapping["confidence"],
            "severity": mapping["severity"],
            "metadata": trigger.get("metadata", {})
        }

        events.append(event)

    return events
