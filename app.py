from core.normalizer import normalize_url
from core.parser import parse_url
from core.analyzer import analyze

from phema.adapter import adapt_phishing_triggers


def check_url(raw_url: str) -> dict:
    """
    PHEMA-compliant phishing signal emitter.
    NO scoring. NO verdicts. NO risk decisions.
    """

    normalized = normalize_url(raw_url)
    parsed = parse_url(normalized)

    # Core phishing detection (granular triggers only)
    triggers = analyze(parsed)

    # Adapt triggers to PHEMA backend events
    events = adapt_phishing_triggers(triggers, normalized)

    return {
        "entity_id": events[0]["entity_id"] if events else None,
        "entity_type": "session",
        "module": "phishing",
        "events": events
    }


def print_events(result: dict):
    print("\nEntity ID:", result["entity_id"])
    print("Module:", result["module"])
    print("Emitted Events:")

    if not result["events"]:
        print("  None")
    else:
        for e in result["events"]:
            print(f"  - signal: {e['signal']}")
            print(f"    confidence: {e['confidence']}")
            print(f"    severity: {e['severity']}")
            print(f"    metadata: {e['metadata']}")
            print()


if __name__ == "__main__":
    print("=== PHEMA Phishing Signal Emitter ===")
    print("Enter one URL per line. Press ENTER on empty line to emit events.\n")

    urls = []
    while True:
        line = input()
        if not line.strip():
            break
        urls.append(line.strip())

    if not urls:
        print("No URLs provided.")
        exit(0)

    for url in urls:
        try:
            result = check_url(url)
            print_events(result)
            print("-" * 70)
        except Exception as e:
            print(f"\nURL: {url}")
            print("Error:", str(e))
            print("-" * 70)
