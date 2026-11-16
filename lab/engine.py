"""Small reference evaluator. Rules use the documented lab JSON format, not Sigma."""
import argparse
from collections import defaultdict, deque
from datetime import datetime
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def timestamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return dt


def load_events(path):
    events = []
    seen = set()
    with Path(path).open(encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event must be an object")
                for field in ("record_id", "timestamp", "host", "channel", "provider"):
                    if not isinstance(event.get(field), str) or not event[field].strip():
                        raise ValueError(f"{field} must be a nonempty string")
                if type(event.get("event_id")) is not int:
                    raise ValueError("event_id must be an integer")
                timestamp(event["timestamp"])
                identity = (event["host"], event["channel"], event["record_id"])
                if identity in seen:
                    raise ValueError("duplicate host/channel/record_id")
                seen.add(identity)
                events.append(event)
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
    return events


def load_rules(directory=ROOT / "rules"):
    rules = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(directory).glob("*.json"))]
    if not rules:
        raise ValueError("no rules found")
    ids = set()
    for rule in rules:
        if rule["id"] in ids:
            raise ValueError("duplicate rule id")
        ids.add(rule["id"])
        for field, pattern in rule.get("regex", {}).items():
            re.compile(pattern)
    return rules


def matches(event, rule):
    for field, expected in rule["equals"].items():
        if event.get(field) != expected:
            return False
    for field in rule.get("required", []):
        value = event.get(field)
        if not isinstance(value, str) or not value.strip() or value == "-":
            return False
    for field, pattern in rule.get("regex", {}).items():
        value = event.get(field)
        if not isinstance(value, str) or re.search(pattern, value) is None:
            return False
    return True


def detect(events, rules):
    alerts = []
    ordered = sorted(events, key=lambda e: (timestamp(e["timestamp"]), e["host"], e["record_id"]))
    for rule in rules:
        windows = defaultdict(deque)
        for event in ordered:
            if not matches(event, rule):
                continue
            evidence = [event]
            if "threshold" in rule:
                threshold = rule["threshold"]
                key = tuple(event[field] for field in threshold["group_by"])
                window = windows[key]
                now = timestamp(event["timestamp"])
                while window and (now - timestamp(window[0]["timestamp"])).total_seconds() > threshold["seconds"]:
                    window.popleft()
                was_above = len(window) >= threshold["count"]
                window.append(event)
                if was_above or len(window) < threshold["count"]:
                    continue
                evidence = list(window)
            alerts.append({
                "rule_id": rule["id"], "title": rule["title"],
                "severity": rule["severity"], "attack": rule["attack"],
                "timestamp": event["timestamp"], "host": event["host"],
                "evidence": [{"host": e["host"], "channel": e["channel"], "record_id": e["record_id"]} for e in evidence],
            })
    return sorted(alerts, key=lambda a: (timestamp(a["timestamp"]), a["rule_id"], a["host"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="normalized JSONL events")
    parser.add_argument("--rules", type=Path, default=ROOT / "rules")
    parser.add_argument("--output", type=Path, help="write JSON alerts to this file")
    args = parser.parse_args()
    try:
        result = json.dumps(detect(load_events(args.events), load_rules(args.rules)), indent=2) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            print(result, end="")
    except (OSError, ValueError, KeyError, TypeError, re.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
