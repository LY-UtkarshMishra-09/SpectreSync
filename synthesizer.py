"""Decoy trap synthesizer -- generates context-aware honeytokens from scan data."""

import hashlib
import json
import random
import string
from typing import Any
from datetime import datetime, timezone

CANARY_BASE = "/api/canary-hit"

# Common sensitive-key suffixes grouped by category
SUFFIX_POOLS = {
    "secret":   ["SECRET_KEY", "SECRET_ACCESS_KEY", "SECRET_TOKEN", "PRIVATE_KEY"],
    "database": ["DB_URI", "DB_URL", "DB_PASSWORD", "DB_CONNECTION_STRING", "DSN"],
    "token":    ["API_TOKEN", "AUTH_TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN"],
    "key":      ["API_KEY", "ACCESS_KEY", "ENCRYPTION_KEY", "SIGNING_KEY"],
    "generic":  ["BACKUP_CREDENTIALS", "ADMIN_PASSWORD", "SERVICE_ACCOUNT_KEY"],
}

# Realistic fake value templates
VALUE_TEMPLATES = {
    "secret":   "wJalrXUtnFEMI/{rand}",
    "database": "postgresql://admin:{rand}@staging-db.internal:5432/app",
    "token":    "ghp_{rand}",
    "key":      "AKIA{rand}",
    "generic":  "{rand}",
}


def synthesize_traps(
    scan_report: dict[str, Any],
    num_traps: int = 5,
) -> dict[str, Any]:
    """Generate decoy traps that mimic the naming style found in *scan_report*."""
    num_traps = max(3, min(num_traps, 10))

    prefixes = _infer_prefixes(scan_report)
    categories = _pick_categories(scan_report, num_traps)
    traps = []

    for idx, category in enumerate(categories, start=1):
        trap_id = f"trap_{idx:02d}"
        name = _build_trap_name(prefixes, category)
        value = _build_fake_value(category)
        endpoint = f"{CANARY_BASE}?id={trap_id}"
        fingerprint = _fingerprint(trap_id, name)

        traps.append({
            "trap_id": trap_id,
            "variable_name": name,
            "decoy_value": value,
            "category": category,
            "endpoint": endpoint,
            "fingerprint": fingerprint,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })

    return {
        "target": scan_report.get("target", "unknown"),
        "trap_count": len(traps),
        "inferred_prefixes": prefixes,
        "traps": traps,
    }


def _infer_prefixes(report: dict[str, Any]) -> list[str]:
    """Extract common naming prefixes from scanned env vars."""
    prefix_counts: dict[str, int] = {}

    for var in report.get("env_vars", []):
        parts = var["key"].split("_")
        if len(parts) >= 2:
            prefix = parts[0]
            prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1

    # Take the top prefixes, fall back to generic ones
    sorted_prefixes = sorted(prefix_counts, key=prefix_counts.get, reverse=True)
    result = sorted_prefixes[:4] if sorted_prefixes else ["APP", "SVC", "INTERNAL"]
    return result


def _pick_categories(report: dict[str, Any], n: int) -> list[str]:
    """Choose trap categories weighted by what was found in the scan."""
    weights: dict[str, int] = {cat: 1 for cat in SUFFIX_POOLS}

    for var in report.get("env_vars", []):
        key_upper = var["key"].upper()
        if "SECRET" in key_upper:
            weights["secret"] += 2
        if "DB" in key_upper or "DATABASE" in key_upper or "URI" in key_upper:
            weights["database"] += 2
        if "TOKEN" in key_upper:
            weights["token"] += 2
        if "KEY" in key_upper and "SECRET" not in key_upper:
            weights["key"] += 2

    for ck in report.get("config_keys", []):
        if "password" in ck["key_path"].lower() or "secret" in ck["key_path"].lower():
            weights["secret"] += 1
        if "uri" in ck["key_path"].lower() or "host" in ck["key_path"].lower():
            weights["database"] += 1

    pool = []
    for cat, w in weights.items():
        pool.extend([cat] * w)

    selected = []
    while len(selected) < n and pool:
        choice = random.choice(pool)
        selected.append(choice)
        pool = [c for c in pool if c != choice] or list(SUFFIX_POOLS.keys())

    return selected[:n]


def _build_trap_name(prefixes: list[str], category: str) -> str:
    """Assemble a variable name that blends with the repo's style."""
    prefix = random.choice(prefixes)
    suffix = random.choice(SUFFIX_POOLS[category])
    # Optionally insert a contextual middle segment
    middle_options = ["BACKUP", "STAGING", "LEGACY", "INTERNAL", "TEMP", "OLD"]
    if random.random() < 0.5:
        return f"{prefix}_{random.choice(middle_options)}_{suffix}"
    return f"{prefix}_{suffix}"


def _build_fake_value(category: str) -> str:
    """Generate a realistic-looking but fake credential value."""
    rand_part = "".join(random.choices(string.ascii_letters + string.digits, k=20))
    template = VALUE_TEMPLATES.get(category, "{rand}")
    return template.format(rand=rand_part)


def _fingerprint(trap_id: str, name: str) -> str:
    """Produce a short hash to uniquely identify this trap on trigger."""
    raw = f"{trap_id}:{name}:{random.getrandbits(64)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# -- CLI entry point ----------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python synthesizer.py <scanner_output.json>")
        print("       python scanner.py <dir> | python synthesizer.py -")
        sys.exit(1)

    source = sys.argv[1]
    if source == "-":
        data = json.load(sys.stdin)
    else:
        with open(source, encoding="utf-8") as f:
            data = json.load(f)

    output = synthesize_traps(data)
    print(json.dumps(output, indent=2))

