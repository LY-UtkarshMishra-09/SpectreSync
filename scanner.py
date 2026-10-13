"""Filesystem scanner -- extracts secrets patterns and config structures."""

import json
import re
from pathlib import Path
from typing import Any

SENSITIVE_FILES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "config.json", "package.json", "settings.json",
    "docker-compose.yml", "docker-compose.yaml",
    ".npmrc", ".pypirc",
}

SENSITIVE_EXTENSIONS = {".env", ".ini", ".cfg", ".toml", ".yaml", ".yml"}

ENV_VAR_PATTERN = re.compile(
    r"^(?P<key>[A-Z][A-Z0-9_]{2,})=(?P<value>.+)$", re.MULTILINE
)

DB_KEY_PATTERNS = re.compile(
    r"(?i)(database|db|mongo|redis|postgres|mysql|sqlite|dsn|connection_string"
    r"|uri|url|host|port|password|secret|token|key|api_key|access_key)"
)


def scan_directory(target: str | Path) -> dict[str, Any]:
    """Walk *target* and return a structured summary of discovered secrets."""
    target = Path(target).resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {target}")

    result: dict[str, Any] = {
        "target": str(target),
        "env_vars": [],
        "config_keys": [],
        "config_structures": [],
        "scanned_files": [],
    }

    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if _is_ignored(path):
            continue
        if path.name in SENSITIVE_FILES or path.suffix in SENSITIVE_EXTENSIONS:
            result["scanned_files"].append(str(path.relative_to(target)))
            _extract(path, target, result)

    return result


def _is_ignored(path: Path) -> bool:
    """Skip vendor dirs and binary files."""
    ignored = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"}
    return bool(set(path.parts) & ignored)


def _extract(path: Path, root: Path, result: dict[str, Any]) -> None:
    """Dispatch extraction by file type."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    rel = str(path.relative_to(root))

    if path.suffix in (".env", "") and path.name.startswith(".env"):
        _extract_env(text, rel, result)
    elif path.suffix == ".json":
        _extract_json(text, rel, result)
    elif path.suffix in (".yaml", ".yml", ".toml", ".ini", ".cfg"):
        _extract_flat_keys(text, rel, result)


def _extract_env(text: str, rel_path: str, result: dict[str, Any]) -> None:
    """Pull KEY=VALUE pairs from dotenv files."""
    for m in ENV_VAR_PATTERN.finditer(text):
        key, value = m.group("key"), m.group("value").strip().strip("\"'")
        entry = {
            "file": rel_path,
            "key": key,
            "value_hint": _mask(value),
            "is_db_related": bool(DB_KEY_PATTERNS.search(key)),
        }
        result["env_vars"].append(entry)


def _extract_json(text: str, rel_path: str, result: dict[str, Any]) -> None:
    """Pull keys from JSON config files, flag sensitive ones."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return

    if not isinstance(data, dict):
        return

    structure = {"file": rel_path, "top_level_keys": list(data.keys())}
    result["config_structures"].append(structure)

    _walk_json(data, rel_path, prefix="", result=result)


def _walk_json(
    obj: Any, rel_path: str, prefix: str, result: dict[str, Any]
) -> None:
    """Recursively find sensitive keys in nested JSON."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if DB_KEY_PATTERNS.search(k):
                result["config_keys"].append({
                    "file": rel_path,
                    "key_path": full_key,
                    "value_hint": _mask(str(v)) if isinstance(v, str) else type(v).__name__,
                })
            _walk_json(v, rel_path, full_key, result)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_json(item, rel_path, f"{prefix}[{i}]", result)


def _extract_flat_keys(text: str, rel_path: str, result: dict[str, Any]) -> None:
    """Scan YAML/TOML/INI for lines that look like sensitive key assignments."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        for sep in ("=", ":", ":="):
            if sep in line:
                key = line.split(sep, 1)[0].strip().strip('"').strip("'")
                if DB_KEY_PATTERNS.search(key):
                    val = line.split(sep, 1)[1].strip().strip('"').strip("'")
                    result["config_keys"].append({
                        "file": rel_path,
                        "key_path": key,
                        "value_hint": _mask(val),
                    })
                break


def _mask(value: str) -> str:
    """Return a partially masked version of a value for safe logging."""
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


# -- CLI entry point ----------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target_directory>")
        sys.exit(1)

    report = scan_directory(sys.argv[1])
    print(json.dumps(report, indent=2))

