from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _flatten(d: Dict[str, Any], prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = out or {}
    for k, v in d.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            _flatten(v, key, out)
        else:
            out[key] = v
    return out


def export_json(results: List[Dict[str, Any]], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def export_csv(results: List[Dict[str, Any]], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    flattened = [_flatten(r) for r in results]
    # Collect all keys
    keys = sorted({k for row in flattened for k in row.keys()})

    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in flattened:
            writer.writerow(row)
    return p


def mask_password(pw: str) -> str:
    if pw is None:
        return ""
    s = str(pw)
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + ("*" * (len(s) - 2)) + s[-1]
