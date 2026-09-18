"""Refresh the vendored JustDeleteMe dataset.

    python scripts/update_jdm.py

Fetches jdm-contrib/jdm's _data/sites.json (MIT) and keeps only the fields
whoseeme uses, in English. The upstream file carries notes in ~30 languages;
shipping all of them would multiply the package size for text the UI never shows.

The committed src/whoseeme/data/jdm_sites.json is always this script's output,
so it can be regenerated and diffed rather than hand-edited.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

SOURCE = "https://raw.githubusercontent.com/jdm-contrib/jdm/master/_data/sites.json"
LICENSE = "https://raw.githubusercontent.com/jdm-contrib/jdm/master/LICENSE"
KEEP = ("name", "url", "difficulty", "domains", "notes", "email", "email_subject", "email_body")
OUT_DIR = Path(__file__).resolve().parents[1] / "src" / "whoseeme" / "data"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https URL
        return response.read()


def slim(entries: list[dict]) -> list[dict]:
    out = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("domains"):
            continue
        out.append({key: entry[key] for key in KEEP if entry.get(key)})
    out.sort(key=lambda e: e["name"].lower())
    return out


def main() -> int:
    entries = json.loads(fetch(SOURCE).decode("utf-8"))
    slimmed = slim(entries)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "jdm_sites.json").write_text(
        json.dumps(slimmed, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    (OUT_DIR / "LICENSE-JDM").write_bytes(fetch(LICENSE))
    print(f"wrote {len(slimmed)} of {len(entries)} entries to {OUT_DIR / 'jdm_sites.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
