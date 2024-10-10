#!/usr/bin/env python3
"""CLI: extract IOCs from forensic note files using ttp_lab.ioc_parser."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from ttp_lab.ioc_parser import extract_iocs_from_paths  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract IOCs from text files.")
    ap.add_argument("paths", nargs="+", type=Path, help="Files to scan")
    ap.add_argument("--json", action="store_true", help="Print JSON")
    args = ap.parse_args()
    bundle = extract_iocs_from_paths(args.paths)
    data = {
        "md5": bundle.md5,
        "sha1": bundle.sha1,
        "sha256": bundle.sha256,
        "ipv4": bundle.ipv4,
        "domains": bundle.domains,
        "emails": bundle.emails,
    }
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for k, v in data.items():
            if v:
                print(f"{k}:")
                for x in v:
                    print(f"  {x}")


if __name__ == "__main__":
    main()
