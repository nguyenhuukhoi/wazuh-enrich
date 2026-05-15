#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workaround_collector import build_workaround_feed


def read_cve_file(path: str | None) -> list[str]:
    if not path:
        return []
    cves: list[str] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        cves.append(value.split(",", 1)[0].strip())
    return cves


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build cve_workarounds.yaml from trusted vendor workaround pages.")
    parser.add_argument("--output", default="feeds/cve_workarounds.yaml", help="Output YAML path")
    parser.add_argument("--existing-feed", help="Existing feed to merge with output")
    parser.add_argument("--cve", action="append", default=[], help="CVE ID to collect. Can be repeated.")
    parser.add_argument("--cve-file", help="Text file with one CVE per line")
    parser.add_argument("--source", action="append", choices=["ubuntu"], help="Source to use. Default: ubuntu")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout per request")
    parser.add_argument("--no-linked-pages", action="store_true", help="Do not fetch mitigation links found on CVE pages")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cves = [*args.cve, *read_cve_file(args.cve_file)]
    if not cves:
        print("No CVEs provided. Use --cve or --cve-file.", file=sys.stderr)
        return 2
    count = build_workaround_feed(
        cves,
        Path(args.output),
        existing_feed=Path(args.existing_feed) if args.existing_feed else None,
        sources=args.source,
        timeout=args.timeout,
        fetch_linked_pages=not args.no_linked_pages,
    )
    print(f"Wrote {count} workaround metadata rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
