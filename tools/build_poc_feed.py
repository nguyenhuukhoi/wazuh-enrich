#!/usr/bin/env python3
import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.request import Request, urlopen

import yaml


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)


@dataclass(frozen=True)
class PocEntry:
    cve: str
    url: str
    source: str


def find_cves(text: str) -> set[str]:
    return {match.group(0).upper() for match in CVE_RE.finditer(text or "")}


def first_url(text: str) -> str:
    match = URL_RE.search(text or "")
    return match.group(0) if match else ""


def read_text(path_or_url: str) -> str:
    if path_or_url.startswith(("http://", "https://")):
        request = Request(
            path_or_url,
            headers={"User-Agent": "wazuh-enrich-poc-feed-builder/1.0"},
        )
        with urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8", errors="replace")
    return Path(path_or_url).read_text(encoding="utf-8", errors="replace")


def exploitdb_entries(csv_path_or_url: str) -> Iterable[PocEntry]:
    text = read_text(csv_path_or_url)
    reader = csv.DictReader(text.splitlines())
    for row in reader:
        row_text = " ".join(str(value or "") for value in row.values())
        cves = find_cves(row_text)
        if not cves:
            continue
        exploit_id = row.get("id") or row.get("EDB-ID") or ""
        file_path = row.get("file") or row.get("File") or ""
        url = f"https://www.exploit-db.com/exploits/{exploit_id}" if exploit_id else ""
        if not url and file_path:
            url = f"https://gitlab.com/exploit-database/exploitdb/-/blob/main/{file_path}"
        for cve in cves:
            yield PocEntry(cve=cve, url=url, source="Exploit-DB")


def nuclei_entries(templates_dir: Path) -> Iterable[PocEntry]:
    for path in templates_dir.rglob("*.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        info = data.get("info") if isinstance(data, dict) else {}
        classification = info.get("classification", {}) if isinstance(info, dict) else {}
        cve_values = classification.get("cve-id", []) if isinstance(classification, dict) else []
        if isinstance(cve_values, str):
            cves = find_cves(cve_values)
        else:
            cves = {str(cve).upper() for cve in cve_values if str(cve).upper().startswith("CVE-")}
        if not cves:
            cves = find_cves(path.name)
        if not cves:
            continue
        references = info.get("reference", []) if isinstance(info, dict) else []
        if isinstance(references, str):
            references = [references]
        url = next((reference for reference in references if str(reference).startswith("http")), "")
        if not url:
            relative = path.as_posix()
            marker = "nuclei-templates/"
            if marker in relative:
                relative = relative.split(marker, 1)[1]
            url = f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{relative}"
        for cve in cves:
            yield PocEntry(cve=cve, url=url, source="ProjectDiscovery nuclei-templates")


def poc_in_github_entries(repo_dir: Path) -> Iterable[PocEntry]:
    for path in repo_dir.rglob("CVE-*.json"):
        cves = find_cves(path.name)
        if not cves:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            url = ""
            if isinstance(item, dict):
                url = str(item.get("html_url") or item.get("url") or item.get("repository") or "")
            if not url:
                url = first_url(json.dumps(item, ensure_ascii=True))
            for cve in cves:
                yield PocEntry(cve=cve, url=url, source="nomi-sec PoC-in-GitHub")


def trickest_entries(repo_dir: Path) -> Iterable[PocEntry]:
    for path in repo_dir.rglob("CVE-*.md"):
        cves = find_cves(path.name)
        if not cves:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        url = first_url(text)
        if not url:
            relative = path.as_posix()
            marker = "cve/"
            if marker in relative:
                relative = relative.split(marker, 1)[1]
            url = f"https://github.com/trickest/cve/blob/main/{relative}"
        for cve in cves:
            yield PocEntry(cve=cve, url=url, source="trickest/cve")


def write_csv(entries: Iterable[PocEntry], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted({(entry.cve, entry.url, entry.source) for entry in entries})
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve", "url", "source"])
        writer.writerows(unique)
    return len(unique)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build cve_poc.csv from trusted public metadata sources without downloading PoC code."
    )
    parser.add_argument("--output", default="feeds/cve_poc.csv", help="Output CSV path")
    parser.add_argument(
        "--exploitdb-csv",
        help="Local path or metadata URL for Exploit-DB files_exploits.csv",
    )
    parser.add_argument("--nuclei-templates", help="Local projectdiscovery/nuclei-templates checkout")
    parser.add_argument("--poc-in-github", help="Local nomi-sec/PoC-in-GitHub checkout")
    parser.add_argument("--trickest-cve", help="Local trickest/cve checkout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    entries: list[PocEntry] = []

    if args.exploitdb_csv:
        entries.extend(exploitdb_entries(args.exploitdb_csv))
    if args.nuclei_templates:
        entries.extend(nuclei_entries(Path(args.nuclei_templates)))
    if args.poc_in_github:
        entries.extend(poc_in_github_entries(Path(args.poc_in_github)))
    if args.trickest_cve:
        entries.extend(trickest_entries(Path(args.trickest_cve)))

    if not entries:
        print("No PoC metadata entries found. Provide at least one source.", file=sys.stderr)
        return 2

    count = write_csv(entries, Path(args.output))
    print(f"Wrote {count} PoC metadata rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
