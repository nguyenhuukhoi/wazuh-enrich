#!/usr/bin/env python3
import argparse
import csv
import json
import re
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator
from urllib.request import Request, urlopen

import yaml


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)
GITHUB_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$", re.IGNORECASE)


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


def read_bytes(url: str) -> bytes:
    request = Request(
        url,
        headers={"User-Agent": "wazuh-enrich-poc-feed-builder/1.0"},
    )
    with urlopen(request, timeout=120) as response:
        return response.read()


def github_default_branch(owner: str, repo: str) -> str:
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    data = json.loads(read_text(api_url))
    return str(data.get("default_branch") or "main")


@contextmanager
def source_directory(path_or_url: str) -> Iterator[Path]:
    source = str(path_or_url)
    if source.startswith(("http://", "https://")):
        archive_url = source
        match = GITHUB_REPO_RE.match(source)
        if match:
            owner, repo = match.groups()
            branch = github_default_branch(owner, repo)
            archive_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        with tempfile.TemporaryDirectory(prefix="wazuh-poc-feed-") as tmpdir:
            archive = Path(tmpdir) / "source.zip"
            archive.write_bytes(read_bytes(archive_url))
            extract_dir = Path(tmpdir) / "src"
            extract_dir.mkdir()
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(extract_dir)
            children = [child for child in extract_dir.iterdir() if child.is_dir()]
            yield children[0] if len(children) == 1 else extract_dir
        return

    path = Path(source)
    if path.is_file() and path.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(prefix="wazuh-poc-feed-") as tmpdir:
            extract_dir = Path(tmpdir) / "src"
            extract_dir.mkdir()
            with zipfile.ZipFile(path) as zf:
                zf.extractall(extract_dir)
            children = [child for child in extract_dir.iterdir() if child.is_dir()]
            yield children[0] if len(children) == 1 else extract_dir
        return

    yield path


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


def build_poc_feed(
    output: Path,
    exploitdb_csv: str | None = None,
    nuclei_templates: str | None = None,
    poc_in_github: str | None = None,
    trickest_cve: str | None = None,
) -> int:
    entries: list[PocEntry] = []
    if exploitdb_csv:
        entries.extend(exploitdb_entries(exploitdb_csv))
    if nuclei_templates:
        with source_directory(nuclei_templates) as source_dir:
            entries.extend(nuclei_entries(source_dir))
    if poc_in_github:
        with source_directory(poc_in_github) as source_dir:
            entries.extend(poc_in_github_entries(source_dir))
    if trickest_cve:
        with source_directory(trickest_cve) as source_dir:
            entries.extend(trickest_entries(source_dir))
    if not entries:
        return 0
    return write_csv(entries, output)


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
    count = build_poc_feed(
        output=Path(args.output),
        exploitdb_csv=args.exploitdb_csv,
        nuclei_templates=args.nuclei_templates,
        poc_in_github=args.poc_in_github,
        trickest_cve=args.trickest_cve,
    )
    if count == 0:
        print("No PoC metadata entries found. Provide at least one source.", file=sys.stderr)
        return 2

    print(f"Wrote {count} PoC metadata rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
