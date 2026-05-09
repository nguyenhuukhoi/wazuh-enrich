import csv
import gzip
import hashlib
import io
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class EpssRecord:
    score: float
    percentile: float


@dataclass(frozen=True)
class PocRecord:
    count: int
    references: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()


def parse_kev_json(payload: bytes | str) -> set[str]:
    raw = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    data = json.loads(raw)
    vulnerabilities = data.get("vulnerabilities", [])
    cves = {
        str(item.get("cveID", "")).upper()
        for item in vulnerabilities
        if item.get("cveID")
    }
    return cves


def parse_epss_csv_gz(payload: bytes) -> dict[str, EpssRecord]:
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as gz:
        text = gz.read().decode("utf-8")
    return parse_epss_csv(text)


def parse_epss_csv(text: str) -> dict[str, EpssRecord]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    reader = csv.DictReader(lines)
    records: dict[str, EpssRecord] = {}
    for row in reader:
        cve = (row.get("cve") or row.get("CVE") or "").strip().upper()
        if not cve:
            continue
        try:
            records[cve] = EpssRecord(
                score=float(row.get("epss", 0.0) or 0.0),
                percentile=float(row.get("percentile", 0.0) or 0.0),
            )
        except ValueError:
            LOG.warning("epss_row_malformed cve=%s row=%s", cve, row)
    return records


def parse_poc_feed(payload: bytes | str, file_name: str = "poc.csv") -> dict[str, PocRecord]:
    raw = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    if file_name.lower().endswith(".json"):
        return parse_poc_json(raw)
    return parse_poc_csv(raw)


def parse_poc_json(text: str) -> dict[str, PocRecord]:
    data = json.loads(text)
    records: dict[str, list[dict[str, str]]] = {}

    if isinstance(data, dict) and "pocs" in data:
        data = data["pocs"]

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            cve = str(item.get("cve") or item.get("cve_id") or item.get("cveID") or "").upper()
            if cve.startswith("CVE-"):
                records.setdefault(cve, []).append(
                    {
                        "reference": str(item.get("url") or item.get("reference") or ""),
                        "source": str(item.get("source") or ""),
                    }
                )
    elif isinstance(data, dict):
        for cve, value in data.items():
            cve_id = str(cve).upper()
            if not cve_id.startswith("CVE-"):
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if isinstance(entry, dict):
                    records.setdefault(cve_id, []).append(
                        {
                            "reference": str(entry.get("url") or entry.get("reference") or ""),
                            "source": str(entry.get("source") or ""),
                        }
                    )
                else:
                    records.setdefault(cve_id, []).append({"reference": str(entry), "source": ""})

    return _build_poc_records(records)


def parse_poc_csv(text: str) -> dict[str, PocRecord]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    reader = csv.DictReader(lines)
    records: dict[str, list[dict[str, str]]] = {}
    for row in reader:
        cve = str(row.get("cve") or row.get("cve_id") or row.get("CVE") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        records.setdefault(cve, []).append(
            {
                "reference": str(row.get("url") or row.get("reference") or row.get("repo") or "").strip(),
                "source": str(row.get("source") or "").strip(),
            }
        )
    return _build_poc_records(records)


def _build_poc_records(raw: dict[str, list[dict[str, str]]]) -> dict[str, PocRecord]:
    records: dict[str, PocRecord] = {}
    for cve, entries in raw.items():
        references = tuple(sorted({entry["reference"] for entry in entries if entry.get("reference")}))
        sources = tuple(sorted({entry["source"] for entry in entries if entry.get("source")}))
        count = len(references) if references else len(entries)
        records[cve] = PocRecord(count=count, references=references[:10], sources=sources[:10])
    return records


class FeedSync:
    def __init__(
        self,
        cache_dir: Path,
        kev_url: str,
        epss_url: str,
        timeout: int = 30,
        kev_file: Path | None = None,
        poc_file: Path | None = None,
    ):
        self.cache_dir = cache_dir
        self.kev_url = kev_url
        self.epss_url = epss_url
        self.timeout = timeout
        self.kev_file = kev_file
        self.poc_file = poc_file
        self.kev_cache = cache_dir / "cisa_kev.json"
        self.epss_cache = cache_dir / "epss_scores-current.csv.gz"
        self.poc_cache = cache_dir / "cve_poc.csv"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def sync_kev(self, force: bool = False) -> set[str]:
        if self.kev_file:
            LOG.info("load_kev_file path=%s", self.kev_file)
            payload = self.kev_file.read_bytes()
            cves = parse_kev_json(payload)
            self._atomic_write(self.kev_cache, payload)
            return cves
        if not force and self._fresh(self.kev_cache, timedelta(hours=1)):
            return self.load_kev()
        LOG.info("sync_kev url=%s", self.kev_url)
        payload = self._download(self.kev_url)
        parse_kev_json(payload)
        self._atomic_write(self.kev_cache, payload)
        return self.load_kev()

    def sync_epss(self, force: bool = False) -> dict[str, EpssRecord]:
        if not force and self._fresh(self.epss_cache, timedelta(hours=24)):
            return self.load_epss()
        LOG.info("sync_epss url=%s", self.epss_url)
        payload = self._download(self.epss_url)
        parse_epss_csv_gz(payload)
        self._atomic_write(self.epss_cache, payload)
        return self.load_epss()

    def load_kev(self) -> set[str]:
        if not self.kev_cache.exists():
            return set()
        return parse_kev_json(self.kev_cache.read_bytes())

    def load_epss(self) -> dict[str, EpssRecord]:
        if not self.epss_cache.exists():
            return {}
        return parse_epss_csv_gz(self.epss_cache.read_bytes())

    def load_poc(self) -> dict[str, PocRecord]:
        if self.poc_cache.exists():
            return parse_poc_feed(self.poc_cache.read_bytes(), self.poc_cache.name)
        if not self.poc_file:
            return {}
        return self.sync_poc()

    def sync_poc(self) -> dict[str, PocRecord]:
        if not self.poc_file:
            LOG.info("sync_poc skipped=true reason=no_poc_file_configured")
            return {}
        LOG.info("load_poc_file path=%s", self.poc_file)
        payload = self.poc_file.read_bytes()
        records = parse_poc_feed(payload, self.poc_file.name)
        self._atomic_write(self.poc_cache, payload)
        return records

    def sync_all(self, force: bool = False) -> tuple[set[str], dict[str, EpssRecord], dict[str, PocRecord]]:
        return self.sync_kev(force=force), self.sync_epss(force=force), self.sync_poc()

    def fingerprints(self) -> dict[str, str | None]:
        return {
            "kev": self._file_sha256(self.kev_cache),
            "epss": self._file_sha256(self.epss_cache),
            "poc": self._file_sha256(self.poc_cache),
        }

    def _download(self, url: str) -> bytes:
        headers = {
            "Accept": "application/json,text/csv,application/gzip,*/*",
            "User-Agent": "wazuh-enrich/1.0 (+https://github.com/nguyenhuukhoi/wazuh-enrich)",
        }
        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        return response.content

    @staticmethod
    def _file_sha256(path: Path) -> str | None:
        if not path.exists():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(payload)
        tmp.replace(path)

    @staticmethod
    def _fresh(path: Path, max_age: timedelta) -> bool:
        if not path.exists():
            return False
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        return datetime.now(timezone.utc) - modified < max_age
