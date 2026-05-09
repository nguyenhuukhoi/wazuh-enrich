import csv
import gzip
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


class FeedSync:
    def __init__(self, cache_dir: Path, kev_url: str, epss_url: str, timeout: int = 30):
        self.cache_dir = cache_dir
        self.kev_url = kev_url
        self.epss_url = epss_url
        self.timeout = timeout
        self.kev_cache = cache_dir / "cisa_kev.json"
        self.epss_cache = cache_dir / "epss_scores-current.csv.gz"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def sync_kev(self, force: bool = False) -> set[str]:
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

    def sync_all(self, force: bool = False) -> tuple[set[str], dict[str, EpssRecord]]:
        return self.sync_kev(force=force), self.sync_epss(force=force)

    def _download(self, url: str) -> bytes:
        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        return response.content

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
