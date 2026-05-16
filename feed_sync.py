import csv
import gzip
import hashlib
import io
import json
import logging
import bz2
import re
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

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


@dataclass(frozen=True)
class UbuntuOvalRecord:
    cve_id: str
    release: str
    package_name: str
    fixed_version: str
    severity: str = ""
    title: str = ""
    advisory_url: str = ""
    source_url: str = ""


@dataclass(frozen=True)
class UbuntuOsvRecord:
    cve_id: str
    release: str
    package_name: str
    fixed_version: str = ""
    severity: str = ""
    advisory_url: str = ""
    source_url: str = ""
    record_id: str = ""
    status: str = "affected_no_fixed_version"


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


def parse_ubuntu_oval(payload: bytes | str, release: str, source_url: str = "") -> dict[tuple[str, str, str], UbuntuOvalRecord]:
    raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    if raw.startswith(b"BZh"):
        raw = bz2.decompress(raw)
    root = ElementTree.fromstring(raw)

    objects = _ubuntu_oval_objects(root)
    states = _ubuntu_oval_states(root)
    tests = _ubuntu_oval_tests(root, objects, states)
    records: dict[tuple[str, str, str], UbuntuOvalRecord] = {}

    for definition in root.iter():
        if _local_name(definition.tag) != "definition":
            continue
        cves = _definition_cves(definition)
        if not cves:
            continue
        title = _first_descendant_text(definition, "title")
        severity = _first_descendant_text(definition, "severity")
        advisory_url = _definition_advisory_url(definition)
        test_refs = _definition_test_refs(definition)
        packages = [tests[test_ref] for test_ref in test_refs if test_ref in tests]
        if not packages:
            continue
        for cve_id in cves:
            for package_name, fixed_version in packages:
                if not package_name:
                    continue
                key = (release, cve_id, package_name)
                current = records.get(key)
                if current and current.fixed_version:
                    continue
                records[key] = UbuntuOvalRecord(
                    cve_id=cve_id,
                    release=release,
                    package_name=package_name,
                    fixed_version=fixed_version,
                    severity=severity,
                    title=title,
                    advisory_url=advisory_url,
                    source_url=source_url,
                )
    return records


def parse_ubuntu_osv(
    payload: bytes | str,
    source_url: str = "",
    include_binary_packages: bool = False,
    releases: set[str] | None = None,
    binary_package_filter: set[tuple[str, str, str]] | None = None,
) -> dict[tuple[str, str, str], UbuntuOsvRecord]:
    raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    records: dict[tuple[str, str, str], UbuntuOsvRecord] = {}
    if raw.lstrip().startswith(b"{"):
        _merge_ubuntu_osv_record(
            records,
            json.loads(raw),
            source_url,
            include_binary_packages,
            releases,
            binary_package_filter,
        )
        return records

    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            extracted = archive.extractfile(member)
            if not extracted:
                continue
            try:
                data = json.loads(extracted.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                LOG.warning("ubuntu_osv_record_malformed member=%s error=%s", member.name, exc)
                continue
            _merge_ubuntu_osv_record(
                records,
                data,
                source_url,
                include_binary_packages,
                releases,
                binary_package_filter,
            )
    return records


def _merge_ubuntu_osv_record(
    records: dict[tuple[str, str, str], UbuntuOsvRecord],
    data: dict[str, Any],
    source_url: str,
    include_binary_packages: bool = False,
    releases: set[str] | None = None,
    binary_package_filter: set[tuple[str, str, str]] | None = None,
) -> None:
    if data.get("withdrawn"):
        return
    cve_id = _ubuntu_osv_cve_id(data)
    if not cve_id:
        return
    severity = _ubuntu_osv_severity(data)
    advisory_url = _ubuntu_osv_advisory_url(data, cve_id)
    record_id = str(data.get("id", ""))
    for affected in data.get("affected", []):
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        source_package = str(package.get("name") or "")
        release = _ubuntu_release_from_ecosystem(str(package.get("ecosystem") or ""))
        if not source_package or not release:
            continue
        if releases is not None and release not in releases:
            continue
        fixed_version = _ubuntu_osv_fixed_version(affected)
        status = "fixed_version_available" if fixed_version else "affected_no_fixed_version"
        packages = {source_package: fixed_version}
        if include_binary_packages:
            for binary in (affected.get("ecosystem_specific") or {}).get("binaries", []) or []:
                if not isinstance(binary, dict):
                    continue
                binary_name = str(binary.get("binary_name") or "")
                if binary_name:
                    binary_key = (release, cve_id, binary_name)
                    if binary_package_filter is None or binary_key in binary_package_filter:
                        packages[binary_name] = str(binary.get("binary_version") or fixed_version or "")
        for package_name, package_fixed_version in packages.items():
            key = (release, cve_id, package_name)
            current = records.get(key)
            if current and current.fixed_version:
                continue
            records[key] = UbuntuOsvRecord(
                cve_id=cve_id,
                release=release,
                package_name=package_name,
                fixed_version=package_fixed_version,
                severity=severity,
                advisory_url=advisory_url,
                source_url=source_url,
                record_id=record_id,
                status=status,
            )


def _ubuntu_osv_cve_id(data: dict[str, Any]) -> str:
    for value in data.get("upstream", []) + data.get("aliases", []):
        cve_id = str(value).upper()
        if cve_id.startswith("CVE-"):
            return cve_id
    record_id = str(data.get("id", "")).upper()
    if record_id.startswith("UBUNTU-CVE-"):
        return record_id.replace("UBUNTU-", "", 1)
    return ""


def _ubuntu_release_from_ecosystem(ecosystem: str) -> str:
    match = re.search(r"(\d{2}\.\d{2})", ecosystem)
    if not match:
        return ""
    return {
        "24.04": "noble",
        "22.04": "jammy",
        "20.04": "focal",
        "18.04": "bionic",
        "16.04": "xenial",
    }.get(match.group(1), "")


def _ubuntu_osv_fixed_version(affected: dict[str, Any]) -> str:
    for range_info in affected.get("ranges", []) or []:
        for event in range_info.get("events", []) or []:
            fixed = event.get("fixed")
            if fixed:
                return str(fixed)
    return ""


def _ubuntu_osv_severity(data: dict[str, Any]) -> str:
    for severity in data.get("severity", []) or []:
        if severity.get("type") == "Ubuntu":
            return str(severity.get("score") or "")
    return ""


def _ubuntu_osv_advisory_url(data: dict[str, Any], cve_id: str) -> str:
    cve_url = ""
    for reference in data.get("references", []) or []:
        url = str(reference.get("url") or "")
        ref_type = str(reference.get("type") or "")
        if ref_type == "ADVISORY" and "ubuntu.com/security/notices" in url:
            return url
        if f"ubuntu.com/security/{cve_id}" in url:
            cve_url = url
    return cve_url or f"https://ubuntu.com/security/{cve_id}"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _first_descendant_text(element: ElementTree.Element, local_name: str) -> str:
    for child in element.iter():
        if _local_name(child.tag) == local_name and child.text:
            return child.text.strip()
    return ""


def _ubuntu_oval_objects(root: ElementTree.Element) -> dict[str, str]:
    objects: dict[str, str] = {}
    for element in root.iter():
        if not _local_name(element.tag).endswith("_object"):
            continue
        object_id = element.attrib.get("id")
        package_name = _first_descendant_text(element, "name")
        if object_id and package_name:
            objects[object_id] = package_name
    return objects


def _ubuntu_oval_states(root: ElementTree.Element) -> dict[str, str]:
    states: dict[str, str] = {}
    for element in root.iter():
        if not _local_name(element.tag).endswith("_state"):
            continue
        state_id = element.attrib.get("id")
        fixed_version = _first_descendant_text(element, "evr")
        if state_id and fixed_version:
            states[state_id] = fixed_version
    return states


def _ubuntu_oval_tests(
    root: ElementTree.Element,
    objects: dict[str, str],
    states: dict[str, str],
) -> dict[str, tuple[str, str]]:
    tests: dict[str, tuple[str, str]] = {}
    for element in root.iter():
        if not _local_name(element.tag).endswith("_test"):
            continue
        test_id = element.attrib.get("id")
        object_ref = ""
        state_ref = ""
        for child in element:
            child_name = _local_name(child.tag)
            if child_name == "object":
                object_ref = child.attrib.get("object_ref", "")
            elif child_name == "state":
                state_ref = child.attrib.get("state_ref", "")
        if test_id and object_ref in objects:
            tests[test_id] = (objects[object_ref], states.get(state_ref, ""))
    return tests


def _definition_cves(definition: ElementTree.Element) -> set[str]:
    cves: set[str] = set()
    for element in definition.iter():
        for attr in ("ref_id", "name"):
            value = str(element.attrib.get(attr, "")).upper()
            if value.startswith("CVE-"):
                cves.add(value)
        if _local_name(element.tag) == "cve" and element.text:
            value = element.text.strip().upper()
            if value.startswith("CVE-"):
                cves.add(value)
    return cves


def _definition_advisory_url(definition: ElementTree.Element) -> str:
    for element in definition.iter():
        ref_url = element.attrib.get("ref_url", "")
        ref_id = element.attrib.get("ref_id", "")
        if "ubuntu.com/security/notices" in ref_url or ref_id.startswith("USN-"):
            return ref_url
    for element in definition.iter():
        ref_url = element.attrib.get("ref_url", "")
        if ref_url:
            return ref_url
    return ""


def _definition_test_refs(definition: ElementTree.Element) -> set[str]:
    return {
        str(element.attrib["test_ref"])
        for element in definition.iter()
        if "test_ref" in element.attrib
    }


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
        ubuntu_oval: dict[str, Any] | None = None,
        ubuntu_osv_binary_package_filter: set[tuple[str, str, str]] | None = None,
    ):
        self.cache_dir = cache_dir
        self.kev_url = kev_url
        self.epss_url = epss_url
        self.timeout = timeout
        self.kev_file = kev_file
        self.poc_file = poc_file
        self.ubuntu_oval = ubuntu_oval or {}
        self.ubuntu_osv_binary_package_filter = ubuntu_osv_binary_package_filter
        self.kev_cache = cache_dir / "cisa_kev.json"
        self.epss_cache = cache_dir / "epss_scores-current.csv.gz"
        self.poc_cache = cache_dir / "cve_poc.csv"
        self.ubuntu_cache_dir = cache_dir / "ubuntu-oval"
        self.ubuntu_osv_cache = cache_dir / "ubuntu-osv" / "osv-all.tar.xz"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ubuntu_cache_dir.mkdir(parents=True, exist_ok=True)
        self.ubuntu_osv_cache.parent.mkdir(parents=True, exist_ok=True)

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

    def sync_ubuntu_oval(self, force: bool = False) -> dict[tuple[str, str, str], UbuntuOvalRecord]:
        if not self.ubuntu_oval.get("enabled"):
            return {}
        records: dict[tuple[str, str, str], UbuntuOvalRecord] = {}
        for release in self.ubuntu_oval.get("releases", []):
            release_name = str(release).strip()
            if not release_name:
                continue
            url = self._ubuntu_oval_url(release_name)
            cache = self.ubuntu_cache_dir / f"com.ubuntu.{release_name}.usn.oval.xml.bz2"
            if force or not self._fresh(cache, timedelta(hours=int(self.ubuntu_oval.get("max_age_hours", 24)))):
                LOG.info("sync_ubuntu_oval release=%s url=%s", release_name, url)
                payload = self._read_or_download(url)
                parsed = parse_ubuntu_oval(payload, release_name, source_url=url)
                self._atomic_write(cache, payload)
                records.update(parsed)
            else:
                records.update(parse_ubuntu_oval(cache.read_bytes(), release_name, source_url=url))
        return records

    def load_ubuntu_oval(self) -> dict[tuple[str, str, str], UbuntuOvalRecord]:
        if not self.ubuntu_oval.get("enabled"):
            return {}
        records: dict[tuple[str, str, str], UbuntuOvalRecord] = {}
        for release in self.ubuntu_oval.get("releases", []):
            release_name = str(release).strip()
            if not release_name:
                continue
            cache = self.ubuntu_cache_dir / f"com.ubuntu.{release_name}.usn.oval.xml.bz2"
            if cache.exists():
                records.update(parse_ubuntu_oval(cache.read_bytes(), release_name, source_url=self._ubuntu_oval_url(release_name)))
        return records

    def sync_ubuntu_osv(self, force: bool = False) -> dict[tuple[str, str, str], UbuntuOsvRecord]:
        if not self.ubuntu_oval.get("osv_enabled", self.ubuntu_oval.get("enabled", False)):
            return {}
        url = self._ubuntu_osv_url()
        max_age = timedelta(hours=int(self.ubuntu_oval.get("osv_max_age_hours", self.ubuntu_oval.get("max_age_hours", 24))))
        if force or not self._fresh(self.ubuntu_osv_cache, max_age):
            LOG.info("sync_ubuntu_osv url=%s", url)
            payload = self._read_or_download(url)
            records = parse_ubuntu_osv(
                payload,
                source_url=url,
                include_binary_packages=self._ubuntu_osv_include_binary_packages(),
                releases=self._ubuntu_osv_releases(),
                binary_package_filter=self.ubuntu_osv_binary_package_filter,
            )
            self._atomic_write(self.ubuntu_osv_cache, payload)
            return records
        return self.load_ubuntu_osv()

    def load_ubuntu_osv(self) -> dict[tuple[str, str, str], UbuntuOsvRecord]:
        if not self.ubuntu_oval.get("osv_enabled", self.ubuntu_oval.get("enabled", False)):
            return {}
        if not self.ubuntu_osv_cache.exists():
            return {}
        return parse_ubuntu_osv(
            self.ubuntu_osv_cache.read_bytes(),
            source_url=self._ubuntu_osv_url(),
            include_binary_packages=self._ubuntu_osv_include_binary_packages(),
            releases=self._ubuntu_osv_releases(),
            binary_package_filter=self.ubuntu_osv_binary_package_filter,
        )

    def sync_all(self, force: bool = False) -> tuple[set[str], dict[str, EpssRecord], dict[str, PocRecord]]:
        return self.sync_kev(force=force), self.sync_epss(force=force), self.sync_poc()

    def fingerprints(self) -> dict[str, str | None]:
        return {
            "kev": self._file_sha256(self.kev_cache),
            "epss": self._file_sha256(self.epss_cache),
            "poc": self._file_sha256(self.poc_cache),
            "ubuntu_osv": self._file_sha256(self.ubuntu_osv_cache),
            **{
                f"ubuntu_oval_{path.stem}": self._file_sha256(path)
                for path in sorted(self.ubuntu_cache_dir.glob("*.xml.bz2"))
            },
        }

    def _download(self, url: str) -> bytes:
        headers = {
            "Accept": "application/json,text/csv,application/gzip,*/*",
            "User-Agent": "wazuh-enrich/1.0 (+https://github.com/nguyenhuukhoi/wazuh-enrich)",
        }
        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        return response.content

    def _read_or_download(self, url_or_path: str) -> bytes:
        if url_or_path.startswith(("http://", "https://")):
            return self._download(url_or_path)
        return Path(url_or_path).read_bytes()

    def _ubuntu_oval_url(self, release: str) -> str:
        urls = self.ubuntu_oval.get("urls", {}) or {}
        if release in urls and urls[release]:
            return str(urls[release])
        base_url = str(
            self.ubuntu_oval.get("base_url")
            or "https://security-metadata.canonical.com/oval"
        ).rstrip("/")
        return f"{base_url}/com.ubuntu.{release}.usn.oval.xml.bz2"

    def _ubuntu_osv_url(self) -> str:
        return str(
            self.ubuntu_oval.get("osv_url")
            or "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
        )

    def _ubuntu_osv_include_binary_packages(self) -> bool:
        return str(self.ubuntu_oval.get("osv_include_binary_packages", False)).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _ubuntu_osv_releases(self) -> set[str] | None:
        releases = {
            str(release).strip()
            for release in self.ubuntu_oval.get("releases", [])
            if str(release).strip()
        }
        return releases or None

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
