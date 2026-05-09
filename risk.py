import logging
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from feed_sync import EpssRecord, PocRecord

LOG = logging.getLogger(__name__)
CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)


def get_path(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def first_path(data: dict[str, Any], paths: list[str], default: Any = None) -> Any:
    for path in paths:
        value = get_path(data, path)
        if value not in (None, ""):
            return value
    return default


def first_valid_ip(data: dict[str, Any], paths: list[str], default: str = "") -> str:
    candidates: list[tuple[int, str]] = []
    for path in paths:
        value = get_path(data, path)
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item in (None, ""):
                continue
            text = str(item).strip()
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                continue
            if ip.is_unspecified or ip.is_loopback:
                continue
            candidates.append((_ip_rank(ip), text))
    if not candidates:
        return default
    return sorted(candidates, key=lambda candidate: candidate[0])[0][1]


def _ip_rank(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
    if isinstance(ip, ipaddress.IPv4Address) and not ip.is_link_local:
        return 0
    if isinstance(ip, ipaddress.IPv6Address) and not ip.is_link_local:
        return 1
    if isinstance(ip, ipaddress.IPv4Address):
        return 2
    return 3


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def cve_year(cve_id: str) -> int | None:
    match = CVE_YEAR_RE.match(cve_id or "")
    return int(match.group(1)) if match else None


def classify_priority(kev: bool, epss_score: float, cvss_score: float) -> tuple[str, str]:
    if kev:
        return "P0", "CVE nam trong CISA KEV"
    if epss_score >= 0.7 and cvss_score >= 8.0:
        return "P0", "EPSS cao va CVSS cao"
    if epss_score >= 0.3:
        return "P1", "EPSS cao"
    if cvss_score >= 8.0:
        return "P1", "CVSS cao"
    if cvss_score >= 6.0:
        return "P2", "CVSS trung binh"
    return "P3", "exploitability thap"


def calculate_risk_score(kev: bool, epss_score: float, cvss_score: float) -> float:
    return round((epss_score * 50.0) + (cvss_score * 3.0) + (30.0 if kev else 0.0), 2)


def normalize_finding(
    source: dict[str, Any],
    kev_cves: set[str],
    epss_records: dict[str, EpssRecord],
    poc_records: dict[str, PocRecord] | None = None,
    agent_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    cve_id = str(first_path(source, ["vulnerability.id", "vulnerability.cve"], "")).upper()
    if not cve_id.startswith("CVE-"):
        LOG.warning("finding_without_cve source_id=%s", first_path(source, ["id", "_id"], "unknown"))
        return None

    epss = epss_records.get(cve_id, EpssRecord(score=0.0, percentile=0.0))
    poc = (poc_records or {}).get(cve_id)
    cvss_score = as_float(first_path(source, ["vulnerability.score.base", "vulnerability.cvss.cvss3.base_score"]))
    kev = cve_id in kev_cves
    priority, reason = classify_priority(kev, epss.score, cvss_score)
    if poc:
        reason = f"{reason}; public PoC available"
    detected_at = first_path(source, ["vulnerability.detected_at", "@timestamp"], None)

    agent_id = str(first_path(source, ["agent.id"], ""))
    metadata = (agent_metadata or {}).get(agent_id, {})
    source_ip = first_valid_ip(source, ["agent.ip", "agent.host.ip", "host.ip", "related.ip"], "")
    metadata_ip = first_valid_ip(metadata, ["agent_ip", "agent.ip", "agent.host.ip", "host.ip", "related.ip"], "")

    doc = {
        "cve_id": cve_id,
        "cve_year": cve_year(cve_id),
        "agent_id": agent_id,
        "agent_name": first_path(source, ["agent.name"], "") or metadata.get("agent_name", ""),
        "agent_ip": source_ip or metadata_ip,
        "os_name": first_path(source, ["host.os.name", "agent.host.os.name", "host.os.full"], "")
        or metadata.get("os_name", ""),
        "os_version": first_path(source, ["host.os.version", "agent.host.os.version"], "")
        or metadata.get("os_version", ""),
        "package_name": first_path(source, ["package.name"], ""),
        "package_version": first_path(source, ["package.version"], ""),
        "package_architecture": first_path(source, ["package.architecture"], ""),
        "package_type": first_path(source, ["package.type"], ""),
        "kev": kev,
        "epss_score": epss.score,
        "epss_percentile": epss.percentile,
        "public_poc": poc is not None,
        "poc_count": poc.count if poc else 0,
        "poc_references": list(poc.references) if poc else [],
        "poc_sources": list(poc.sources) if poc else [],
        "cvss_score": cvss_score,
        "priority": priority,
        "risk_score": calculate_risk_score(kev, epss.score, cvss_score),
        "reason": reason,
        "detected_at": detected_at,
        "published_at": first_path(source, ["vulnerability.published_at"], None),
        "first_detected_at": detected_at,
        "last_detected_at": detected_at,
        "recommended_action": recommended_action(priority, kev, epss.score),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }
    if poc:
        doc["impact_cve_id"] = cve_id
        doc["impact_agent_id"] = agent_id
        if doc["agent_name"]:
            doc["impact_host"] = doc["agent_name"]
    return doc


def recommended_action(priority: str, kev: bool, epss_score: float) -> str:
    if kev:
        return "Patch hoac mitigate ngay; CVE da co trong CISA KEV."
    if priority == "P0":
        return "Uu tien patch trong chu ky khan cap va xac minh exposure."
    if priority == "P1" or epss_score >= 0.3:
        return "Len lich patch som; uu tien host internet-facing hoac critical."
    if priority == "P2":
        return "Patch theo chu ky bao tri gan nhat."
    return "Theo doi va patch theo chu ky thong thuong."


def epss_bucket(score: float) -> str:
    if score >= 0.7:
        return ">=0.7"
    if score >= 0.3:
        return ">=0.3"
    return "<0.3"
