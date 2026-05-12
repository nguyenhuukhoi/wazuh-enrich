import logging
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from feed_sync import EpssRecord, PocRecord, UbuntuOvalRecord, UbuntuOsvRecord

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
            if ip.is_unspecified or ip.is_loopback or ip.is_link_local:
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
    return 2


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


def exploitability_status(kev: bool, public_poc: bool, epss_score: float) -> str:
    if kev:
        return "exploited_in_wild"
    if public_poc:
        return "public_poc_available"
    if epss_score >= 0.7:
        return "high_epss"
    if epss_score >= 0.3:
        return "medium_epss"
    return "no_known_exploit"


def exposure_status(package_name: str, os_kernel: str = "") -> str:
    package = package_name or ""
    if re.match(r"^linux-image-\d", package):
        kernel_release = package.removeprefix("linux-image-")
        if os_kernel and (os_kernel == kernel_release or kernel_release in os_kernel):
            return "running_kernel"
        return "kernel_package_installed"
    if re.match(r"^linux-(modules|headers|tools)-\d", package):
        return "kernel_related_package_installed"
    return "package_installed"


def patch_decision(
    verification_status: str,
    fix_available: bool,
    kev: bool,
    public_poc: bool,
    epss_score: float,
    cvss_score: float,
    exposure: str,
) -> str:
    if verification_status == "installed_version_at_or_above_fixed":
        return "no_action"

    vendor_affected = verification_status in {"confirmed_affected", "likely_affected"}
    high_threat = kev or epss_score >= 0.7 or (public_poc and cvss_score >= 7.0)
    important_exposure = exposure == "running_kernel"

    if vendor_affected and (kev or epss_score >= 0.7 or important_exposure and (public_poc or cvss_score >= 8.0)):
        return "patch_now"
    if vendor_affected and public_poc and cvss_score >= 7.0:
        return "patch_now"
    if vendor_affected and fix_available:
        return "patch_scheduled"
    if vendor_affected:
        return "monitor"
    if verification_status in {"vendor_not_found", "needs_manual_check", "not_verified"} and high_threat:
        return "needs_review"
    return "monitor"


def impact_assessment(verification_status: str, exploit_status: str, exposure: str, decision: str) -> str:
    if decision == "patch_now":
        if exploit_status == "exploited_in_wild":
            return "vendor_confirmed_exploited_patch_now"
        if exposure == "running_kernel":
            return "vendor_confirmed_running_kernel_patch_now"
        return "vendor_confirmed_high_threat_patch_now"
    if decision == "patch_scheduled":
        return "vendor_confirmed_patch_available"
    if decision == "no_action":
        return "installed_version_not_vulnerable"
    if decision == "needs_review":
        return "wazuh_finding_vendor_unconfirmed_review"
    return "monitor_vendor_or_exploitability"


UBUNTU_RELEASE_BY_VERSION = {
    "24.04": "noble",
    "22.04": "jammy",
    "20.04": "focal",
    "18.04": "bionic",
    "16.04": "xenial",
}


def ubuntu_release_from_os(os_name: str, os_version: str) -> str:
    text = f"{os_name} {os_version}".lower()
    for release in ["noble", "jammy", "focal", "bionic", "xenial"]:
        if release in text:
            return release
    for version, release in UBUNTU_RELEASE_BY_VERSION.items():
        if version in text:
            return release
    return ""


def verify_ubuntu_impact(
    cve_id: str,
    os_name: str,
    os_version: str,
    package_name: str,
    package_version: str,
    ubuntu_records: dict[tuple[str, str, str], UbuntuOvalRecord] | None,
    ubuntu_osv_records: dict[tuple[str, str, str], UbuntuOsvRecord] | None = None,
) -> dict[str, Any]:
    release = ubuntu_release_from_os(os_name, os_version)
    base = {
        "verification_status": "not_verified",
        "verification_source": "",
        "verification_confidence": "none",
        "vendor_source": "",
        "vendor_advisory_url": "",
        "vendor_fixed_version": "",
        "vendor_severity": "",
        "vendor_status": "",
        "fix_available": False,
        "fix_status": "unknown",
        "ubuntu_release": release,
    }
    if "ubuntu" not in (os_name or "").lower() and not release:
        return base
    if not release:
        base.update(
            {
                "verification_status": "needs_manual_check",
                "verification_confidence": "low",
                "vendor_source": "ubuntu_oval",
            }
        )
        return base
    osv_record = _find_ubuntu_osv_record(release, cve_id, package_name, ubuntu_osv_records)
    if osv_record:
        fixed_version = osv_record.fixed_version
        fix_available = bool(fixed_version)
        status = "likely_affected"
        confidence = "medium"
        fix_status = "no_fix_yet"
        if fix_available:
            fix_status = "fixed_version_available"
            if package_version:
                cmp_result = deb_version_compare(package_version, fixed_version)
                if cmp_result < 0:
                    status = "confirmed_affected"
                    confidence = "high"
                else:
                    status = "installed_version_at_or_above_fixed"
        base.update(
            {
                "verification_status": status,
                "verification_source": "ubuntu_osv",
                "verification_confidence": confidence,
                "vendor_source": "ubuntu_osv",
                "vendor_advisory_url": osv_record.advisory_url,
                "vendor_fixed_version": fixed_version,
                "vendor_severity": osv_record.severity,
                "vendor_status": osv_record.status,
                "fix_available": fix_available,
                "fix_status": fix_status,
                "ubuntu_release": release,
            }
        )
        return base

    oval_record = (ubuntu_records or {}).get((release, cve_id, package_name))
    if not oval_record:
        base.update(
            {
                "verification_status": "vendor_not_found",
                "verification_confidence": "low",
                "verification_source": "ubuntu_oval",
                "vendor_source": "ubuntu_oval",
            }
        )
        return base

    fix_available = bool(oval_record.fixed_version)
    status = "likely_affected"
    confidence = "medium"
    fix_status = "no_fix_yet"
    if fix_available:
        fix_status = "fixed_version_available"
        if package_version:
            cmp_result = deb_version_compare(package_version, oval_record.fixed_version)
            if cmp_result < 0:
                status = "confirmed_affected"
                confidence = "high"
            else:
                status = "installed_version_at_or_above_fixed"
                confidence = "medium"

    base.update(
        {
            "verification_status": status,
            "verification_source": "ubuntu_oval",
            "verification_confidence": confidence,
            "vendor_source": "ubuntu_oval",
            "vendor_advisory_url": oval_record.advisory_url,
            "vendor_fixed_version": oval_record.fixed_version,
            "vendor_severity": oval_record.severity,
            "vendor_status": "fixed_version_available" if fix_available else "affected_no_fixed_version",
            "fix_available": fix_available,
            "fix_status": fix_status,
            "ubuntu_release": release,
        }
    )
    return base


def _find_ubuntu_osv_record(
    release: str,
    cve_id: str,
    package_name: str,
    ubuntu_osv_records: dict[tuple[str, str, str], UbuntuOsvRecord] | None,
) -> UbuntuOsvRecord | None:
    records = ubuntu_osv_records or {}
    for candidate in ubuntu_package_candidates(package_name):
        record = records.get((release, cve_id, candidate))
        if record:
            return record
    return None


def ubuntu_package_candidates(package_name: str) -> list[str]:
    candidates = [package_name]
    if re.match(r"^linux-(image|modules|headers|tools)-\d", package_name or ""):
        candidates.append("linux")
    return list(dict.fromkeys(candidate for candidate in candidates if candidate))


def deb_version_compare(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _split_deb_version(left)
    right_epoch, right_upstream, right_revision = _split_deb_version(right)
    for left_part, right_part in [
        (left_epoch, right_epoch),
        (left_upstream, right_upstream),
        (left_revision, right_revision),
    ]:
        result = _compare_deb_part(left_part, right_part)
        if result:
            return result
    return 0


def _split_deb_version(version: str) -> tuple[str, str, str]:
    epoch = "0"
    rest = str(version or "")
    if ":" in rest:
        epoch, rest = rest.split(":", 1)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def _compare_deb_part(left: str, right: str) -> int:
    left_tokens = _deb_tokens(left)
    right_tokens = _deb_tokens(right)
    for left_token, right_token in zip(left_tokens, right_tokens):
        result = _compare_deb_token(left_token, right_token)
        if result:
            return result
    if len(left_tokens) == len(right_tokens):
        return 0
    return -1 if len(left_tokens) < len(right_tokens) else 1


def _deb_tokens(value: str) -> list[str]:
    return re.findall(r"\d+|[A-Za-z]+|~|[^A-Za-z0-9~]+", value or "")


def _compare_deb_token(left: str, right: str) -> int:
    if left == right:
        return 0
    if left == "~" or right == "~":
        return -1 if left == "~" else 1
    if left.isdigit() and right.isdigit():
        left_int = int(left.lstrip("0") or "0")
        right_int = int(right.lstrip("0") or "0")
        return (left_int > right_int) - (left_int < right_int)
    return (left > right) - (left < right)


def normalize_finding(
    source: dict[str, Any],
    kev_cves: set[str],
    epss_records: dict[str, EpssRecord],
    poc_records: dict[str, PocRecord] | None = None,
    agent_metadata: dict[str, dict[str, Any]] | None = None,
    ubuntu_records: dict[tuple[str, str, str], UbuntuOvalRecord] | None = None,
    ubuntu_osv_records: dict[tuple[str, str, str], UbuntuOsvRecord] | None = None,
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

    os_name = first_path(source, ["host.os.name", "agent.host.os.name", "host.os.full"], "") or metadata.get("os_name", "")
    os_version = first_path(source, ["host.os.version", "agent.host.os.version"], "") or metadata.get("os_version", "")
    os_kernel = first_path(source, ["host.os.kernel", "agent.host.os.kernel"], "") or metadata.get("os_kernel", "")
    package_name = first_path(source, ["package.name"], "")
    package_version = first_path(source, ["package.version"], "")
    verification = verify_ubuntu_impact(
        cve_id,
        os_name,
        os_version,
        package_name,
        package_version,
        ubuntu_records,
        ubuntu_osv_records,
    )
    exploit_status = exploitability_status(kev, poc is not None, epss.score)
    system_exposure = exposure_status(package_name, os_kernel)
    decision = patch_decision(
        str(verification.get("verification_status", "not_verified")),
        bool(verification.get("fix_available")),
        kev,
        poc is not None,
        epss.score,
        cvss_score,
        system_exposure,
    )
    assessment = impact_assessment(
        str(verification.get("verification_status", "not_verified")),
        exploit_status,
        system_exposure,
        decision,
    )

    doc = {
        "cve_id": cve_id,
        "cve_year": cve_year(cve_id),
        "agent_id": agent_id,
        "agent_name": first_path(source, ["agent.name"], "") or metadata.get("agent_name", ""),
        "agent_ip": source_ip or metadata_ip,
        "os_name": os_name,
        "os_version": os_version,
        "os_kernel": os_kernel,
        "package_name": package_name,
        "package_version": package_version,
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
        "exploitability_status": exploit_status,
        "exposure_status": system_exposure,
        "patch_decision": decision,
        "impact_assessment": assessment,
        "recommended_action": recommended_action(
            decision,
            priority,
            kev,
            epss.score,
            bool(verification.get("fix_available")),
            str(verification.get("vendor_fixed_version", "")),
            system_exposure,
        ),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        **verification,
    }
    if poc:
        doc["impact_cve_id"] = cve_id
        doc["impact_agent_id"] = agent_id
        if doc["agent_name"]:
            doc["impact_host"] = doc["agent_name"]
    return doc


def recommended_action(
    decision: str,
    priority: str,
    kev: bool,
    epss_score: float,
    fix_available: bool = False,
    fixed_version: str = "",
    exposure: str = "",
) -> str:
    fixed = f" Len fixed version: {fixed_version}." if fixed_version else ""
    if decision == "patch_now":
        if exposure == "running_kernel":
            return f"Patch kernel ngay va reboot sang kernel da fix.{fixed}"
        if kev:
            return f"Patch hoac mitigate ngay; CVE da co trong CISA KEV.{fixed}"
        return f"Patch som theo chu ky khan cap; exploitability cao tren package vendor-confirmed affected.{fixed}"
    if decision == "patch_scheduled":
        return f"Len lich patch theo maintenance window gan nhat.{fixed}"
    if decision == "monitor":
        if not fix_available:
            return "Theo doi vendor advisory; chua thay fixed version hoac exploitability thap."
        return "Theo doi va patch theo chu ky thong thuong."
    if decision == "no_action":
        return "Khong can patch cho finding nay; installed version dang bang hoac cao hon fixed version vendor."
    if decision == "needs_review":
        return "Can review thu cong: Wazuh co finding nhung vendor metadata chua xac nhan package/release bi anh huong."
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
