import json
import logging
from pathlib import Path
from typing import Any

import yaml

LOG = logging.getLogger(__name__)


def load_workaround_feed(path: Path | None) -> dict[str, dict[str, Any]]:
    if not path:
        return {}
    if not path.exists():
        LOG.info("workaround_feed_missing path=%s", path)
        return {}
    data = _load_structured_file(path)
    records = data.get("workarounds", data) if isinstance(data, dict) else data
    feed: dict[str, dict[str, Any]] = {}
    if not isinstance(records, list):
        return feed
    for item in records:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cve_id", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        normalized = dict(item)
        normalized["cve_id"] = cve_id
        feed[cve_id] = normalized
    LOG.info("workaround_feed_loaded path=%s records=%s", path, len(feed))
    return feed


def load_workaround_results(path: Path | None) -> dict[tuple[str, str], dict[str, Any]]:
    if not path:
        return {}
    if not path.exists():
        LOG.info("workaround_result_missing path=%s", path)
        return {}
    data = _load_structured_file(path)
    records = data.get("results", data) if isinstance(data, dict) else data
    results: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(records, list):
        return results
    for item in records:
        if not isinstance(item, dict):
            continue
        agent_id = str(item.get("agent_id", "")).strip()
        cve_id = str(item.get("cve_id", "")).strip().upper()
        if not agent_id or not cve_id.startswith("CVE-"):
            continue
        record = normalize_workaround_result(item)
        results[(agent_id, cve_id)] = record
    LOG.info("workaround_results_loaded path=%s records=%s", path, len(results))
    return results


def build_mitigation_records(
    feed: dict[str, dict[str, Any]],
    results: dict[tuple[str, str], dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for cve_id, meta in feed.items():
        merged[("*", cve_id)] = {
            **_metadata_fields(meta),
            "mitigation_status": "unknown",
        }
    for (agent_id, cve_id), result in results.items():
        meta = feed.get(cve_id, {})
        merged[(agent_id, cve_id)] = {
            **_metadata_fields(meta),
            **result,
        }
    return merged


def normalize_workaround_result(item: dict[str, Any]) -> dict[str, Any]:
    verify_status = str(item.get("verify_status", item.get("status", ""))).strip().lower()
    mitigation_status = str(item.get("mitigation_status", "")).strip().lower()
    if not mitigation_status:
        mitigation_status = _status_from_verify(verify_status)
    checks = item.get("checks") if isinstance(item.get("checks"), dict) else {}
    failed_checks = [
        key
        for key, value in checks.items()
        if _check_failed(value)
    ]
    passed_checks = [
        key
        for key, value in checks.items()
        if _check_passed(value)
    ]
    if mitigation_status == "mitigated" and failed_checks:
        mitigation_status = "not_mitigated"
    return {
        "mitigation_status": mitigation_status or "unknown",
        "workaround_verified": mitigation_status == "mitigated",
        "workaround_check_passed": _as_int(item.get("workaround_check_passed"), len(passed_checks)),
        "workaround_check_failed": _as_int(item.get("workaround_check_failed"), len(failed_checks)),
        "workaround_failed_checks": sorted(failed_checks),
        "workaround_passed_checks": sorted(passed_checks),
        "workaround_id": str(item.get("workaround_id", "")).strip(),
        "workaround_source": str(item.get("source", "ansible")).strip() or "ansible",
        "workaround_apply_status": str(item.get("apply_status", "")).strip(),
        "workaround_verify_status": verify_status,
        "workaround_verified_at": str(item.get("verified_at", "")).strip(),
        "workaround_checks": checks,
        "workaround_evidence": item.get("evidence") if isinstance(item.get("evidence"), dict) else {},
    }


def _metadata_fields(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "workaround_available": bool(meta),
        "workaround_id": str(meta.get("workaround_id", "")).strip(),
        "workaround_title": str(meta.get("title", "")).strip(),
        "workaround_source_url": str(meta.get("source_url", meta.get("source", ""))).strip(),
        "workaround_executor": str(meta.get("executor", "")).strip(),
        "workaround_playbook": str(meta.get("playbook", "")).strip(),
        "workaround_notes": str(meta.get("notes", "")).strip(),
    }


def _load_structured_file(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(raw) or {}
    return json.loads(raw or "[]")


def _status_from_verify(verify_status: str) -> str:
    if verify_status in {"passed", "pass", "ok", "success", "verified"}:
        return "mitigated"
    if verify_status in {"failed", "fail", "error", "not_mitigated"}:
        return "not_mitigated"
    return "unknown"


def _check_passed(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "pass", "passed", "ok"}


def _check_failed(value: Any) -> bool:
    if isinstance(value, bool):
        return not value
    return str(value).strip().lower() in {"0", "false", "no", "fail", "failed", "error"}


def _as_int(value: Any, default: int) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default
