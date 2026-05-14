from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
VERIFICATION_ORDER = {
    "confirmed_affected": 0,
    "likely_affected": 1,
    "needs_manual_check": 2,
    "vendor_not_found": 3,
    "installed_version_at_or_above_fixed": 4,
    "not_verified": 5,
}
PATCH_DECISION_ORDER = {
    "patch_now": 0,
    "workaround_active": 1,
    "patch_scheduled": 2,
    "cleanup_old_kernel": 3,
    "needs_review": 4,
    "monitor": 5,
    "no_action": 6,
}


def _min_dt(values: list[str | None]) -> str | None:
    clean = [value for value in values if value]
    return min(clean) if clean else None


def _max_dt(values: list[str | None]) -> str | None:
    clean = [value for value in values if value]
    return max(clean) if clean else None


def _top(counter: Counter[str], limit: int = 10) -> list[str]:
    return [item for item, _count in counter.most_common(limit) if item]


def _highest_verification_status(docs: list[dict[str, Any]]) -> str:
    statuses = {str(doc.get("verification_status", "not_verified")) for doc in docs}
    return sorted(statuses, key=lambda val: VERIFICATION_ORDER.get(val, 99))[0] if statuses else "not_verified"


def _highest_patch_decision(docs: list[dict[str, Any]]) -> str:
    decisions = {str(doc.get("patch_decision", "monitor")) for doc in docs}
    return sorted(decisions, key=lambda val: PATCH_DECISION_ORDER.get(val, 99))[0] if decisions else "monitor"


def _highest_patch_doc(docs: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(
        docs,
        key=lambda doc: (
            PATCH_DECISION_ORDER.get(str(doc.get("patch_decision", "monitor")), 99),
            -float(doc.get("risk_score", 0.0)),
        ),
    )[0]


def _mitigation_status(docs: list[dict[str, Any]]) -> str:
    statuses = {str(doc.get("mitigation_status", "unknown")) for doc in docs}
    if "not_mitigated" in statuses and "mitigated" in statuses:
        return "partially_mitigated"
    if "not_mitigated" in statuses:
        return "not_mitigated"
    if statuses == {"mitigated"}:
        return "mitigated"
    if "mitigated" in statuses:
        return "partially_mitigated"
    return "unknown"


def _workaround_fields(docs: list[dict[str, Any]]) -> dict[str, Any]:
    status = _mitigation_status(docs)
    return {
        "mitigation_status": status,
        "workaround_verified": status == "mitigated",
        "workaround_check_passed": sum(int(doc.get("workaround_check_passed", 0)) for doc in docs),
        "workaround_check_failed": sum(int(doc.get("workaround_check_failed", 0)) for doc in docs),
        "workaround_policy_ids": sorted(
            {item for doc in docs for item in (doc.get("workaround_policy_ids") or []) if item}
        )[:20],
        "workaround_check_ids": sorted(
            {item for doc in docs for item in (doc.get("workaround_check_ids") or []) if item}
        )[:20],
        "workaround_check_titles": sorted(
            {item for doc in docs for item in (doc.get("workaround_check_titles") or []) if item}
        )[:20],
    }


def build_cve_summary(enriched_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in enriched_docs:
        grouped[doc["cve_id"]].append(doc)

    summaries = []
    now = datetime.now(timezone.utc).isoformat()
    for cve_id, docs in grouped.items():
        priorities = sorted({doc["priority"] for doc in docs}, key=lambda val: PRIORITY_ORDER.get(val, 9))
        packages = Counter(str(doc.get("package_name", "")) for doc in docs)
        hosts = {str(doc.get("agent_id", "")) for doc in docs if doc.get("agent_id")}
        highest = max(docs, key=lambda doc: float(doc.get("risk_score", 0.0)))
        patch_doc = _highest_patch_doc(docs)
        public_poc = any(bool(doc.get("public_poc")) for doc in docs)
        patch_decision = _highest_patch_decision(docs)
        summary = {
            "cve_id": cve_id,
            "cve_year": highest.get("cve_year"),
            "priority": priorities[0] if priorities else "P3",
            "patch_decision": patch_decision,
            "exploitability_status": patch_doc.get("exploitability_status", ""),
            "exposure_status": patch_doc.get("exposure_status", ""),
            "impact_assessment": patch_doc.get("impact_assessment", ""),
            "kev": any(bool(doc.get("kev")) for doc in docs),
            "epss_score": max(float(doc.get("epss_score", 0.0)) for doc in docs),
            "epss_percentile": max(float(doc.get("epss_percentile", 0.0)) for doc in docs),
            "public_poc": public_poc,
            "poc_count": max(int(doc.get("poc_count", 0)) for doc in docs),
            "poc_references": sorted(
                {
                    reference
                    for doc in docs
                    for reference in (doc.get("poc_references") or [])
                    if reference
                }
            )[:10],
            "poc_sources": sorted(
                {source for doc in docs for source in (doc.get("poc_sources") or []) if source}
            )[:10],
            "cvss_score": max(float(doc.get("cvss_score", 0.0)) for doc in docs),
            "affected_hosts_count": len(hosts),
            "affected_packages": _top(packages),
            "first_detected_at": _min_dt([doc.get("first_detected_at") or doc.get("detected_at") for doc in docs]),
            "last_detected_at": _max_dt([doc.get("last_detected_at") or doc.get("detected_at") for doc in docs]),
            "risk_score": max(float(doc.get("risk_score", 0.0)) for doc in docs),
            "reason": highest.get("reason", ""),
            "verification_status": _highest_verification_status(docs),
            "fix_available": any(bool(doc.get("fix_available")) for doc in docs),
            "fix_status": "fixed_version_available"
            if any(str(doc.get("fix_status")) == "fixed_version_available" for doc in docs)
            else "unknown",
            "vendor_source": highest.get("vendor_source", ""),
            "vendor_fixed_version": highest.get("vendor_fixed_version", ""),
            "vendor_advisory_url": highest.get("vendor_advisory_url", ""),
            "vendor_severity": highest.get("vendor_severity", ""),
            "vendor_status": highest.get("vendor_status", ""),
            "recommended_action": patch_doc.get("recommended_action", ""),
            "updated_at": now,
            **_workaround_fields(docs),
        }
        if public_poc:
            summary["impact_cve_id"] = cve_id
            summary["impact_agent_id"] = sorted(
                {str(doc.get("agent_id", "")) for doc in docs if doc.get("agent_id")}
            )
            summary["impact_host"] = sorted(
                {str(doc.get("agent_name", "")) for doc in docs if doc.get("agent_name")}
            )
        summaries.append(summary)
    return summaries


def build_host_summary(enriched_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in enriched_docs:
        agent_id = str(doc.get("agent_id", ""))
        if agent_id:
            grouped[agent_id].append(doc)

    summaries = []
    now = datetime.now(timezone.utc).isoformat()
    for agent_id, docs in grouped.items():
        first = docs[0]
        packages = Counter(str(doc.get("package_name", "")) for doc in docs)
        cves = {doc.get("cve_id") for doc in docs if doc.get("cve_id")}
        summaries.append(
            {
                "agent_id": agent_id,
                "agent_name": first.get("agent_name", ""),
                "agent_ip": first.get("agent_ip", ""),
                "os_name": first.get("os_name", ""),
                "os_version": first.get("os_version", ""),
                "total_cves": len(cves),
                "patch_now_count": len({doc["cve_id"] for doc in docs if doc.get("patch_decision") == "patch_now"}),
                "workaround_active_count": len(
                    {doc["cve_id"] for doc in docs if doc.get("patch_decision") == "workaround_active"}
                ),
                "patch_scheduled_count": len({doc["cve_id"] for doc in docs if doc.get("patch_decision") == "patch_scheduled"}),
                "cleanup_old_kernel_count": len({doc["cve_id"] for doc in docs if doc.get("patch_decision") == "cleanup_old_kernel"}),
                "needs_review_count": len({doc["cve_id"] for doc in docs if doc.get("patch_decision") == "needs_review"}),
                "p0_count": len({doc["cve_id"] for doc in docs if doc.get("priority") == "P0"}),
                "p1_count": len({doc["cve_id"] for doc in docs if doc.get("priority") == "P1"}),
                "kev_count": len({doc["cve_id"] for doc in docs if doc.get("kev")}),
                "highest_epss": max(float(doc.get("epss_score", 0.0)) for doc in docs),
                "highest_cvss": max(float(doc.get("cvss_score", 0.0)) for doc in docs),
                "top_packages": _top(packages),
                "last_scan_time": _max_dt([doc.get("last_detected_at") or doc.get("detected_at") for doc in docs]),
                "mitigated_cves_count": len(
                    {doc["cve_id"] for doc in docs if doc.get("mitigation_status") == "mitigated"}
                ),
                "not_mitigated_cves_count": len(
                    {doc["cve_id"] for doc in docs if doc.get("mitigation_status") == "not_mitigated"}
                ),
                "updated_at": now,
            }
        )
    return summaries


def build_host_cve_impact_summary(enriched_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for doc in enriched_docs:
        cve_id = str(doc.get("cve_id", ""))
        agent_id = str(doc.get("agent_id", ""))
        if cve_id and agent_id:
            grouped[(cve_id, agent_id)].append(doc)

    summaries = []
    now = datetime.now(timezone.utc).isoformat()
    for (cve_id, agent_id), docs in grouped.items():
        priorities = sorted({doc["priority"] for doc in docs}, key=lambda val: PRIORITY_ORDER.get(val, 9))
        highest = max(docs, key=lambda doc: float(doc.get("risk_score", 0.0)))
        patch_doc = _highest_patch_doc(docs)
        patch_decision = _highest_patch_decision(docs)
        packages = Counter(str(doc.get("package_name", "")) for doc in docs)
        versions = Counter(str(doc.get("package_version", "")) for doc in docs)
        first = docs[0]
        summaries.append(
            {
                "cve_id": cve_id,
                "impact_cve_id": cve_id,
                "agent_id": agent_id,
                "impact_agent_id": agent_id,
                "agent_name": first.get("agent_name", ""),
                "impact_host": first.get("agent_name", ""),
                "agent_ip": first.get("agent_ip", ""),
                "os_name": first.get("os_name", ""),
                "os_version": first.get("os_version", ""),
                "priority": priorities[0] if priorities else "P3",
                "patch_decision": patch_decision,
                "exploitability_status": patch_doc.get("exploitability_status", ""),
                "exposure_status": patch_doc.get("exposure_status", ""),
                "impact_assessment": patch_doc.get("impact_assessment", ""),
                "kev": any(bool(doc.get("kev")) for doc in docs),
                "public_poc": any(bool(doc.get("public_poc")) for doc in docs),
                "poc_count": max(int(doc.get("poc_count", 0)) for doc in docs),
                "poc_references": sorted(
                    {
                        reference
                        for doc in docs
                        for reference in (doc.get("poc_references") or [])
                        if reference
                    }
                )[:10],
                "poc_sources": sorted(
                    {source for doc in docs for source in (doc.get("poc_sources") or []) if source}
                )[:10],
                "epss_score": max(float(doc.get("epss_score", 0.0)) for doc in docs),
                "epss_percentile": max(float(doc.get("epss_percentile", 0.0)) for doc in docs),
                "cvss_score": max(float(doc.get("cvss_score", 0.0)) for doc in docs),
                "risk_score": max(float(doc.get("risk_score", 0.0)) for doc in docs),
                "affected_packages": _top(packages),
                "affected_package_versions": _top(versions),
                "finding_count": len(docs),
                "first_detected_at": _min_dt([doc.get("first_detected_at") or doc.get("detected_at") for doc in docs]),
                "last_detected_at": _max_dt([doc.get("last_detected_at") or doc.get("detected_at") for doc in docs]),
                "reason": highest.get("reason", ""),
                "recommended_action": patch_doc.get("recommended_action", ""),
                "verification_status": _highest_verification_status(docs),
                "fix_available": any(bool(doc.get("fix_available")) for doc in docs),
                "fix_status": "fixed_version_available"
                if any(str(doc.get("fix_status")) == "fixed_version_available" for doc in docs)
                else "unknown",
                "vendor_source": highest.get("vendor_source", ""),
                "vendor_fixed_version": highest.get("vendor_fixed_version", ""),
                "vendor_advisory_url": highest.get("vendor_advisory_url", ""),
                "vendor_severity": highest.get("vendor_severity", ""),
                "vendor_status": highest.get("vendor_status", ""),
                "updated_at": now,
                **_workaround_fields(docs),
            }
        )
    return summaries


def overview_metrics(
    enriched_docs: list[dict[str, Any]],
    cve_summaries: list[dict[str, Any]],
    host_summaries: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "total_agents": len({doc.get("agent_id") for doc in enriched_docs if doc.get("agent_id")}),
        "vulnerable_agents": len(host_summaries),
        "total_active_cve_findings": len(enriched_docs),
        "unique_cves": len(cve_summaries),
        "p0_cves": len([doc for doc in cve_summaries if doc.get("priority") == "P0"]),
        "p1_cves": len([doc for doc in cve_summaries if doc.get("priority") == "P1"]),
        "kev_cves": len([doc for doc in cve_summaries if doc.get("kev")]),
        "epss_07_cves": len([doc for doc in cve_summaries if float(doc.get("epss_score", 0.0)) >= 0.7]),
    }
