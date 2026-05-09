from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def _min_dt(values: list[str | None]) -> str | None:
    clean = [value for value in values if value]
    return min(clean) if clean else None


def _max_dt(values: list[str | None]) -> str | None:
    clean = [value for value in values if value]
    return max(clean) if clean else None


def _top(counter: Counter[str], limit: int = 10) -> list[str]:
    return [item for item, _count in counter.most_common(limit) if item]


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
        summaries.append(
            {
                "cve_id": cve_id,
                "cve_year": highest.get("cve_year"),
                "priority": priorities[0] if priorities else "P3",
                "kev": any(bool(doc.get("kev")) for doc in docs),
                "epss_score": max(float(doc.get("epss_score", 0.0)) for doc in docs),
                "epss_percentile": max(float(doc.get("epss_percentile", 0.0)) for doc in docs),
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
                "cvss_score": max(float(doc.get("cvss_score", 0.0)) for doc in docs),
                "affected_hosts_count": len(hosts),
                "affected_packages": _top(packages),
                "first_detected_at": _min_dt([doc.get("first_detected_at") or doc.get("detected_at") for doc in docs]),
                "last_detected_at": _max_dt([doc.get("last_detected_at") or doc.get("detected_at") for doc in docs]),
                "risk_score": max(float(doc.get("risk_score", 0.0)) for doc in docs),
                "reason": highest.get("reason", ""),
                "updated_at": now,
            }
        )
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
                "p0_count": len({doc["cve_id"] for doc in docs if doc.get("priority") == "P0"}),
                "p1_count": len({doc["cve_id"] for doc in docs if doc.get("priority") == "P1"}),
                "kev_count": len({doc["cve_id"] for doc in docs if doc.get("kev")}),
                "highest_epss": max(float(doc.get("epss_score", 0.0)) for doc in docs),
                "highest_cvss": max(float(doc.get("cvss_score", 0.0)) for doc in docs),
                "top_packages": _top(packages),
                "last_scan_time": _max_dt([doc.get("last_detected_at") or doc.get("detected_at") for doc in docs]),
                "updated_at": now,
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
