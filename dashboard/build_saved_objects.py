#!/usr/bin/env python3
import json
from pathlib import Path
from typing import Any


ENRICHED = "wazuh-vuln-enriched-pattern"
CVE_SUMMARY = "wazuh-vuln-cve-summary-pattern"
HOST_SUMMARY = "wazuh-vuln-host-summary-pattern"
HOST_CVE_IMPACT = "wazuh-vuln-host-cve-impact-pattern"
CRITICAL_REAL_IMPACT_QUERY = (
    "patch_decision:patch_now and "
    "(verification_status:confirmed_affected or verification_status:likely_affected) and "
    "(exploitability_status:exploited_in_wild or public_poc:true or epss_score >= 0.7)"
)
NEEDS_REVIEW_QUERY = (
    "patch_decision:needs_review or "
    "((verification_status:vendor_not_found or verification_status:needs_manual_check or verification_status:not_verified) "
    "and (kev:true or public_poc:true or epss_score >= 0.7))"
)
PATCH_SCHEDULED_QUERY = "patch_decision:patch_scheduled or patch_decision:cleanup_old_kernel or patch_decision:workaround_active"


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def index_pattern(object_id: str, title: str, time_field: str) -> dict[str, Any]:
    return {
        "type": "index-pattern",
        "id": object_id,
        "attributes": {
            "title": title,
            "timeFieldName": time_field,
            "fields": "[]",
            "fieldFormatMap": "{}",
            "sourceFilters": "[]",
        },
        "references": [],
    }


def search_source(index_ref: str, query: str = "", filters: list[dict[str, Any]] | None = None) -> str:
    return dumps(
        {
            "query": {"query": query, "language": "kuery"},
            "filter": filters or [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        }
    )


def phrase_filter(field: str, value: Any, index: str) -> dict[str, Any]:
    return {
        "meta": {
            "index": index,
            "type": "phrase",
            "key": field,
            "params": {"query": value},
            "disabled": False,
            "negate": False,
            "alias": None,
        },
        "query": {"match_phrase": {field: value}},
    }


def range_filter(field: str, gte: float, index: str) -> dict[str, Any]:
    return {
        "meta": {
            "index": index,
            "type": "range",
            "key": field,
            "params": {"gte": gte},
            "disabled": False,
            "negate": False,
            "alias": None,
        },
        "range": {field: {"gte": gte}},
    }


def metric_vis(
    object_id: str,
    title: str,
    index_ref: str,
    agg_type: str = "count",
    field: str | None = None,
    filters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if field:
        params["field"] = field
    vis_state = {
        "title": title,
        "type": "metric",
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 100000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48},
            },
        },
        "aggs": [{"id": "1", "enabled": True, "type": agg_type, "schema": "metric", "params": params}],
    }
    return {
        "type": "visualization",
        "id": object_id,
        "attributes": {
            "title": title,
            "visState": dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(index_ref, filters=filters)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_ref}
        ],
    }


def terms_bar_vis(object_id: str, title: str, index_ref: str, field: str) -> dict[str, Any]:
    vis_state = {
        "title": title,
        "type": "histogram",
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True}],
            "valueAxes": [{"id": "ValueAxis-1", "type": "value", "position": "left", "show": True}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "normal", "data": {"label": "Count", "id": "1"}}],
            "addTooltip": True,
            "addLegend": True,
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {"field": field, "orderBy": "1", "order": "desc", "size": 10},
            },
        ],
    }
    return {
        "type": "visualization",
        "id": object_id,
        "attributes": {
            "title": title,
            "visState": dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(index_ref)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_ref}
        ],
    }


def controls_vis(object_id: str, title: str, index_ref: str) -> dict[str, Any]:
    controls = [
        {
            "id": "public_poc_cve",
            "fieldName": "impact_cve_id.keyword",
            "indexPatternRefName": "control_0_index",
            "label": "Dangerous CVE impacting system",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 100,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "impact_host",
            "fieldName": "impact_host.keyword",
            "indexPatternRefName": "control_1_index",
            "label": "Host impacted by dangerous CVE",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 100,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "verification_status",
            "fieldName": "verification_status.keyword",
            "indexPatternRefName": "control_2_index",
            "label": "Ubuntu verification status",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 20,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "fix_status",
            "fieldName": "fix_status.keyword",
            "indexPatternRefName": "control_3_index",
            "label": "Fix status",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 20,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "patch_decision",
            "fieldName": "patch_decision.keyword",
            "indexPatternRefName": "control_4_index",
            "label": "Patch decision",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 20,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "mitigation_status",
            "fieldName": "mitigation_status.keyword",
            "indexPatternRefName": "control_5_index",
            "label": "Mitigation status",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 20,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
    ]
    vis_state = {
        "title": title,
        "type": "input_control_vis",
        "params": {
            "controls": controls,
            "updateFiltersOnChange": False,
            "useTimeFilter": True,
            "pinFilters": False,
        },
        "aggs": [],
    }
    return {
        "type": "visualization",
        "id": object_id,
        "attributes": {
            "title": title,
            "visState": dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "Dropdown filter for dangerous CVEs currently impacting hosts.",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(index_ref)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_ref},
            {"name": "control_0_index", "type": "index-pattern", "id": HOST_CVE_IMPACT},
            {"name": "control_1_index", "type": "index-pattern", "id": HOST_CVE_IMPACT},
            {"name": "control_2_index", "type": "index-pattern", "id": HOST_CVE_IMPACT},
            {"name": "control_3_index", "type": "index-pattern", "id": HOST_CVE_IMPACT},
            {"name": "control_4_index", "type": "index-pattern", "id": HOST_CVE_IMPACT},
            {"name": "control_5_index", "type": "index-pattern", "id": HOST_CVE_IMPACT},
        ],
    }


def saved_search(
    object_id: str,
    title: str,
    index_ref: str,
    columns: list[str],
    sort_field: str,
    query: str = "",
    filters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "type": "search",
        "id": object_id,
        "attributes": {
            "title": title,
            "description": "",
            "columns": columns,
            "sort": [[sort_field, "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(index_ref, query=query, filters=filters)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_ref}
        ],
    }


def dashboard_object() -> dict[str, Any]:
    panels = []

    def add(panel_id: str, panel_type: str, x: int, y: int, w: int, h: int) -> None:
        panel_index = str(len(panels) + 1)
        panels.append(
            {
                "version": "2.13.0",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
                "panelIndex": panel_index,
                "embeddableConfig": {},
                "panelRefName": f"panel_{panel_index}",
                "type": panel_type,
            }
        )

    add("vis-impact-controls", "visualization", 0, 0, 48, 8)
    add("search-critical-real-impact", "search", 0, 8, 48, 14)
    add("search-critical-real-impact-hosts", "search", 0, 22, 48, 14)
    add("search-needs-review", "search", 0, 36, 48, 14)
    add("search-needs-review-hosts", "search", 0, 50, 48, 14)
    add("search-patch-scheduled", "search", 0, 64, 48, 14)
    add("search-patch-scheduled-hosts", "search", 0, 78, 48, 14)

    references = []
    panel_ids = [
        ("vis-impact-controls", "visualization"),
        ("search-critical-real-impact", "search"),
        ("search-critical-real-impact-hosts", "search"),
        ("search-needs-review", "search"),
        ("search-needs-review-hosts", "search"),
        ("search-patch-scheduled", "search"),
        ("search-patch-scheduled-hosts", "search"),
    ]
    for index, (panel_id, panel_type) in enumerate(panel_ids, start=1):
        references.append({"name": f"panel_{index}", "type": panel_type, "id": panel_id})

    return {
        "type": "dashboard",
        "id": "wazuh-vuln-enrichment-overview",
        "attributes": {
            "title": "Wazuh Vulnerability Enrichment Overview",
            "description": "Dangerous CVEs currently impacting this system and the affected hosts.",
            "panelsJSON": dumps(panels),
            "optionsJSON": dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": references,
    }


def build_objects() -> list[dict[str, Any]]:
    poc_columns = [
        "cve_id",
        "patch_decision",
        "impact_assessment",
        "verification_status",
        "exploitability_status",
        "kev",
        "public_poc",
        "fix_available",
        "vendor_fixed_version",
        "recommended_action",
        "mitigation_status",
        "workaround_verified",
        "workaround_check_passed",
        "workaround_check_failed",
        "affected_hosts_count",
        "affected_packages",
        "priority",
        "epss_score",
        "cvss_score",
        "exposure_status",
        "vendor_advisory_url",
        "vendor_severity",
        "vendor_status",
        "poc_count",
        "poc_references",
        "reason",
    ]
    poc_host_columns = [
        "cve_id",
        "patch_decision",
        "impact_assessment",
        "verification_status",
        "exploitability_status",
        "kev",
        "public_poc",
        "fix_available",
        "vendor_fixed_version",
        "recommended_action",
        "mitigation_status",
        "workaround_verified",
        "workaround_check_passed",
        "workaround_check_failed",
        "agent_id",
        "agent_name",
        "agent_ip",
        "affected_packages",
        "affected_package_versions",
        "priority",
        "epss_score",
        "cvss_score",
        "os_name",
        "os_version",
        "exposure_status",
        "vendor_advisory_url",
        "vendor_severity",
        "vendor_status",
        "finding_count",
        "last_detected_at",
        "poc_count",
        "poc_references",
    ]
    return [
        index_pattern(ENRICHED, "wazuh-vuln-enriched-latest", "enriched_at"),
        index_pattern(CVE_SUMMARY, "wazuh-vuln-cve-summary-latest", "updated_at"),
        index_pattern(HOST_CVE_IMPACT, "wazuh-vuln-host-cve-impact-latest", "updated_at"),
        controls_vis("vis-impact-controls", "Impact Filters", HOST_CVE_IMPACT),
        saved_search(
            "search-critical-real-impact",
            "Critical Real Impact CVEs",
            CVE_SUMMARY,
            poc_columns,
            "risk_score",
            query=CRITICAL_REAL_IMPACT_QUERY,
            filters=[range_filter("affected_hosts_count", 1, CVE_SUMMARY)],
        ),
        saved_search(
            "search-critical-real-impact-hosts",
            "Hosts - Critical Real Impact",
            HOST_CVE_IMPACT,
            poc_host_columns,
            "risk_score",
            query=CRITICAL_REAL_IMPACT_QUERY,
        ),
        saved_search(
            "search-needs-review",
            "Needs Review CVEs",
            CVE_SUMMARY,
            poc_columns,
            "risk_score",
            query=NEEDS_REVIEW_QUERY,
            filters=[range_filter("affected_hosts_count", 1, CVE_SUMMARY)],
        ),
        saved_search(
            "search-needs-review-hosts",
            "Hosts - Needs Review",
            HOST_CVE_IMPACT,
            poc_host_columns,
            "risk_score",
            query=NEEDS_REVIEW_QUERY,
        ),
        saved_search(
            "search-patch-scheduled",
            "Patch Scheduled CVEs",
            CVE_SUMMARY,
            poc_columns,
            "risk_score",
            query=PATCH_SCHEDULED_QUERY,
            filters=[range_filter("affected_hosts_count", 1, CVE_SUMMARY)],
        ),
        saved_search(
            "search-patch-scheduled-hosts",
            "Hosts - Patch Scheduled",
            HOST_CVE_IMPACT,
            poc_host_columns,
            "risk_score",
            query=PATCH_SCHEDULED_QUERY,
        ),
        dashboard_object(),
    ]


def main() -> int:
    output = Path(__file__).with_name("wazuh-vuln-enrichment.ndjson")
    objects = build_objects()
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for obj in objects:
            handle.write(dumps(obj) + "\n")
    print(f"Wrote {len(objects)} saved objects to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
