#!/usr/bin/env python3
import json
from pathlib import Path
from typing import Any


ENRICHED = "wazuh-vuln-enriched-pattern"
CVE_SUMMARY = "wazuh-vuln-cve-summary-pattern"
HOST_SUMMARY = "wazuh-vuln-host-summary-pattern"


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
            "fieldName": "cve_id",
            "indexPatternRefName": "control_0_index",
            "label": "Public PoC CVE impacting system",
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
            "query": "public_poc:true",
        },
        {
            "id": "priority",
            "fieldName": "priority",
            "indexPatternRefName": "control_1_index",
            "label": "Priority",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 10,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "kev",
            "fieldName": "kev",
            "indexPatternRefName": "control_2_index",
            "label": "KEV",
            "type": "list",
            "options": {
                "type": "terms",
                "multiselect": True,
                "size": 2,
                "order": "desc",
                "useTimeFilter": True,
                "ignoreTimeout": False,
            },
            "parent": "",
        },
        {
            "id": "host",
            "fieldName": "agent_name",
            "indexPatternRefName": "control_3_index",
            "label": "Affected host",
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
            "description": "Dropdown filters for public PoC CVEs, priority, KEV, and affected host.",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(index_ref)},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_ref},
            {"name": "control_0_index", "type": "index-pattern", "id": CVE_SUMMARY},
            {"name": "control_1_index", "type": "index-pattern", "id": CVE_SUMMARY},
            {"name": "control_2_index", "type": "index-pattern", "id": CVE_SUMMARY},
            {"name": "control_3_index", "type": "index-pattern", "id": ENRICHED},
        ],
    }


def saved_search(
    object_id: str,
    title: str,
    index_ref: str,
    columns: list[str],
    sort_field: str,
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
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(index_ref, filters=filters)},
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
    add("metric-total-findings", "visualization", 0, 8, 8, 6)
    add("metric-unique-cves", "visualization", 8, 8, 8, 6)
    add("metric-p0-cves", "visualization", 16, 8, 8, 6)
    add("metric-kev-cves", "visualization", 24, 8, 8, 6)
    add("metric-public-poc-cves", "visualization", 32, 8, 8, 6)
    add("metric-vulnerable-agents", "visualization", 40, 8, 8, 6)
    add("search-public-poc", "search", 0, 14, 48, 12)
    add("search-public-poc-hosts", "search", 0, 26, 48, 16)
    add("vis-cves-by-priority", "visualization", 0, 42, 16, 10)
    add("vis-cves-by-year", "visualization", 16, 42, 16, 10)
    add("vis-top-packages", "visualization", 32, 42, 16, 10)
    add("search-cve-impact", "search", 0, 52, 48, 16)
    add("search-host-impact", "search", 0, 68, 48, 14)
    add("search-kev-cves", "search", 0, 82, 48, 12)

    references = []
    panel_ids = [
        ("vis-impact-controls", "visualization"),
        ("metric-total-findings", "visualization"),
        ("metric-unique-cves", "visualization"),
        ("metric-p0-cves", "visualization"),
        ("metric-kev-cves", "visualization"),
        ("metric-public-poc-cves", "visualization"),
        ("metric-vulnerable-agents", "visualization"),
        ("vis-cves-by-priority", "visualization"),
        ("vis-cves-by-year", "visualization"),
        ("vis-top-packages", "visualization"),
        ("search-public-poc", "search"),
        ("search-public-poc-hosts", "search"),
        ("search-cve-impact", "search"),
        ("search-host-impact", "search"),
        ("search-kev-cves", "search"),
    ]
    for index, (panel_id, panel_type) in enumerate(panel_ids, start=1):
        references.append({"name": f"panel_{index}", "type": panel_type, "id": panel_id})

    return {
        "type": "dashboard",
        "id": "wazuh-vuln-enrichment-overview",
        "attributes": {
            "title": "Wazuh Vulnerability Enrichment Overview",
            "description": "KEV, EPSS, PoC, CVE impact, and host impact overview.",
            "panelsJSON": dumps(panels),
            "optionsJSON": dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": references,
    }


def build_objects() -> list[dict[str, Any]]:
    cve_columns = [
        "cve_id",
        "priority",
        "kev",
        "public_poc",
        "poc_count",
        "epss_score",
        "epss_percentile",
        "cvss_score",
        "affected_hosts_count",
        "affected_packages",
        "first_detected_at",
        "last_detected_at",
        "reason",
    ]
    host_columns = [
        "agent_id",
        "agent_name",
        "agent_ip",
        "os_name",
        "os_version",
        "total_cves",
        "p0_count",
        "p1_count",
        "kev_count",
        "highest_epss",
        "highest_cvss",
        "top_packages",
        "last_scan_time",
    ]
    poc_columns = [
        "cve_id",
        "priority",
        "kev",
        "public_poc",
        "poc_count",
        "epss_score",
        "cvss_score",
        "affected_hosts_count",
        "affected_packages",
        "poc_references",
        "reason",
    ]
    poc_host_columns = [
        "cve_id",
        "priority",
        "kev",
        "public_poc",
        "poc_count",
        "agent_id",
        "agent_name",
        "agent_ip",
        "os_name",
        "os_version",
        "package_name",
        "package_version",
        "epss_score",
        "cvss_score",
        "detected_at",
        "poc_references",
        "recommended_action",
    ]
    return [
        index_pattern(ENRICHED, "wazuh-vuln-enriched-*", "detected_at"),
        index_pattern(CVE_SUMMARY, "wazuh-vuln-cve-summary-*", "updated_at"),
        index_pattern(HOST_SUMMARY, "wazuh-vuln-host-summary-*", "updated_at"),
        controls_vis("vis-impact-controls", "Impact Filters", CVE_SUMMARY),
        metric_vis("metric-total-findings", "Total Active Findings", ENRICHED),
        metric_vis("metric-unique-cves", "Unique CVEs", CVE_SUMMARY),
        metric_vis("metric-p0-cves", "P0 CVEs", CVE_SUMMARY, filters=[phrase_filter("priority", "P0", CVE_SUMMARY)]),
        metric_vis("metric-kev-cves", "KEV CVEs", CVE_SUMMARY, filters=[phrase_filter("kev", True, CVE_SUMMARY)]),
        metric_vis(
            "metric-public-poc-cves",
            "Public PoC CVEs",
            CVE_SUMMARY,
            filters=[phrase_filter("public_poc", True, CVE_SUMMARY)],
        ),
        metric_vis("metric-vulnerable-agents", "Vulnerable Agents", HOST_SUMMARY),
        terms_bar_vis("vis-cves-by-priority", "CVE Count by Priority", CVE_SUMMARY, "priority"),
        terms_bar_vis("vis-cves-by-year", "CVE Count by Year", CVE_SUMMARY, "cve_year"),
        terms_bar_vis("vis-top-packages", "Top Affected Packages", CVE_SUMMARY, "affected_packages"),
        saved_search(
            "search-public-poc",
            "Public PoC CVEs Impacting This System",
            CVE_SUMMARY,
            poc_columns,
            "risk_score",
            filters=[phrase_filter("public_poc", True, CVE_SUMMARY)],
        ),
        saved_search(
            "search-public-poc-hosts",
            "Hosts Affected by Public PoC CVEs",
            ENRICHED,
            poc_host_columns,
            "risk_score",
            filters=[phrase_filter("public_poc", True, ENRICHED)],
        ),
        saved_search("search-cve-impact", "CVE Impact Overview", CVE_SUMMARY, cve_columns, "risk_score"),
        saved_search("search-host-impact", "Host Impact Overview", HOST_SUMMARY, host_columns, "p0_count"),
        saved_search("search-kev-cves", "KEV CVEs", CVE_SUMMARY, cve_columns, "risk_score"),
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
