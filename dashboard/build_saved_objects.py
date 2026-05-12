#!/usr/bin/env python3
import json
from pathlib import Path
from typing import Any


ENRICHED = "wazuh-vuln-enriched-pattern"
CVE_SUMMARY = "wazuh-vuln-cve-summary-pattern"
HOST_SUMMARY = "wazuh-vuln-host-summary-pattern"
HOST_CVE_IMPACT = "wazuh-vuln-host-cve-impact-pattern"
PUBLIC_POC_IMPACT_QUERY = "public_poc:true and affected_hosts_count > 0"


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
        },
        {
            "id": "impact_host",
            "fieldName": "impact_host.keyword",
            "indexPatternRefName": "control_1_index",
            "label": "Host impacted by public PoC",
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
            "description": "Dropdown filter for public PoC CVEs currently impacting hosts.",
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
    add("search-public-poc", "search", 0, 8, 24, 18)
    add("search-public-poc-hosts", "search", 24, 8, 24, 18)

    references = []
    panel_ids = [
        ("vis-impact-controls", "visualization"),
        ("search-public-poc", "search"),
        ("search-public-poc-hosts", "search"),
    ]
    for index, (panel_id, panel_type) in enumerate(panel_ids, start=1):
        references.append({"name": f"panel_{index}", "type": panel_type, "id": panel_id})

    return {
        "type": "dashboard",
        "id": "wazuh-vuln-enrichment-overview",
        "attributes": {
            "title": "Wazuh Vulnerability Enrichment Overview",
            "description": "Public PoC CVEs currently impacting this system and the affected hosts.",
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
        "priority",
        "patch_decision",
        "kev",
        "public_poc",
        "poc_count",
        "epss_score",
        "cvss_score",
        "affected_hosts_count",
        "affected_packages",
        "verification_status",
        "exploitability_status",
        "exposure_status",
        "impact_assessment",
        "fix_available",
        "vendor_fixed_version",
        "vendor_advisory_url",
        "vendor_severity",
        "vendor_status",
        "poc_references",
        "reason",
        "recommended_action",
    ]
    poc_host_columns = [
        "cve_id",
        "priority",
        "patch_decision",
        "kev",
        "public_poc",
        "poc_count",
        "agent_id",
        "agent_name",
        "agent_ip",
        "os_name",
        "os_version",
        "affected_packages",
        "affected_package_versions",
        "verification_status",
        "exploitability_status",
        "exposure_status",
        "impact_assessment",
        "fix_available",
        "vendor_fixed_version",
        "vendor_advisory_url",
        "vendor_severity",
        "vendor_status",
        "finding_count",
        "epss_score",
        "cvss_score",
        "last_detected_at",
        "poc_references",
        "recommended_action",
    ]
    return [
        index_pattern(ENRICHED, "wazuh-vuln-enriched-*", "enriched_at"),
        index_pattern(CVE_SUMMARY, "wazuh-vuln-cve-summary-*", "updated_at"),
        index_pattern(HOST_CVE_IMPACT, "wazuh-vuln-host-cve-impact-*", "updated_at"),
        controls_vis("vis-impact-controls", "Impact Filters", HOST_CVE_IMPACT),
        saved_search(
            "search-public-poc",
            "Public PoC CVEs Impacting This System",
            CVE_SUMMARY,
            poc_columns,
            "risk_score",
            filters=[phrase_filter("public_poc", True, CVE_SUMMARY), range_filter("affected_hosts_count", 1, CVE_SUMMARY)],
        ),
        saved_search(
            "search-public-poc-hosts",
            "Hosts Affected by Public PoC CVEs",
            HOST_CVE_IMPACT,
            poc_host_columns,
            "risk_score",
            filters=[phrase_filter("public_poc", True, HOST_CVE_IMPACT)],
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
