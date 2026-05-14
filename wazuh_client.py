import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from opensearchpy import OpenSearch, RequestsHttpConnection, helpers

from config import Settings
from risk import finding_key, first_path, first_valid_ip

LOG = logging.getLogger(__name__)


IMPACT_FIELD_MAPPING = {
    "type": "text",
    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
}

KNOWN_AGENT_IP_FIELDS = [
    "agent.host.ip",
    "host.ip",
    "network.ip",
    "interface.ip",
    "related.ip",
    "agent.ip",
]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

SOURCE_FIELDS = [
    "agent.id",
    "agent.name",
    "agent.ip",
    "agent.host.ip",
    "agent.host.os.*",
    "host.ip",
    "host.os.*",
    "related.ip",
    "vulnerability.id",
    "vulnerability.cve",
    "vulnerability.severity",
    "vulnerability.score.base",
    "vulnerability.cvss.cvss3.base_score",
    "vulnerability.detected_at",
    "vulnerability.published_at",
    "package.name",
    "package.version",
    "package.architecture",
    "package.type",
    "@timestamp",
]

AGENT_METADATA_FIELDS = [
    "agent.id",
    "agent.name",
    "agent.host.os.*",
    "host.os.*",
    *KNOWN_AGENT_IP_FIELDS,
]


class WazuhIndexerClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = OpenSearch(
            hosts=[settings.wazuh_indexer_url],
            http_auth=(settings.wazuh_indexer_username, settings.wazuh_indexer_password),
            use_ssl=settings.wazuh_indexer_url.startswith("https://"),
            verify_certs=settings.verify_ssl,
            ca_certs=settings.wazuh_ca_cert or None,
            connection_class=RequestsHttpConnection,
            timeout=settings.request_timeout_seconds,
            max_retries=3,
            retry_on_timeout=True,
        )

    @staticmethod
    def index_name(prefix: str, when: datetime | None = None) -> str:
        current = when or datetime.now(timezone.utc)
        return f"{prefix}-{current:%Y.%m.%d}"

    def ensure_templates(self) -> None:
        templates = {
            "wazuh-vuln-enriched-template": (
                f"{self.settings.enriched_index_prefix}-*",
                {
                    "cve_id": {"type": "keyword"},
                    "finding_key": {"type": "keyword"},
                    "cve_year": {"type": "integer"},
                    "agent_id": {"type": "keyword"},
                    "agent_name": {"type": "keyword"},
                    "agent_ip": {"type": "ip", "ignore_malformed": True},
                    "impact_cve_id": IMPACT_FIELD_MAPPING,
                    "impact_agent_id": IMPACT_FIELD_MAPPING,
                    "impact_host": IMPACT_FIELD_MAPPING,
                    "os_name": {"type": "keyword"},
                    "os_version": {"type": "keyword"},
                    "os_kernel": {"type": "keyword"},
                    "package_name": {"type": "keyword"},
                    "package_version": {"type": "keyword"},
                    "kev": {"type": "boolean"},
                    "epss_score": {"type": "float"},
                    "epss_percentile": {"type": "float"},
                    "public_poc": {"type": "boolean"},
                    "impact_cve_id": IMPACT_FIELD_MAPPING,
                    "impact_agent_id": IMPACT_FIELD_MAPPING,
                    "impact_host": IMPACT_FIELD_MAPPING,
                    "poc_count": {"type": "integer"},
                    "poc_references": {"type": "keyword"},
                    "poc_sources": {"type": "keyword"},
                    "cvss_score": {"type": "float"},
                    "priority": {"type": "keyword"},
                    "patch_decision": {"type": "keyword"},
                    "mitigation_status": {"type": "keyword"},
                    "workaround_verified": {"type": "boolean"},
                    "workaround_check_passed": {"type": "integer"},
                    "workaround_check_failed": {"type": "integer"},
                    "workaround_policy_ids": {"type": "keyword"},
                    "workaround_check_ids": {"type": "keyword"},
                    "workaround_check_titles": {"type": "keyword"},
                    "exploitability_status": {"type": "keyword"},
                    "exposure_status": {"type": "keyword"},
                    "impact_assessment": {"type": "keyword"},
                    "risk_score": {"type": "float"},
                    "reason": {"type": "keyword"},
                    "detected_at": {"type": "date", "ignore_malformed": True},
                    "first_detected_at": {"type": "date", "ignore_malformed": True},
                    "last_detected_at": {"type": "date", "ignore_malformed": True},
                    "enriched_at": {"type": "date", "ignore_malformed": True},
                },
            ),
            "wazuh-vuln-cve-summary-template": (
                f"{self.settings.cve_summary_index_prefix}-*",
                {
                    "cve_id": {"type": "keyword"},
                    "cve_year": {"type": "integer"},
                    "priority": {"type": "keyword"},
                    "patch_decision": {"type": "keyword"},
                    "mitigation_status": {"type": "keyword"},
                    "workaround_verified": {"type": "boolean"},
                    "workaround_check_passed": {"type": "integer"},
                    "workaround_check_failed": {"type": "integer"},
                    "workaround_policy_ids": {"type": "keyword"},
                    "workaround_check_ids": {"type": "keyword"},
                    "workaround_check_titles": {"type": "keyword"},
                    "exploitability_status": {"type": "keyword"},
                    "exposure_status": {"type": "keyword"},
                    "impact_assessment": {"type": "keyword"},
                    "kev": {"type": "boolean"},
                    "epss_score": {"type": "float"},
                    "epss_percentile": {"type": "float"},
                    "public_poc": {"type": "boolean"},
                    "poc_count": {"type": "integer"},
                    "poc_references": {"type": "keyword"},
                    "poc_sources": {"type": "keyword"},
                    "cvss_score": {"type": "float"},
                    "affected_hosts_count": {"type": "integer"},
                    "affected_packages": {"type": "keyword"},
                    "risk_score": {"type": "float"},
                    "first_detected_at": {"type": "date", "ignore_malformed": True},
                    "last_detected_at": {"type": "date", "ignore_malformed": True},
                },
            ),
            "wazuh-vuln-host-summary-template": (
                f"{self.settings.host_summary_index_prefix}-*",
                {
                    "agent_id": {"type": "keyword"},
                    "agent_name": {"type": "keyword"},
                    "agent_ip": {"type": "ip", "ignore_malformed": True},
                    "os_name": {"type": "keyword"},
                    "os_version": {"type": "keyword"},
                    "patch_now_count": {"type": "integer"},
                    "workaround_active_count": {"type": "integer"},
                    "patch_scheduled_count": {"type": "integer"},
                    "cleanup_old_kernel_count": {"type": "integer"},
                    "needs_review_count": {"type": "integer"},
                    "mitigated_cves_count": {"type": "integer"},
                    "not_mitigated_cves_count": {"type": "integer"},
                    "total_cves": {"type": "integer"},
                    "p0_count": {"type": "integer"},
                    "p1_count": {"type": "integer"},
                    "kev_count": {"type": "integer"},
                    "highest_epss": {"type": "float"},
                    "highest_cvss": {"type": "float"},
                    "top_packages": {"type": "keyword"},
                    "last_scan_time": {"type": "date", "ignore_malformed": True},
                },
            ),
            "wazuh-vuln-host-cve-impact-template": (
                f"{self.settings.host_cve_impact_index_prefix}-*",
                {
                    "cve_id": {"type": "keyword"},
                    "impact_cve_id": IMPACT_FIELD_MAPPING,
                    "agent_id": {"type": "keyword"},
                    "impact_agent_id": IMPACT_FIELD_MAPPING,
                    "agent_name": {"type": "keyword"},
                    "impact_host": IMPACT_FIELD_MAPPING,
                    "agent_ip": {"type": "ip", "ignore_malformed": True},
                    "os_name": {"type": "keyword"},
                    "os_version": {"type": "keyword"},
                    "priority": {"type": "keyword"},
                    "patch_decision": {"type": "keyword"},
                    "mitigation_status": {"type": "keyword"},
                    "workaround_verified": {"type": "boolean"},
                    "workaround_check_passed": {"type": "integer"},
                    "workaround_check_failed": {"type": "integer"},
                    "workaround_policy_ids": {"type": "keyword"},
                    "workaround_check_ids": {"type": "keyword"},
                    "workaround_check_titles": {"type": "keyword"},
                    "exploitability_status": {"type": "keyword"},
                    "exposure_status": {"type": "keyword"},
                    "impact_assessment": {"type": "keyword"},
                    "kev": {"type": "boolean"},
                    "public_poc": {"type": "boolean"},
                    "poc_count": {"type": "integer"},
                    "poc_references": {"type": "keyword"},
                    "poc_sources": {"type": "keyword"},
                    "epss_score": {"type": "float"},
                    "epss_percentile": {"type": "float"},
                    "cvss_score": {"type": "float"},
                    "risk_score": {"type": "float"},
                    "affected_packages": {"type": "keyword"},
                    "affected_package_versions": {"type": "keyword"},
                    "finding_count": {"type": "integer"},
                    "first_detected_at": {"type": "date", "ignore_malformed": True},
                    "last_detected_at": {"type": "date", "ignore_malformed": True},
                    "updated_at": {"type": "date", "ignore_malformed": True},
                },
            ),
        }
        for name, (pattern, properties) in templates.items():
            body = {
                "index_patterns": [pattern],
                "template": {
                    "settings": {"number_of_shards": 1, "number_of_replicas": 1},
                    "mappings": {"dynamic": True, "properties": properties},
                },
            }
            try:
                self.client.indices.put_index_template(name=name, body=body)
                LOG.info("index_template_ready name=%s pattern=%s", name, pattern)
            except Exception as exc:
                LOG.warning("index_template_failed name=%s error=%s", name, exc)

    def iter_vulnerability_findings(
        self,
        agent_id: str | None = None,
        since: str | None = None,
    ) -> Iterable[dict[str, Any]]:
        filters: list[dict[str, Any]] = []
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        if since:
            filters.append({"range": {"vulnerability.detected_at": {"gt": since}}})
        query: dict[str, Any] = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {"query": query, "_source": SOURCE_FIELDS}
        yield from self._scroll_sources(self.settings.wazuh_vuln_index_pattern, body)

    def iter_vulnerability_finding_keys(self) -> Iterable[str]:
        body = {
            "query": {"match_all": {}},
            "_source": [
                "agent.id",
                "vulnerability.id",
                "vulnerability.cve",
                "package.name",
                "package.version",
            ],
        }
        for source in self._scroll_sources(self.settings.wazuh_vuln_index_pattern, body):
            cve_id = str(first_path(source, ["vulnerability.id", "vulnerability.cve"], "")).upper()
            agent_id = str(first_path(source, ["agent.id"], ""))
            package_name = str(first_path(source, ["package.name"], ""))
            package_version = str(first_path(source, ["package.version"], ""))
            if cve_id.startswith("CVE-") and agent_id:
                yield finding_key(cve_id, agent_id, package_name, package_version)

    def sca_workaround_results(self) -> dict[tuple[str, str], dict[str, Any]]:
        if not getattr(self.settings, "sca_workaround_enabled", False):
            return {}
        body = {
            "query": {"match_all": {}},
            "_source": [
                "agent.id",
                "agent.name",
                "policy.id",
                "policy.name",
                "check.id",
                "check.title",
                "check.description",
                "check.rationale",
                "check.remediation",
                "check.result",
                "check.status",
                "result",
                "status",
            ],
        }
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for source in self._scroll_sources(self.settings.wazuh_sca_index_pattern, body, ignore_unavailable=True):
            agent_id = str(first_path(source, ["agent.id"], ""))
            if not agent_id:
                continue
            text = " ".join(
                str(first_path(source, [path], ""))
                for path in [
                    "check.id",
                    "check.title",
                    "check.description",
                    "check.rationale",
                    "check.remediation",
                    "policy.id",
                    "policy.name",
                ]
            )
            cve_ids = {match.group(0).upper() for match in CVE_RE.finditer(text)}
            if not cve_ids:
                continue
            result = _sca_result(first_path(source, ["check.result", "check.status", "result", "status"], ""))
            policy_id = str(first_path(source, ["policy.id"], ""))
            check_id = str(first_path(source, ["check.id"], ""))
            check_title = str(first_path(source, ["check.title"], ""))
            for cve_id in cve_ids:
                record = grouped.setdefault(
                    (agent_id, cve_id),
                    {
                        "mitigation_status": "unknown",
                        "workaround_verified": False,
                        "workaround_check_passed": 0,
                        "workaround_check_failed": 0,
                        "workaround_policy_ids": set(),
                        "workaround_check_ids": set(),
                        "workaround_check_titles": set(),
                    },
                )
                if result == "passed":
                    record["workaround_check_passed"] += 1
                elif result == "failed":
                    record["workaround_check_failed"] += 1
                if policy_id:
                    record["workaround_policy_ids"].add(policy_id)
                if check_id:
                    record["workaround_check_ids"].add(check_id)
                if check_title:
                    record["workaround_check_titles"].add(check_title)

        normalized = {}
        for key, record in grouped.items():
            failed = int(record["workaround_check_failed"])
            passed = int(record["workaround_check_passed"])
            status = "not_mitigated" if failed else "mitigated" if passed else "unknown"
            normalized[key] = {
                "mitigation_status": status,
                "workaround_verified": status == "mitigated",
                "workaround_check_passed": passed,
                "workaround_check_failed": failed,
                "workaround_policy_ids": sorted(record["workaround_policy_ids"]),
                "workaround_check_ids": sorted(record["workaround_check_ids"]),
                "workaround_check_titles": sorted(record["workaround_check_titles"])[:20],
            }
        LOG.info("sca_workaround_results_loaded records=%s index=%s", len(normalized), self.settings.wazuh_sca_index_pattern)
        return normalized

    def iter_index_sources(self, index: str, query: dict[str, Any] | None = None) -> Iterable[dict[str, Any]]:
        body = {"query": query or {"match_all": {}}}
        yield from self._scroll_sources(index, body, ignore_unavailable=True)

    def index_doc_count(self, index: str) -> int | None:
        try:
            response = self.client.count(
                index=index,
                params={"ignore_unavailable": "true"},
                request_timeout=self.settings.request_timeout_seconds,
            )
        except Exception as exc:
            LOG.warning("index_count_failed index=%s error=%s", index, exc)
            return None
        return int(response.get("count", 0))

    def latest_inventory_timestamp(self, timestamp_fields: list[str]) -> str | None:
        index = ",".join([pattern for pattern in self.settings.agent_inventory_index_patterns if pattern])
        if not index:
            return None
        for field in timestamp_fields:
            body = {
                "size": 1,
                "query": {"exists": {"field": field}},
                "_source": [field],
                "sort": [{field: {"order": "desc", "unmapped_type": "date"}}],
            }
            try:
                response = self.client.search(
                    index=index,
                    body=body,
                    params={"ignore_unavailable": "true"},
                )
            except Exception as exc:
                LOG.debug("latest_inventory_timestamp_field_failed field=%s error=%s", field, exc)
                continue
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                continue
            timestamp = first_path(hits[0].get("_source") or {}, [field], None)
            if timestamp:
                return str(timestamp)
        return None

    def inventory_agents_updated_since(
        self,
        since: str,
        timestamp_fields: list[str],
        max_agents: int,
    ) -> tuple[set[str], str | None]:
        index = ",".join([pattern for pattern in self.settings.agent_inventory_index_patterns if pattern])
        if not index or not since:
            return set(), None
        for field in timestamp_fields:
            agents: set[str] = set()
            newest: str | None = None
            body = {
                "query": {"range": {field: {"gt": since}}},
                "_source": ["agent.id", field],
                "sort": [{field: {"order": "asc", "unmapped_type": "date"}}],
            }
            try:
                for source in self._scroll_sources(index, body, ignore_unavailable=True):
                    agent_id = str(first_path(source, ["agent.id"], ""))
                    timestamp = first_path(source, [field], None)
                    if timestamp and (newest is None or str(timestamp) > newest):
                        newest = str(timestamp)
                    if agent_id:
                        agents.add(agent_id)
            except Exception as exc:
                LOG.debug("inventory_updates_field_failed field=%s error=%s", field, exc)
                continue
            if agents or newest:
                LOG.info("inventory_updates_detected field=%s agents=%s newest=%s", field, len(agents), newest)
                return agents, newest
        return set(), None

    def agent_metadata(self) -> dict[str, dict[str, Any]]:
        patterns = [pattern for pattern in self.settings.agent_inventory_index_patterns if pattern]
        if not patterns:
            return {}
        metadata: dict[str, dict[str, Any]] = {}
        ip_fields = self.discover_agent_ip_fields(patterns)
        source_fields = self._dedupe([*AGENT_METADATA_FIELDS, *ip_fields])
        body = {"query": {"match_all": {}}, "_source": source_fields}
        try:
            sources = self._scroll_sources(",".join(patterns), body, ignore_unavailable=True)
            for source in sources:
                agent_id = str(first_path(source, ["agent.id"], ""))
                if not agent_id:
                    continue
                current = metadata.setdefault(agent_id, {})
                ip = first_valid_ip(source, ip_fields, "")
                if ip and not current.get("agent_ip"):
                    current["agent_ip"] = ip
                agent_name = first_path(source, ["agent.name"], "")
                if agent_name and not current.get("agent_name"):
                    current["agent_name"] = agent_name
                os_name = first_path(source, ["host.os.name", "agent.host.os.name", "host.os.full"], "")
                if os_name and not current.get("os_name"):
                    current["os_name"] = os_name
                os_version = first_path(source, ["host.os.version", "agent.host.os.version"], "")
                if os_version and not current.get("os_version"):
                    current["os_version"] = os_version
                os_kernel = first_path(source, ["host.os.kernel", "agent.host.os.kernel"], "")
                if os_kernel and not current.get("os_kernel"):
                    current["os_kernel"] = os_kernel
        except Exception as exc:
            LOG.warning("agent_metadata_load_failed patterns=%s error=%s", patterns, exc)
        LOG.info("agent_metadata_loaded agents=%s patterns=%s ip_fields=%s", len(metadata), patterns, ip_fields)
        return metadata

    def discover_agent_ip_fields(self, patterns: list[str]) -> list[str]:
        discovered: list[str] = []
        index = ",".join(patterns)
        try:
            response = self.client.field_caps(
                index=index,
                params={"fields": "*ip*,*IP*", "ignore_unavailable": "true"},
            )
            for field_name, caps in (response.get("fields") or {}).items():
                if self._looks_like_ip_field(field_name, caps):
                    discovered.append(field_name)
        except Exception as exc:
            LOG.warning("agent_ip_field_discovery_failed patterns=%s error=%s", patterns, exc)
        fields = self._dedupe([*KNOWN_AGENT_IP_FIELDS, *sorted(discovered)])
        LOG.info("agent_ip_fields_discovered patterns=%s fields=%s", patterns, fields)
        return fields

    def sample_agent_inventory(self, agent_id: str, limit: int = 5) -> dict[str, Any]:
        patterns = [pattern for pattern in self.settings.agent_inventory_index_patterns if pattern]
        if not patterns:
            return {"patterns": [], "ip_fields": [], "documents": [], "selected_metadata": {}}
        ip_fields = self.discover_agent_ip_fields(patterns)
        source_fields = self._dedupe([*AGENT_METADATA_FIELDS, *ip_fields])
        body = {
            "query": {"term": {"agent.id": agent_id}},
            "_source": source_fields,
        }
        documents = []
        for source in self._scroll_sources(",".join(patterns), body, ignore_unavailable=True):
            documents.append(source)
            if len(documents) >= limit:
                break
        return {
            "patterns": patterns,
            "ip_fields": ip_fields,
            "documents": documents,
            "selected_metadata": self._metadata_from_sources(documents, ip_fields).get(agent_id, {}),
        }

    def list_agents_with_vulnerabilities(self) -> list[dict[str, str]]:
        agents: list[dict[str, str]] = []
        after: dict[str, Any] | None = None
        while True:
            composite: dict[str, Any] = {
                "size": 1000,
                "sources": [{"agent_id": {"terms": {"field": "agent.id"}}}],
            }
            if after:
                composite["after"] = after
            body = {
                "size": 0,
                "aggs": {
                    "agents": {
                        "composite": composite,
                        "aggs": {"agent_name": {"terms": {"field": "agent.name", "size": 1}}},
                    }
                },
            }
            response = self.client.search(index=self.settings.wazuh_vuln_index_pattern, body=body)
            agg = response.get("aggregations", {}).get("agents", {})
            for bucket in agg.get("buckets", []):
                name_buckets = bucket.get("agent_name", {}).get("buckets", [])
                agents.append(
                    {
                        "agent_id": str(bucket.get("key", {}).get("agent_id", "")),
                        "agent_name": str(name_buckets[0].get("key", "")) if name_buckets else "",
                    }
                )
            after = agg.get("after_key")
            if not after:
                break
        return [agent for agent in agents if agent["agent_id"]]

    def bulk_index(self, index: str, docs: list[dict[str, Any]], id_fields: list[str]) -> tuple[int, int]:
        if not docs:
            return 0, 0
        actions = [
            {
                "_op_type": "index",
                "_index": index,
                "_id": self._doc_id(doc, id_fields),
                "_source": doc,
            }
            for doc in docs
        ]
        success, errors = helpers.bulk(
            self.client,
            actions,
            chunk_size=self.settings.bulk_size,
            request_timeout=self.settings.request_timeout_seconds,
            raise_on_error=False,
        )
        error_count = len(errors) if isinstance(errors, list) else int(bool(errors))
        if error_count:
            LOG.warning("bulk_index_errors index=%s errors=%s", index, error_count)
        LOG.info("bulk_index_done index=%s success=%s errors=%s", index, success, error_count)
        return int(success), error_count

    def delete_by_query(self, index: str, query: dict[str, Any]) -> int:
        try:
            response = self.client.delete_by_query(
                index=index,
                body={"query": query},
                params={"conflicts": "proceed", "ignore_unavailable": "true", "refresh": "true"},
                request_timeout=self.settings.request_timeout_seconds,
            )
        except Exception as exc:
            LOG.warning("delete_by_query_failed index=%s error=%s query=%s", index, exc, query)
            return 0
        deleted = int(response.get("deleted", 0))
        LOG.info("delete_by_query_done index=%s deleted=%s", index, deleted)
        return deleted

    def delete_enriched_findings_by_identity(self, index: str, docs: list[dict[str, Any]]) -> int:
        deleted = 0
        for start in range(0, len(docs), 200):
            chunk = docs[start : start + 200]
            should = [self._identity_clause(doc) for doc in chunk]
            deleted += self.delete_by_query(
                index,
                {"bool": {"should": should, "minimum_should_match": 1}},
            )
        return deleted

    @staticmethod
    def _identity_clause(doc: dict[str, Any]) -> dict[str, Any]:
        filters: list[dict[str, Any]] = []
        for field in ["cve_id", "agent_id", "package_name", "package_version"]:
            value = str(doc.get(field, ""))
            if value:
                filters.append({"term": {field: value}})
            else:
                filters.append({"bool": {"must_not": {"exists": {"field": field}}}})
        return {"bool": {"filter": filters}}

    def _scroll_sources(
        self,
        index: str,
        body: dict[str, Any],
        ignore_unavailable: bool = False,
    ) -> Iterable[dict[str, Any]]:
        scroll_id = None
        try:
            response = self.client.search(
                index=index,
                body=body,
                params={
                    "scroll": self.settings.scroll_ttl,
                    "size": self.settings.page_size,
                    "ignore_unavailable": str(ignore_unavailable).lower(),
                },
            )
            scroll_id = response.get("_scroll_id")
            while True:
                hits = response.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for hit in hits:
                    source = hit.get("_source") or {}
                    source["_wazuh_source_index"] = hit.get("_index")
                    source["_wazuh_source_id"] = hit.get("_id")
                    yield source
                response = self.client.scroll(scroll_id=scroll_id, params={"scroll": self.settings.scroll_ttl})
                scroll_id = response.get("_scroll_id")
        finally:
            if scroll_id:
                try:
                    self.client.clear_scroll(scroll_id=scroll_id)
                except Exception as exc:
                    LOG.debug("clear_scroll_failed error=%s", exc)

    @staticmethod
    def _doc_id(doc: dict[str, Any], id_fields: list[str]) -> str:
        raw = "|".join(str(doc.get(field, "")) for field in id_fields)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _metadata_from_sources(sources: list[dict[str, Any]], ip_fields: list[str]) -> dict[str, dict[str, Any]]:
        metadata: dict[str, dict[str, Any]] = {}
        for source in sources:
            agent_id = str(first_path(source, ["agent.id"], ""))
            if not agent_id:
                continue
            current = metadata.setdefault(agent_id, {})
            ip = first_valid_ip(source, ip_fields, "")
            if ip and not current.get("agent_ip"):
                current["agent_ip"] = ip
            agent_name = first_path(source, ["agent.name"], "")
            if agent_name and not current.get("agent_name"):
                current["agent_name"] = agent_name
            os_name = first_path(source, ["host.os.name", "agent.host.os.name", "host.os.full"], "")
            if os_name and not current.get("os_name"):
                current["os_name"] = os_name
            os_version = first_path(source, ["host.os.version", "agent.host.os.version"], "")
            if os_version and not current.get("os_version"):
                current["os_version"] = os_version
            os_kernel = first_path(source, ["host.os.kernel", "agent.host.os.kernel"], "")
            if os_kernel and not current.get("os_kernel"):
                current["os_kernel"] = os_kernel
        return metadata

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        seen = set()
        result = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    @staticmethod
    def _looks_like_ip_field(field_name: str, caps: dict[str, Any]) -> bool:
        lower = field_name.lower()
        tokens = lower.replace("-", "_").replace(".", "_").split("_")
        if "ip" not in tokens and not lower.endswith("ip"):
            return False
        field_types = set(caps.keys())
        return bool(field_types & {"ip", "keyword", "text"})


def _sca_result(value: Any) -> str:
    text = str(value).strip().lower()
    if text in {"passed", "pass", "ok", "compliant", "true", "1"}:
        return "passed"
    if text in {"failed", "fail", "not_compliant", "non-compliant", "false", "0"}:
        return "failed"
    return "unknown"
