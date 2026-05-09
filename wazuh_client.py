import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from opensearchpy import OpenSearch, RequestsHttpConnection, helpers

from config import Settings

LOG = logging.getLogger(__name__)

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
                    "cve_year": {"type": "integer"},
                    "agent_id": {"type": "keyword"},
                    "agent_name": {"type": "keyword"},
                    "agent_ip": {"type": "ip", "ignore_malformed": True},
                    "os_name": {"type": "keyword"},
                    "os_version": {"type": "keyword"},
                    "package_name": {"type": "keyword"},
                    "package_version": {"type": "keyword"},
                    "kev": {"type": "boolean"},
                    "epss_score": {"type": "float"},
                    "epss_percentile": {"type": "float"},
                    "public_poc": {"type": "boolean"},
                    "poc_count": {"type": "integer"},
                    "poc_references": {"type": "keyword"},
                    "poc_sources": {"type": "keyword"},
                    "cvss_score": {"type": "float"},
                    "priority": {"type": "keyword"},
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

    def iter_index_sources(self, index: str, query: dict[str, Any] | None = None) -> Iterable[dict[str, Any]]:
        body = {"query": query or {"match_all": {}}}
        yield from self._scroll_sources(index, body)

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

    def _scroll_sources(self, index: str, body: dict[str, Any]) -> Iterable[dict[str, Any]]:
        scroll_id = None
        try:
            response = self.client.search(
                index=index,
                body=body,
                scroll=self.settings.scroll_ttl,
                size=self.settings.page_size,
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
                response = self.client.scroll(scroll_id=scroll_id, scroll=self.settings.scroll_ttl)
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
