from types import SimpleNamespace

from state import StateStore
from vuln_enricher import (
    daily_full_refresh_required,
    latest_index,
    latest_indices,
    mark_daily_full_refresh,
    mark_startup_full_refresh,
    reconcile_resolved_latest_findings,
    replace_latest_index,
    startup_full_refresh_required,
)


class FakeClient:
    def __init__(self, index_name: str, count: int | None = 0):
        self._index_name = index_name
        self._count = count
        self.count_calls = 0

    def index_name(self, prefix: str) -> str:
        return self._index_name

    def index_doc_count(self, index: str) -> int | None:
        self.count_calls += 1
        assert index == self._index_name
        return self._count


class FakeReconcileClient:
    def __init__(self):
        self.latest_docs = [
            {
                "cve_id": "CVE-2026-0001",
                "agent_id": "001",
                "package_name": "openssl",
                "package_version": "1.0",
            },
            {
                "cve_id": "CVE-2026-0002",
                "agent_id": "001",
                "package_name": "nginx",
                "package_version": "2.0",
            },
        ]
        self.deleted: list[dict] = []

    def iter_vulnerability_finding_keys(self):
        yield "CVE-2026-0001|001|openssl|1.0"

    def iter_index_sources(self, index: str, query=None):
        assert index == "wazuh-vuln-enriched-latest"
        yield from self.latest_docs

    def delete_enriched_findings_by_identity(self, index: str, docs: list[dict]) -> int:
        assert index == "wazuh-vuln-enriched-latest"
        self.deleted.extend(docs)
        return len(docs)


class FakeLatestClient:
    def __init__(self):
        self.bulked = []
        self.recreated = []

    def bulk_index(self, index: str, docs: list[dict], id_fields: list[str]):
        self.bulked.append((index, docs, id_fields))
        return len(docs), 0

    def recreate_index(self, index: str) -> None:
        self.recreated.append(index)


def test_daily_full_refresh_required_when_today_index_is_empty(tmp_path):
    state = StateStore(tmp_path / "state.json")
    settings = SimpleNamespace(enriched_index_prefix="wazuh-vuln-enriched")
    client = FakeClient("wazuh-vuln-enriched-2026.05.11", count=0)

    required, index, count = daily_full_refresh_required(settings, client, state)

    assert required is True
    assert index == "wazuh-vuln-enriched-2026.05.11"
    assert count == 0
    assert state.data["last_daily_full_refresh_index"] is None


def test_daily_full_refresh_skipped_after_index_was_marked(tmp_path):
    state = StateStore(tmp_path / "state.json")
    settings = SimpleNamespace(enriched_index_prefix="wazuh-vuln-enriched")
    client = FakeClient("wazuh-vuln-enriched-2026.05.11", count=0)
    mark_daily_full_refresh(settings, client, state)

    required, index, count = daily_full_refresh_required(settings, client, state)

    assert required is False
    assert index == "wazuh-vuln-enriched-2026.05.11"
    assert count is None
    assert client.count_calls == 0


def test_daily_full_refresh_skipped_and_marked_when_today_index_has_docs(tmp_path):
    state = StateStore(tmp_path / "state.json")
    settings = SimpleNamespace(enriched_index_prefix="wazuh-vuln-enriched")
    client = FakeClient("wazuh-vuln-enriched-2026.05.11", count=25)

    required, index, count = daily_full_refresh_required(settings, client, state)

    assert required is False
    assert index == "wazuh-vuln-enriched-2026.05.11"
    assert count == 25
    assert state.data["last_daily_full_refresh_index"] == "wazuh-vuln-enriched-2026.05.11"


def test_latest_indices_use_stable_dashboard_index_names():
    settings = SimpleNamespace(
        enriched_index_prefix="wazuh-vuln-enriched",
        cve_summary_index_prefix="wazuh-vuln-cve-summary",
        host_summary_index_prefix="wazuh-vuln-host-summary",
        host_cve_impact_index_prefix="wazuh-vuln-host-cve-impact",
    )

    assert latest_index("wazuh-vuln-enriched") == "wazuh-vuln-enriched-latest"
    assert latest_indices(settings) == {
        "enriched_index": "wazuh-vuln-enriched-latest",
        "cve_summary_index": "wazuh-vuln-cve-summary-latest",
        "host_summary_index": "wazuh-vuln-host-summary-latest",
        "host_cve_impact_index": "wazuh-vuln-host-cve-impact-latest",
    }


def test_startup_full_refresh_required_until_marked(tmp_path):
    state = StateStore(tmp_path / "state.json")

    assert startup_full_refresh_required(state) is True

    mark_startup_full_refresh(state)

    assert startup_full_refresh_required(state) is False
    assert state.data["startup_full_refresh_done"] is True
    assert state.data["startup_full_refresh_at"]


def test_reconcile_resolved_latest_findings_deletes_docs_missing_from_wazuh():
    settings = SimpleNamespace(
        enriched_index_prefix="wazuh-vuln-enriched",
        cve_summary_index_prefix="wazuh-vuln-cve-summary",
        host_summary_index_prefix="wazuh-vuln-host-summary",
        host_cve_impact_index_prefix="wazuh-vuln-host-cve-impact",
    )
    client = FakeReconcileClient()

    result = reconcile_resolved_latest_findings(client, settings)

    assert result["checked_latest_docs"] == 2
    assert result["stale_docs"] == 1
    assert result["deleted_latest_docs"] == 1
    assert client.deleted[0]["cve_id"] == "CVE-2026-0002"


def test_replace_latest_index_recreates_index_then_bulk_indexes_current_docs():
    client = FakeLatestClient()

    replace_latest_index(
        client,
        "wazuh-vuln-enriched-latest",
        [{"cve_id": "CVE-2026-0001", "agent_id": "001"}],
        ["cve_id", "agent_id"],
    )

    assert client.recreated == ["wazuh-vuln-enriched-latest"]
    assert client.bulked[0][0] == "wazuh-vuln-enriched-latest"
    assert client.bulked[0][1] == [{"cve_id": "CVE-2026-0001", "agent_id": "001"}]
    assert client.bulked[0][2] == ["cve_id", "agent_id"]
