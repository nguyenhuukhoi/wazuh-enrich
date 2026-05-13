from types import SimpleNamespace

from state import StateStore
from vuln_enricher import (
    daily_full_refresh_required,
    ensure_latest_indices,
    latest_index,
    latest_indices,
    mark_daily_full_refresh,
)


class FakeClient:
    def __init__(self, index_name: str, count: int | None = 0):
        self._index_name = index_name
        self._count = count
        self.count_calls = 0
        self.created_indices = []

    def index_name(self, prefix: str) -> str:
        return self._index_name

    def index_doc_count(self, index: str) -> int | None:
        self.count_calls += 1
        assert index == self._index_name
        return self._count

    def ensure_index(self, index: str) -> bool:
        self.created_indices.append(index)
        return True


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


def test_ensure_latest_indices_creates_dashboard_indices_even_without_docs():
    settings = SimpleNamespace(
        enriched_index_prefix="wazuh-vuln-enriched",
        cve_summary_index_prefix="wazuh-vuln-cve-summary",
        host_summary_index_prefix="wazuh-vuln-host-summary",
        host_cve_impact_index_prefix="wazuh-vuln-host-cve-impact",
    )
    client = FakeClient("wazuh-vuln-enriched-2026.05.11")

    indices = ensure_latest_indices(client, settings)

    assert list(indices.values()) == client.created_indices
    assert "wazuh-vuln-cve-summary-latest" in client.created_indices
    assert "wazuh-vuln-host-cve-impact-latest" in client.created_indices
