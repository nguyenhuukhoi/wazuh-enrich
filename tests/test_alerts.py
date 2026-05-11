from alerts import AlertManager, finding_dedup_key
from state import StateStore


class CapturingAlertManager(AlertManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.messages = []

    def send_message(self, message: str) -> None:
        self.messages.append(message)


def test_finding_dedup_key():
    doc = {
        "cve_id": "CVE-2025-0001",
        "agent_id": "001",
        "package_name": "openssl",
        "package_version": "1.2.3",
    }

    assert finding_dedup_key(doc) == "CVE-2025-0001|001|openssl|1.2.3"


def test_alert_dedup_for_same_cve(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"epss_high": 0.7, "cve_many_agents": 25, "max_top_cves": 10},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2025-0001",
            "priority": "P0",
            "kev": True,
            "epss_score": 0.94,
            "cvss_score": 9.8,
            "affected_hosts_count": 72,
            "affected_packages": ["openssl"],
            "public_poc": True,
            "risk_score": 106.4,
        }
    ]

    enriched_docs = [
        {"cve_id": "CVE-2025-0001", "agent_id": "001", "priority": "P0"},
        {"cve_id": "CVE-2025-0001", "agent_id": "002", "priority": "P0"},
        {"cve_id": "CVE-2025-0001", "agent_id": "002", "priority": "P0"},
    ]

    manager.process_cycle(enriched_docs, cve_summary)
    manager.process_cycle(enriched_docs, cve_summary)

    assert len(manager.messages) == 1
    assert "CRITICAL - Exploited CVEs detected" in manager.messages[0]
    assert "- Affected agents: 2" in manager.messages[0]
    assert "- Affected agents: 72" not in manager.messages[0]
    assert "- Public PoC CVEs: 1" in manager.messages[0]
    assert "PoC=yes" in manager.messages[0]


def test_alert_summary_fallback_names_host_cve_pairs(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"epss_high": 0.7, "cve_many_agents": 25, "max_top_cves": 10},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2025-0001",
            "priority": "P0",
            "kev": True,
            "epss_score": 0.94,
            "cvss_score": 9.8,
            "affected_hosts_count": 72,
            "affected_packages": ["openssl"],
            "risk_score": 106.4,
        }
    ]

    manager.process_cycle([], cve_summary)

    assert "- Affected host-CVE pairs: 72" in manager.messages[0]


def test_send_all_alerts_bypasses_dedup(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"epss_high": 0.7, "send_all_alerts": True, "max_top_cves": 10},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-0001",
            "priority": "P0",
            "kev": False,
            "epss_score": 0.8,
            "cvss_score": 9.0,
            "affected_hosts_count": 1,
            "affected_packages": ["openssl"],
            "risk_score": 90.0,
        }
    ]

    manager.process_cycle([{"cve_id": "CVE-2026-0001", "agent_id": "001"}], cve_summary)
    manager.process_cycle([{"cve_id": "CVE-2026-0001", "agent_id": "001"}], cve_summary)

    assert len(manager.messages) == 2


def test_send_all_impacted_cves_alerts_active_cves_even_without_risk_threshold(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_impacted_cves": True, "max_top_cves": 10},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-LOW1",
            "priority": "P3",
            "kev": False,
            "epss_score": 0.01,
            "cvss_score": 3.0,
            "affected_hosts_count": 1,
            "affected_packages": ["curl"],
            "risk_score": 10,
        }
    ]

    manager.process_cycle([{"cve_id": "CVE-2026-LOW1", "agent_id": "001"}], cve_summary)
    manager.process_cycle([{"cve_id": "CVE-2026-LOW1", "agent_id": "001"}], cve_summary)

    assert len(manager.messages) == 1
    assert "CVE-2026-LOW1" in manager.messages[0]


def test_max_top_cves_zero_includes_all_cves(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "max_top_cves": 0},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-0001",
            "priority": "P0",
            "kev": False,
            "epss_score": 0.1,
            "cvss_score": 9.0,
            "affected_hosts_count": 1,
            "affected_packages": ["a"],
            "risk_score": 10,
        },
        {
            "cve_id": "CVE-2026-0002",
            "priority": "P0",
            "kev": False,
            "epss_score": 0.1,
            "cvss_score": 9.0,
            "affected_hosts_count": 1,
            "affected_packages": ["b"],
            "risk_score": 9,
        },
    ]

    manager.process_cycle([], cve_summary)

    assert "1. CVE-2026-0001" in manager.messages[0]
    assert "2. CVE-2026-0002" in manager.messages[0]


def test_dry_run_alert_renders_readable_block(tmp_path, capsys):
    state = StateStore(tmp_path / "state.json")
    manager = AlertManager(
        bot_token="",
        chat_id="",
        thresholds={},
        state=state,
        dry_run=True,
    )

    manager.send_message("CRITICAL - Test\n\nSummary:\n- Affected agents: 1")

    captured = capsys.readouterr()
    assert "=== DRY RUN ALERT ===" in captured.err
    assert "CRITICAL - Test" in captured.err
    assert "\\n" not in captured.err
