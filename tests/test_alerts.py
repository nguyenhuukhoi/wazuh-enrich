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
            "risk_score": 106.4,
        }
    ]

    manager.process_cycle([], cve_summary)
    manager.process_cycle([], cve_summary)

    assert len(manager.messages) == 1
    assert "CRITICAL - Exploited CVEs detected" in manager.messages[0]


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
