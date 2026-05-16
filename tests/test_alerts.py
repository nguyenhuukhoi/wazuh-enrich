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
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
            "fix_available": True,
            "recommended_action": "Patch now.",
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
    assert "CRITICAL - Critical Real Impact CVEs impacting system" in manager.messages[0]
    assert "- Alert scope: critical_real_impact" in manager.messages[0]
    assert "- Affected agents: 2" in manager.messages[0]
    assert "- Affected agents: 72" not in manager.messages[0]
    assert "- Public PoC CVEs: 1" in manager.messages[0]
    assert "- Patch now CVEs: 1" in manager.messages[0]
    assert "- Vendor confirmed affected: 1" in manager.messages[0]
    assert "PoC=yes" in manager.messages[0]
    assert "patch=patch_now" in manager.messages[0]
    assert "Ubuntu=confirmed_affected" in manager.messages[0]
    assert "action=Patch now." in manager.messages[0]


def test_alert_not_marked_when_delivery_is_not_configured(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = AlertManager(
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
            "affected_hosts_count": 1,
            "affected_packages": ["openssl"],
            "public_poc": False,
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
            "fix_available": True,
            "recommended_action": "Patch now.",
            "risk_score": 106.4,
        }
    ]

    manager.process_cycle([{"cve_id": "CVE-2025-0001", "agent_id": "001", "priority": "P0"}], cve_summary)

    assert state.data["alert_dedup_keys"] == {}
    assert state.data["last_alert_sent_by_type"] == {}


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
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
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
        thresholds={"epss_high": 0.7, "send_all_alerts": True, "alert_scope": "all", "max_top_cves": 10},
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
        thresholds={"send_all_impacted_cves": True, "alert_scope": "all", "max_top_cves": 10},
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


def test_default_alert_scope_only_sends_critical_real_impact(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "send_all_impacted_cves": True},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-CRITICAL",
            "priority": "P0",
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.01,
            "cvss_score": 7.8,
            "affected_hosts_count": 1,
            "affected_packages": ["kernel"],
            "risk_score": 80,
        },
        {
            "cve_id": "CVE-2026-REVIEW",
            "priority": "P0",
            "patch_decision": "needs_review",
            "verification_status": "vendor_not_found",
            "exploitability_status": "exploited_in_wild",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.01,
            "cvss_score": 7.8,
            "affected_hosts_count": 1,
            "affected_packages": ["kernel"],
            "risk_score": 70,
        },
    ]

    manager.process_cycle([{"cve_id": "CVE-2026-CRITICAL", "agent_id": "001"}], cve_summary)

    assert len(manager.messages) == 1
    assert "CVE-2026-CRITICAL" in manager.messages[0]
    assert "CVE-2026-REVIEW" not in manager.messages[0]


def test_needs_review_alert_scope_only_sends_review_group(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"alert_scope": "needs_review"},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-REVIEW",
            "priority": "P0",
            "patch_decision": "needs_review",
            "verification_status": "vendor_not_found",
            "exploitability_status": "exploited_in_wild",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.01,
            "cvss_score": 7.8,
            "affected_hosts_count": 1,
            "affected_packages": ["kernel"],
            "risk_score": 70,
        }
    ]

    manager.process_cycle([{"cve_id": "CVE-2026-REVIEW", "agent_id": "001"}], cve_summary)

    assert len(manager.messages) == 1
    assert "- Alert scope: needs_review" in manager.messages[0]
    assert "CVE-2026-REVIEW" in manager.messages[0]


def test_patch_scheduled_alert_scope_only_sends_scheduled_group(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"alert_scope": "patch_scheduled"},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-SCHEDULED",
            "priority": "P2",
            "patch_decision": "patch_scheduled",
            "verification_status": "confirmed_affected",
            "exploitability_status": "no_known_exploit",
            "kev": False,
            "public_poc": False,
            "epss_score": 0.01,
            "cvss_score": 6.8,
            "affected_hosts_count": 1,
            "affected_packages": ["openssl"],
            "risk_score": 20,
        }
    ]

    manager.process_cycle([{"cve_id": "CVE-2026-SCHEDULED", "agent_id": "001"}], cve_summary)

    assert len(manager.messages) == 1
    assert "- Alert scope: patch_scheduled" in manager.messages[0]
    assert "CVE-2026-SCHEDULED" in manager.messages[0]


def test_public_poc_only_filters_alert_cves(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={
            "send_all_alerts": True,
            "send_all_impacted_cves": True,
            "public_poc_only": True,
            "alert_scope": "all",
            "max_top_cves": 10,
        },
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-POC",
            "priority": "P3",
            "kev": False,
            "public_poc": True,
            "epss_score": 0.01,
            "cvss_score": 3.0,
            "affected_hosts_count": 1,
            "affected_packages": ["curl"],
            "risk_score": 10,
        },
        {
            "cve_id": "CVE-2026-NOPOC",
            "priority": "P0",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.01,
            "cvss_score": 9.0,
            "affected_hosts_count": 1,
            "affected_packages": ["kernel"],
            "risk_score": 80,
        },
    ]

    manager.process_cycle(
        [
            {"cve_id": "CVE-2026-POC", "agent_id": "001"},
            {"cve_id": "CVE-2026-NOPOC", "agent_id": "001"},
        ],
        cve_summary,
    )

    assert len(manager.messages) == 1
    assert "CVE-2026-POC" in manager.messages[0]
    assert "CVE-2026-NOPOC" not in manager.messages[0]
    assert "- Public PoC CVEs: 1" in manager.messages[0]


def test_muted_alerts_can_suppress_whole_cve(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={
            "send_all_alerts": True,
            "alert_scope": "all",
            "muted_alerts": [{"cve_id": "CVE-2026-MUTE"}],
        },
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-MUTE",
            "priority": "P0",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.1,
            "cvss_score": 7.8,
            "affected_hosts_count": 2,
            "affected_packages": ["kernel"],
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
            "risk_score": 80,
        }
    ]

    manager.process_cycle(
        [
            {"cve_id": "CVE-2026-MUTE", "agent_id": "001", "priority": "P0"},
            {"cve_id": "CVE-2026-MUTE", "agent_id": "002", "priority": "P0"},
        ],
        cve_summary,
    )

    assert manager.messages == []


def test_muted_alerts_can_suppress_cve_for_one_host_only(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={
            "send_all_alerts": True,
            "alert_scope": "critical_real_impact",
            "muted_alerts": [{"cve_id": "CVE-2026-HOST", "agent_id": "001"}],
        },
        state=state,
    )
    docs = [
        {
            "cve_id": "CVE-2026-HOST",
            "priority": "P0",
            "agent_id": "001",
            "agent_name": "muted-host",
            "package_name": "kernel",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.1,
            "cvss_score": 7.8,
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
            "fix_available": True,
            "risk_score": 80,
        },
        {
            "cve_id": "CVE-2026-HOST",
            "priority": "P0",
            "agent_id": "002",
            "agent_name": "active-host",
            "package_name": "kernel",
            "kev": True,
            "public_poc": False,
            "epss_score": 0.1,
            "cvss_score": 7.8,
            "patch_decision": "patch_now",
            "verification_status": "confirmed_affected",
            "exploitability_status": "exploited_in_wild",
            "fix_available": True,
            "risk_score": 80,
        },
    ]

    manager.process_cycle(docs, [])

    assert len(manager.messages) == 1
    assert "CVE-2026-HOST" in manager.messages[0]
    assert "- Affected agents: 1" in manager.messages[0]


def test_max_top_cves_zero_includes_all_cves(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "alert_scope": "all", "max_top_cves": 0},
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


def test_send_all_alerts_keeps_old_every_cycle_behavior_even_with_interval(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "alert_scope": "all", "alert_interval_seconds": 3600},
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
    assert state.last_alert_type_sent_at("cycle") is not None


def test_alert_interval_can_skip_when_send_all_alerts_is_disabled(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"alert_scope": "all", "alert_interval_seconds": 3600},
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

    assert len(manager.messages) == 1


def test_alert_interval_allows_cycle_after_elapsed(tmp_path):
    state = StateStore(tmp_path / "state.json")
    state.data["last_alert_sent_by_type"] = {"cycle": "2026-01-01T00:00:00+00:00"}
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "alert_scope": "all", "alert_interval_seconds": 1},
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

    assert len(manager.messages) == 1


def test_cycle_alert_deduplicates_duplicate_cve_summaries(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "alert_scope": "all", "max_top_cves": 10},
        state=state,
    )
    cve_summary = [
        {
            "cve_id": "CVE-2026-DUP1",
            "priority": "P0",
            "patch_decision": "patch_scheduled",
            "kev": True,
            "epss_score": 0.1,
            "cvss_score": 7.8,
            "affected_hosts_count": 1,
            "affected_packages": ["openssl"],
            "risk_score": 50.0,
        },
        {
            "cve_id": "CVE-2026-DUP1",
            "priority": "P0",
            "patch_decision": "patch_now",
            "kev": True,
            "epss_score": 0.1,
            "cvss_score": 7.8,
            "affected_hosts_count": 2,
            "affected_packages": ["openssl"],
            "risk_score": 90.0,
        },
    ]

    manager.process_cycle([{"cve_id": "CVE-2026-DUP1", "agent_id": "001"}], cve_summary)

    assert manager.messages[0].count("CVE-2026-DUP1") == 1
    assert "patch=patch_now" in manager.messages[0]


def test_alert_interval_zero_keeps_send_all_behavior(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"send_all_alerts": True, "alert_scope": "all", "alert_interval_seconds": 0},
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


def test_new_agent_baseline_is_not_blocked_by_cycle_alert_interval(tmp_path):
    state = StateStore(tmp_path / "state.json")
    state.mark_alert_type_sent("cycle")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={"alert_interval_seconds": 3600},
        state=state,
    )

    manager.process_new_agent_baseline(
        "002",
        "ubuntu-new",
        [
            {
                "cve_id": "CVE-2026-0001",
                "priority": "P0",
                "agent_id": "002",
                "kev": True,
                "public_poc": False,
                "epss_score": 0.1,
                "cvss_score": 7.8,
                "package_name": "kernel",
                "affected_packages": ["kernel"],
                "patch_decision": "patch_now",
                "verification_status": "confirmed_affected",
                "exploitability_status": "exploited_in_wild",
                "fix_available": True,
                "recommended_action": "Patch now.",
                "risk_score": 80.0,
            }
        ],
    )

    assert len(manager.messages) == 1
    assert "CRITICAL - Critical Real Impact CVEs impacting system" in manager.messages[0]
    assert "- New agent baseline: 002 ubuntu-new" in manager.messages[0]
    assert "patch=patch_now" in manager.messages[0]


def test_new_agent_baseline_uses_alert_scope_not_raw_p0_p1(tmp_path):
    state = StateStore(tmp_path / "state.json")
    manager = CapturingAlertManager(
        bot_token="",
        chat_id="",
        thresholds={},
        state=state,
    )

    manager.process_new_agent_baseline(
        "002",
        "ubuntu-new",
        [
            {
                "cve_id": "CVE-2026-REVIEW",
                "priority": "P0",
                "agent_id": "002",
                "kev": True,
                "public_poc": False,
                "epss_score": 0.1,
                "cvss_score": 7.8,
                "package_name": "kernel",
                "patch_decision": "needs_review",
                "verification_status": "vendor_not_found",
                "exploitability_status": "exploited_in_wild",
                "risk_score": 80.0,
            }
        ],
    )

    assert manager.messages == []


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
