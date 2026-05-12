from summary import build_host_cve_impact_summary


def test_build_host_cve_impact_summary_deduplicates_cve_agent_pairs():
    docs = [
        {
            "cve_id": "CVE-2026-0001",
            "agent_id": "001",
            "agent_name": "host-1",
            "agent_ip": "10.0.0.1",
            "package_name": "kernel-a",
            "package_version": "1",
            "public_poc": True,
            "priority": "P2",
            "patch_decision": "patch_scheduled",
            "exploitability_status": "public_poc_available",
            "exposure_status": "kernel_package_installed",
            "kev": False,
            "poc_count": 1,
            "epss_score": 0.1,
            "epss_percentile": 0.2,
            "cvss_score": 7.8,
            "risk_score": 28.4,
            "detected_at": "2026-05-09T00:00:00Z",
        },
        {
            "cve_id": "CVE-2026-0001",
            "agent_id": "001",
            "agent_name": "host-1",
            "agent_ip": "10.0.0.1",
            "package_name": "kernel-b",
            "package_version": "2",
            "public_poc": True,
            "priority": "P2",
            "patch_decision": "patch_now",
            "exploitability_status": "public_poc_available",
            "exposure_status": "running_kernel",
            "kev": False,
            "poc_count": 1,
            "epss_score": 0.1,
            "epss_percentile": 0.2,
            "cvss_score": 7.8,
            "risk_score": 28.4,
            "detected_at": "2026-05-09T00:01:00Z",
        },
    ]

    summaries = build_host_cve_impact_summary(docs)

    assert len(summaries) == 1
    assert summaries[0]["cve_id"] == "CVE-2026-0001"
    assert summaries[0]["agent_id"] == "001"
    assert summaries[0]["finding_count"] == 2
    assert summaries[0]["affected_packages"] == ["kernel-a", "kernel-b"]
    assert summaries[0]["patch_decision"] == "patch_now"
    assert summaries[0]["exploitability_status"] == "public_poc_available"
