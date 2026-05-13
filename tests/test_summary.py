from summary import build_host_cve_impact_summary, build_host_summary


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


def test_build_host_cve_impact_summary_includes_non_poc_dangerous_cves():
    docs = [
        {
            "cve_id": "CVE-2026-KEV1",
            "agent_id": "001",
            "agent_name": "host-1",
            "agent_ip": "10.0.0.1",
            "package_name": "kernel",
            "package_version": "1",
            "public_poc": False,
            "priority": "P0",
            "patch_decision": "patch_now",
            "exploitability_status": "exploited_in_wild",
            "exposure_status": "running_kernel",
            "kev": True,
            "poc_count": 0,
            "epss_score": 0.1,
            "epss_percentile": 0.2,
            "cvss_score": 7.8,
            "risk_score": 60.0,
            "detected_at": "2026-05-09T00:00:00Z",
        }
    ]

    summaries = build_host_cve_impact_summary(docs)

    assert len(summaries) == 1
    assert summaries[0]["cve_id"] == "CVE-2026-KEV1"
    assert summaries[0]["public_poc"] is False
    assert summaries[0]["patch_decision"] == "patch_now"


def test_build_host_summary_counts_old_kernel_cleanup():
    docs = [
        {
            "cve_id": "CVE-2026-23231",
            "agent_id": "001",
            "agent_name": "host-1",
            "agent_ip": "10.0.0.1",
            "os_name": "Ubuntu",
            "os_version": "24.04",
            "package_name": "linux-image-6.8.0-36-generic",
            "priority": "P0",
            "patch_decision": "cleanup_old_kernel",
            "kev": True,
            "epss_score": 0.1,
            "cvss_score": 7.8,
            "detected_at": "2026-05-09T00:00:00Z",
        }
    ]

    summaries = build_host_summary(docs)

    assert summaries[0]["cleanup_old_kernel_count"] == 1
    assert summaries[0]["patch_now_count"] == 0
