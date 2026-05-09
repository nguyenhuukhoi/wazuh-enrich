import gzip
import json
import io
import tarfile

from feed_sync import FeedSync, parse_epss_csv_gz, parse_kev_json, parse_poc_csv, parse_poc_json, parse_ubuntu_oval, parse_ubuntu_osv


def test_parse_kev_json():
    payload = json.dumps(
        {
            "vulnerabilities": [
                {"cveID": "CVE-2025-0001"},
                {"cveID": "CVE-2024-9999"},
                {"notCve": "ignored"},
            ]
        }
    )

    assert parse_kev_json(payload) == {"CVE-2025-0001", "CVE-2024-9999"}


def test_parse_epss_csv_gz():
    csv_text = "#model_version:v2026.01.01\ncve,epss,percentile\nCVE-2025-0001,0.94,0.99\n"
    records = parse_epss_csv_gz(gzip.compress(csv_text.encode("utf-8")))

    assert records["CVE-2025-0001"].score == 0.94
    assert records["CVE-2025-0001"].percentile == 0.99


def test_sync_kev_from_local_file(tmp_path):
    kev_file = tmp_path / "known_exploited_vulnerabilities.json"
    kev_file.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}),
        encoding="utf-8",
    )
    sync = FeedSync(
        cache_dir=tmp_path / "cache",
        kev_url="https://blocked.example/kev.json",
        epss_url="https://example/epss.csv.gz",
        kev_file=kev_file,
    )

    assert sync.sync_kev() == {"CVE-2026-0001"}
    assert (tmp_path / "cache" / "cisa_kev.json").exists()


def test_sync_poc_from_local_file_caches_feed(tmp_path):
    poc_file = tmp_path / "cve_poc.csv"
    poc_file.write_text("cve,url,source\nCVE-2026-0001,https://example.com/poc,test\n", encoding="utf-8")
    sync = FeedSync(
        cache_dir=tmp_path / "cache",
        kev_url="https://example/kev.json",
        epss_url="https://example/epss.csv.gz",
        poc_file=poc_file,
    )

    records = sync.sync_poc()

    assert records["CVE-2026-0001"].count == 1
    assert (tmp_path / "cache" / "cve_poc.csv").exists()


def test_parse_poc_csv():
    records = parse_poc_csv(
        "cve,url,source\n"
        "CVE-2026-0001,https://example.com/poc,CVE PoC feed\n"
        "CVE-2026-0001,https://example.com/poc2,CVE PoC feed\n"
    )

    assert records["CVE-2026-0001"].count == 2
    assert "https://example.com/poc" in records["CVE-2026-0001"].references


def test_parse_poc_json():
    records = parse_poc_json(
        json.dumps(
            {
                "CVE-2026-0001": [
                    {"url": "https://example.com/repo", "source": "internal"},
                    "https://example.com/writeup",
                ]
            }
        )
    )

    assert records["CVE-2026-0001"].count == 2
    assert "internal" in records["CVE-2026-0001"].sources


def test_parse_ubuntu_oval_extracts_cve_package_and_fixed_version():
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
 xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:com.ubuntu.noble:def:1">
      <metadata>
        <title>CVE-2026-0001 on Ubuntu 24.04 LTS</title>
        <reference source="CVE" ref_id="CVE-2026-0001" ref_url="https://ubuntu.com/security/CVE-2026-0001"/>
        <reference source="USN" ref_id="USN-9999-1" ref_url="https://ubuntu.com/security/notices/USN-9999-1"/>
        <advisory><severity>High</severity></advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:1"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:1">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:1"/>
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:1"/>
    </linux-def:dpkginfo_test>
  </tests>
  <objects>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:1">
      <linux-def:name>openssl</linux-def:name>
    </linux-def:dpkginfo_object>
  </objects>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:1">
      <linux-def:evr datatype="evr_string" operation="less than">3.0.13-0ubuntu3.5</linux-def:evr>
    </linux-def:dpkginfo_state>
  </states>
</oval_definitions>
"""

    records = parse_ubuntu_oval(payload, "noble", source_url="https://example/oval.xml.bz2")

    record = records[("noble", "CVE-2026-0001", "openssl")]
    assert record.fixed_version == "3.0.13-0ubuntu3.5"
    assert record.severity == "High"
    assert record.advisory_url == "https://ubuntu.com/security/notices/USN-9999-1"


def test_parse_ubuntu_osv_extracts_source_and_binary_packages():
    data = {
        "id": "UBUNTU-CVE-2026-0001",
        "upstream": ["CVE-2026-0001"],
        "severity": [{"type": "Ubuntu", "score": "high"}],
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "linux"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "ecosystem_specific": {
                    "binaries": [
                        {"binary_name": "linux-image-6.8.0-36-generic", "binary_version": "6.8.0-100.100"}
                    ]
                },
            }
        ],
        "references": [{"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2026-0001"}],
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        payload = json.dumps(data).encode("utf-8")
        info = tarfile.TarInfo("osv/UBUNTU-CVE-2026-0001.json")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    records = parse_ubuntu_osv(buffer.getvalue(), source_url="https://example/osv-all.tar.xz")

    source_record = records[("noble", "CVE-2026-0001", "linux")]
    binary_record = records[("noble", "CVE-2026-0001", "linux-image-6.8.0-36-generic")]
    assert source_record.status == "affected_no_fixed_version"
    assert binary_record.fixed_version == "6.8.0-100.100"
    assert binary_record.severity == "high"
