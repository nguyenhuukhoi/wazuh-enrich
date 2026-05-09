import gzip
import json

from feed_sync import FeedSync, parse_epss_csv_gz, parse_kev_json, parse_poc_csv, parse_poc_json


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
