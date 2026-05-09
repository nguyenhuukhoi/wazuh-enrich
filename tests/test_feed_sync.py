import gzip
import json

from feed_sync import parse_epss_csv_gz, parse_kev_json


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
