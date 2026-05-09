# Wazuh Vulnerability Enrichment

English version: [README.md](README.md)

Service enrich vulnerability findings của Wazuh 4.14.x bằng CISA KEV, FIRST EPSS và PoC metadata. Service đọc findings từ Wazuh Indexer theo batch, ghi enriched/summary index riêng, gửi alert dạng tổng hợp, và phục vụ dashboard overview.

Không dùng NVD trong phase này. Không gọi EPSS API theo từng CVE. Không query từng agent liên tục.

## Production Flow

```text
Wazuh vulnerability findings
        ↓
sync KEV + EPSS + build/sync PoC feed
        ↓
enrich findings
        ↓
wazuh-vuln-enriched-YYYY.MM.DD
        ↓
CVE summary + Host summary
        ↓
dashboard + aggregate alert
```

Daemon tự làm:

- Sync CISA KEV mỗi 1 giờ.
- Sync EPSS mỗi 24 giờ.
- Build PoC feed từ Exploit-DB metadata nếu bật `POC_BUILD.enabled`.
- Sync PoC metadata.
- Enrich incremental mỗi 15 phút.
- Full refresh mỗi 24 giờ hoặc khi feed đổi.
- Detect agent mới mỗi 5 phút.

## Index Được Tạo

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
```

Dashboard nên đọc 3 index này, không đọc trực tiếp `wazuh-states-vulnerabilities-*`.

## Cài Đặt

```bash
sudo mkdir -p /opt/wazuh-enrich
sudo chown -R "$USER:$USER" /opt/wazuh-enrich
cd /opt/wazuh-enrich

python3.10 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Nếu bạn chạy từ repo hiện tại:

```bash
cd /opt/wazuh-enrich
git pull
```

## Cấu Hình

Credential để trong environment file, không hardcode vào code.

Tạo file:

```bash
sudo nano /etc/wazuh-enrich.env
```

Ví dụ:

```bash
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=your-password
WAZUH_CA_CERT=/etc/filebeat/certs/root-ca.pem
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Nếu lab muốn bỏ SSL verify với Wazuh Indexer, sửa `config.yaml`:

```yaml
VERIFY_SSL: false
```

Production nên dùng:

```yaml
VERIFY_SSL: true
WAZUH_CA_CERT: /path/to/root-ca.pem
```

## PoC Feed

Mặc định config dùng Exploit-DB metadata:

```yaml
POC_BUILD:
  enabled: false
  interval_seconds: 86400
  output_file: feeds/cve_poc.csv
  exploitdb_csv: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
  # Optional extra sources:
  # nuclei_templates: https://github.com/projectdiscovery/nuclei-templates
  # poc_in_github: https://github.com/nomi-sec/PoC-in-GitHub
  # trickest_cve: https://github.com/trickest/cve
```

Muốn daemon tự build PoC feed thì bật:

```yaml
POC_BUILD:
  enabled: true
```

Nếu muốn dùng file local tự quản lý:

```bash
export POC_FEED_FILE=/opt/wazuh-enrich/feeds/cve_poc.csv
```

Format CSV:

```csv
cve,url,source
CVE-2026-0001,https://www.exploit-db.com/exploits/12345,Exploit-DB
```

Tool build thủ công vẫn có sẵn:

```bash
python3 tools/build_poc_feed.py \
  --exploitdb-csv https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
  --output feeds/cve_poc.csv
```

## Chạy Lần Đầu

Load env:

```bash
set -a
. /etc/wazuh-enrich.env
set +a
```

Sync feed:

```bash
python3 vuln_enricher.py sync-feeds
```

Dry-run để kiểm tra:

```bash
python3 vuln_enricher.py --dry-run --log-format text enrich-all
```

Nếu ổn, enrich thật:

```bash
python3 vuln_enricher.py enrich-all
```

Kiểm tra index:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/_cat/indices/wazuh-vuln-*?v"
```

## Chạy Production Bằng systemd

Tạo user riêng nếu muốn:

```bash
sudo useradd --system --home /opt/wazuh-enrich --shell /usr/sbin/nologin wazuh-enrich || true
sudo chown -R wazuh-enrich:wazuh-enrich /opt/wazuh-enrich
```

Tạo service:

```bash
sudo nano /etc/systemd/system/wazuh-enrich.service
```

Nội dung:

```ini
[Unit]
Description=Wazuh vulnerability enrichment service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/wazuh-enrich
EnvironmentFile=/etc/wazuh-enrich.env
ExecStart=/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py daemon
Restart=always
RestartSec=10
User=wazuh-enrich
Group=wazuh-enrich

[Install]
WantedBy=multi-user.target
```

Bật service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-enrich
sudo systemctl status wazuh-enrich
```

Xem log:

```bash
sudo journalctl -u wazuh-enrich -f
```

## CLI Chính

```bash
python3 vuln_enricher.py sync-feeds
python3 vuln_enricher.py build-poc-feed
python3 vuln_enricher.py sync-poc
python3 vuln_enricher.py enrich-all
python3 vuln_enricher.py enrich-agent --agent-id 001
python3 vuln_enricher.py detect-new-agents
python3 vuln_enricher.py run-once
python3 vuln_enricher.py daemon
```

Log mặc định là JSON. Khi đọc terminal:

```bash
python3 vuln_enricher.py --log-format text --dry-run run-once
```

## Priority

```text
P0: KEV=true, hoặc EPSS >= 0.7 và CVSS >= 8
P1: EPSS >= 0.3, hoặc CVSS >= 8
P2: CVSS >= 6
P3: còn lại
```

Risk score:

```text
(epss_score * 50) + (cvss_score * 3) + (30 nếu kev=true)
```

PoC hiện là enrichment signal:

```text
public_poc
poc_count
poc_references
poc_sources
```

## Alert

Alert chỉ gửi khi có tín hiệu quan trọng:

- CVE nằm trong KEV.
- Priority P0.
- EPSS vượt threshold.
- Agent mới có P0/P1.
- CVE chuyển từ non-KEV sang KEV.
- CVE ảnh hưởng nhiều agent.

Ví dụ:

```text
CRITICAL - Exploited CVEs detected

Summary:
- Affected agents: 2
- P0 CVEs: 4
- KEV CVEs: 2
- Public PoC CVEs: 1
- EPSS >= 0.7: 3

Top CVEs:
1. CVE-2025-0001 | KEV=yes | PoC=yes | EPSS=0.94 | CVSS=9.8 | hosts=72 | package=openssl
```

## Dashboard

Bạn có thể tự tạo dashboard thủ công hoặc import saved objects trong `dashboard/`.

Data views cần có:

```text
wazuh-vuln-enriched-*       time field: detected_at
wazuh-vuln-cve-summary-*    time field: updated_at
wazuh-vuln-host-summary-*   time field: updated_at
```

Panel quan trọng nên có:

- Public PoC CVEs Impacting This System.
- Hosts Affected by Public PoC CVEs.
- CVE Impact Overview.
- Host Impact Overview.
- P0/KEV/Public PoC metrics.
- CVE count by priority/year.

Nếu dùng import:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

Import dashboard không nằm trong flow enrich/daemon. Dashboard chỉ đọc index đã được service cập nhật.

## Query Kiểm Tra Nhanh

Top CVE nguy hiểm:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":10,"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

CVE có public PoC:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"term":{"public_poc":true}},"sort":[{"risk_score":"desc"}]}'
```

Host bị ảnh hưởng bởi CVE có public PoC:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-enriched-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":100,"query":{"term":{"public_poc":true}},"sort":[{"risk_score":"desc"}]}'
```

## Troubleshooting

Không có finding:

- Kiểm tra index `wazuh-states-vulnerabilities-*`.
- Kiểm tra Wazuh Vulnerability Detection đã bật index.

CISA bị chặn:

- Set `CISA_KEV_FILE` tới JSON local.
- Hoặc dùng mirror nội bộ.

PoC không hiện:

- Bật `POC_BUILD.enabled: true` hoặc set `POC_FEED_FILE`.
- Chạy `python3 vuln_enricher.py build-poc-feed`.
- Chạy `python3 vuln_enricher.py enrich-all`.
- Kiểm tra field `public_poc:true` trong `wazuh-vuln-cve-summary-*`.

Dashboard chậm:

- Đảm bảo panel đọc summary index.
- Không build dashboard trực tiếp trên raw `wazuh-states-vulnerabilities-*`.

## Test

```bash
python3 -m pytest -q
python3 -m py_compile config.py feed_sync.py risk.py alerts.py state.py summary.py wazuh_client.py vuln_enricher.py
```
