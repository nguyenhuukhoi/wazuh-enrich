# Wazuh Vulnerability Enrichment

English version: [README.md](README.md)

Service enrich vulnerability findings của Wazuh 4.14.x bằng CISA KEV, FIRST EPSS, PoC metadata và Ubuntu OVAL/OSV verification. Service đọc findings từ Wazuh Indexer theo batch, ghi enriched/summary index riêng, gửi alert dạng tổng hợp, và phục vụ dashboard overview.

Phase này không dùng NVD, không gọi EPSS API theo từng CVE, không query từng agent liên tục.

## Flow Production

```text
Wazuh vulnerability findings
        ↓
sync KEV + EPSS + PoC feed + Ubuntu OVAL/OSV
        ↓
enrich findings
        ↓
wazuh-vuln-enriched-YYYY.MM.DD
        ↓
CVE summary + Host summary + Host-CVE impact
        ↓
dashboard + aggregate alert
```

Daemon tự làm:

- Sync CISA KEV mỗi 1 giờ.
- Sync EPSS mỗi 24 giờ.
- Build PoC feed từ Exploit-DB metadata nếu bật `POC_BUILD.enabled`.
- Sync PoC metadata.
- Sync Ubuntu OVAL/OSV mỗi 24 giờ để xác minh package bị ảnh hưởng và fixed version.
- Watch Wazuh inventory index mỗi 60 giây và queue agent nào vừa đổi inventory.
- Chờ 180 giây trước khi xử lý agent đã đổi để Wazuh kịp cập nhật vulnerability state.
- Chỉ enrich lại agent đã đổi và update incremental các summary bị ảnh hưởng.
- Full refresh mỗi 24 giờ hoặc khi feed fingerprint đổi.
- Detect agent mới mỗi 5 phút.

## Index Được Tạo

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
wazuh-vuln-host-cve-impact-YYYY.MM.DD
```

Dashboard nên đọc các index này, không đọc trực tiếp `wazuh-states-vulnerabilities-*`.

## Incremental Theo Nhịp Wazuh

Daemon có 2 đường update:

```text
Inventory của agent N vừa đổi trong Wazuh
        -> chờ inventory_stabilization_seconds
        -> query Wazuh vulnerabilities chỉ của agent N
        -> replace enriched docs chỉ của agent N
        -> rebuild host summary chỉ của agent N
        -> rebuild CVE summary chỉ cho CVE agent N thêm hoặc mất
        -> rebuild host-CVE impact row chỉ của agent N
```

Khi feed đổi thì vẫn cần full refresh, vì KEV, EPSS, PoC hoặc Ubuntu metadata có thể làm đổi risk score của finding cũ trên mọi host.

```text
Inventory update -> refresh incremental theo agent
Feed update      -> full refresh
Daily fallback   -> full refresh
```

Inventory watcher lưu watermark trong `STATE_FILE`:

```text
last_inventory_timestamp
pending_inventory_agents
```

Nó không query từng agent liên tục. Nó query inventory index theo timestamp, lấy danh sách `agent.id` đã đổi, rồi xử lý theo batch có giới hạn.

## Cài Đặt

Clone project vào `/opt/wazuh-enrich`:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip

cd /opt
sudo git clone https://github.com/nguyenhuukhoi/wazuh-enrich.git
sudo chown -R "$USER:$USER" /opt/wazuh-enrich
cd /opt/wazuh-enrich

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
deactivate

sudo chown -R root:root /opt/wazuh-enrich
```

Nếu thư mục đã tồn tại:

```bash
cd /opt/wazuh-enrich
sudo chown -R "$USER:$USER" /opt/wazuh-enrich
git pull
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
deactivate
sudo chown -R root:root /opt/wazuh-enrich
```

## Cấu Hình

Tạo layout production:

```bash
sudo mkdir -p /etc/wazuh-enrich /var/lib/wazuh-enrich/cache /var/lib/wazuh-enrich/feeds
sudo cp config.yaml /etc/wazuh-enrich/config.yaml
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 600 /etc/wazuh-enrich/config.yaml
```

Các path mặc định:

```yaml
WAZUH_VULN_INDEX_PATTERN: wazuh-states-vulnerabilities-*
AGENT_INVENTORY_INDEX_PATTERNS:
  - wazuh-states-inventory-system-*
  - wazuh-states-inventory-packages-*
  - wazuh-states-inventory-hotfixes-*
  - wazuh-states-inventory-interfaces-*
  - wazuh-states-inventory-networks-*
INVENTORY_WATCH_TIMESTAMP_FIELDS:
  - "@timestamp"
  - event.created
  - timestamp

CACHE_DIR: /var/lib/wazuh-enrich/cache
STATE_FILE: /var/lib/wazuh-enrich/state.json
```

`AGENT_INVENTORY_INDEX_PATTERNS` dùng để enrich IP thật của agent và detect inventory update. Wazuh vulnerability document có thể ghi `agent.ip: 0.0.0.0`; inventory index thường có IP thật ở `agent.host.ip`, `host.ip`, `network.ip` hoặc field IP khác.

`INVENTORY_WATCH_TIMESTAMP_FIELDS` là danh sách field timestamp dùng để phát hiện inventory document mới. Giữ `@timestamp` ở đầu nếu Wazuh Indexer của bạn không dùng field custom.

Tạo environment file:

```bash
sudo nano /etc/wazuh-enrich/wazuh-enrich.env
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

Bảo vệ credential:

```bash
sudo chown root:root /etc/wazuh-enrich/wazuh-enrich.env
sudo chmod 600 /etc/wazuh-enrich/wazuh-enrich.env
```

Lab có thể bỏ SSL verify:

```yaml
VERIFY_SSL: false
```

Production nên dùng:

```yaml
VERIFY_SSL: true
WAZUH_CA_CERT: /path/to/root-ca.pem
```

## PoC Feed

Mặc định PoC build source là Exploit-DB metadata:

```yaml
POC_BUILD:
  enabled: false
  interval_seconds: 86400
  output_file: /var/lib/wazuh-enrich/feeds/cve_poc.csv
  exploitdb_csv: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
```

Bật auto build PoC feed:

```yaml
POC_BUILD:
  enabled: true
```

Build thủ công:

```bash
python3 tools/build_poc_feed.py \
  --exploitdb-csv https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
  --output /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

Field PoC được ghi vào enriched/summary docs:

```text
public_poc
poc_count
poc_references
poc_sources
```

## Ubuntu Impact Verification

Ubuntu verification dùng Canonical Ubuntu OVAL và Ubuntu OSV.

- OVAL cung cấp USN/fixed-version patch data.
- OSV mirror dữ liệu Ubuntu Security Tracker và có cả CVE/package đã biết bị ảnh hưởng dù chưa có security update.
- Service tải feed theo batch, cache local, không gọi Canonical theo từng CVE hoặc từng agent.

Field được ghi thêm:

```text
verification_status
verification_source
verification_confidence
vendor_source
vendor_advisory_url
vendor_fixed_version
vendor_severity
vendor_status
fix_available
fix_status
ubuntu_release
```

Ý nghĩa trạng thái:

- `confirmed_affected`: Wazuh finding đang active và Ubuntu OVAL cho thấy installed version thấp hơn fixed version.
- `likely_affected`: Ubuntu OVAL/OSV xác nhận CVE/package nhưng thiếu fixed version hoặc không đủ dữ liệu để compare.
- `installed_version_at_or_above_fixed`: installed version có vẻ đã bằng hoặc cao hơn fixed version. Nếu Wazuh vẫn báo active thì nên chạy lại vulnerability detection/check inventory.
- `vendor_not_found`: Wazuh báo CVE nhưng không tìm thấy CVE/package trong Ubuntu metadata cache của release đó.

Kernel Ubuntu: Wazuh thường báo binary package như `linux-image-6.8.0-36-generic`, còn Canonical hay tracking CVE theo source package `linux`. Enricher map các kernel binary package phổ biến về `linux` để tránh false `vendor_not_found`.

## Chạy Lần Đầu

Sync feed:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
```

Dry-run, không ghi index/state và không gửi Telegram:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --dry-run --log-format text enrich-all
```

Dry-run nhưng vẫn gửi Telegram thật nếu có alert:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py \
  --config /etc/wazuh-enrich/config.yaml \
  --dry-run \
  --dry-run-send-alerts \
  --log-format text \
  enrich-all
```

Gửi Telegram test message thật, không cần chạy enrichment:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml test-alert
```

Enrich thật:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
```

Kiểm tra index:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/_cat/indices/wazuh-vuln-*?v"
```

## systemd

Service chạy bằng root. Unit không set `User=` hoặc `Group=`.

Tạo unit:

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
EnvironmentFile=/etc/wazuh-enrich/wazuh-enrich.env
ExecStart=/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py --config /etc/wazuh-enrich/config.yaml daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Bật service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-enrich
sudo journalctl -u wazuh-enrich -f
```

Reload sau khi sửa `/etc/wazuh-enrich/config.yaml` hoặc `/etc/wazuh-enrich/wazuh-enrich.env`:

```bash
sudo systemctl reload wazuh-enrich
sudo journalctl -u wazuh-enrich -n 50 --no-pager
```

Reload gửi `SIGHUP` tới daemon. Process vẫn chạy, save state hiện tại, đọc lại config, reconnect Wazuh Indexer, tạo lại feed client, cập nhật schedule. Reload **không tải feed ngay** để tránh chạy tác vụ nặng bất ngờ; feed vẫn sync theo lịch, theo ETag/Last-Modified, hoặc khi bạn chạy `sync-feeds`. Nếu config mới lỗi, daemon giữ config cũ và log lỗi.

## CLI Chính

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-poc-feed
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-poc
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-agent --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml process-inventory-updates
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml detect-new-agents
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml test-alert
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml run-once
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml daemon
```

Log mặc định là JSON. Khi đọc terminal:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --log-format text --dry-run run-once
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

## Alert

Service gửi alert tổng hợp, không spam từng finding. Điều kiện chính:

- CVE nằm trong CISA KEV.
- Priority là P0.
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
```

## Dashboard

Tạo data view:

```text
wazuh-vuln-enriched-*        time field: enriched_at
wazuh-vuln-cve-summary-*     time field: updated_at
wazuh-vuln-host-cve-impact-* time field: updated_at
```

Dashboard import là tùy chọn và tách khỏi flow enrichment:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

Dashboard hiện có:

- Impact Filters.
- Public PoC CVEs Impacting This System.
- Hosts Affected by Public PoC CVEs.

## Kiểm Tra Nhanh

CVE có public PoC và đang impact hệ thống:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"term":{"public_poc":true}},{"range":{"affected_hosts_count":{"gte":1}}}]}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

Host bị ảnh hưởng bởi CVE có public PoC:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-host-cve-impact-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":100,"query":{"term":{"public_poc":true}},"sort":[{"risk_score":"desc"}]}'
```

## Troubleshooting

- Không có findings: kiểm tra `wazuh-states-vulnerabilities-*`.
- CISA bị chặn: set `CISA_KEV_FILE` trỏ tới local JSON mirror.
- PoC không hiện: bật `POC_BUILD`, chạy `build-poc-feed`, rồi `enrich-all`.
- Agent IP là `0.0.0.0`: chạy `debug-agent-ip`, kiểm tra inventory index có `agent.host.ip`, `host.ip`, `network.ip` hoặc field IP được discover.
- Dashboard chậm: dùng summary index, không build trực tiếp trên raw Wazuh state index.

Debug IP agent:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 002
```

## Test

```bash
python3 -m pytest -q
python3 -m py_compile config.py feed_sync.py risk.py alerts.py state.py summary.py wazuh_client.py vuln_enricher.py
```
