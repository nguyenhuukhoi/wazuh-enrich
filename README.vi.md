# Wazuh Vulnerability Enrichment

English version: [README.md](README.md)

Service enrich vulnerability findings của Wazuh 4.14.x bằng CISA KEV, FIRST EPSS, PoC metadata và Ubuntu OVAL verification. Service đọc findings từ Wazuh Indexer theo batch, xác minh package Ubuntu/fixed version bằng metadata chính thống của Canonical, ghi enriched/summary index riêng, gửi alert dạng tổng hợp, và phục vụ dashboard overview.

Không dùng NVD trong phase này. Không gọi EPSS API theo từng CVE. Không query từng agent liên tục.

## Production Flow

```text
Wazuh vulnerability findings
        ↓
sync KEV + EPSS + build/sync PoC feed + Ubuntu OVAL
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
- Sync Ubuntu OVAL mỗi 24 giờ để xác minh package bị ảnh hưởng và fixed version.
- Enrich incremental mỗi 15 phút.
- Full refresh mỗi 24 giờ hoặc khi feed đổi.
- Detect agent mới mỗi 5 phút.

## Index Được Tạo

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
wazuh-vuln-host-cve-impact-YYYY.MM.DD
```

Dashboard nên đọc 3 index này, không đọc trực tiếp `wazuh-states-vulnerabilities-*`.

## Cài Đặt

Cài package cần thiết và clone project vào `/opt/wazuh-enrich`:

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

Nếu thư mục đã tồn tại, update code:

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

Credential để trong environment file, không hardcode vào code.

Layout production nên dùng:

```bash
sudo mkdir -p /etc/wazuh-enrich /var/lib/wazuh-enrich/cache /var/lib/wazuh-enrich/feeds
sudo cp config.yaml /etc/wazuh-enrich/config.yaml
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 600 /etc/wazuh-enrich/config.yaml
```

Config mặc định đã dùng các runtime path production này:

```yaml
WAZUH_VULN_INDEX_PATTERN: wazuh-states-vulnerabilities-*
AGENT_INVENTORY_INDEX_PATTERNS:
  - wazuh-states-inventory-system-*
  - wazuh-states-inventory-interfaces-*
  - wazuh-states-inventory-networks-*

CACHE_DIR: /var/lib/wazuh-enrich/cache
STATE_FILE: /var/lib/wazuh-enrich/state.json

POC_BUILD:
  output_file: /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

`AGENT_INVENTORY_INDEX_PATTERNS` dùng để enrich IP thật của agent theo batch. Wazuh vulnerability document có thể ghi `agent.ip: 0.0.0.0`; inventory index thường có IP thật ở `agent.host.ip`.

Tạo environment file:

```bash
sudo nano /etc/wazuh-enrich/wazuh-enrich.env
```

Ví dụ `/etc/wazuh-enrich/wazuh-enrich.env`:

```bash
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=your-password
WAZUH_CA_CERT=/etc/filebeat/certs/root-ca.pem
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Khóa quyền file credential:

```bash
sudo chown root:root /etc/wazuh-enrich/wazuh-enrich.env
sudo chmod 600 /etc/wazuh-enrich/wazuh-enrich.env
```

Nếu lab muốn bỏ SSL verify với Wazuh Indexer, sửa `/etc/wazuh-enrich/config.yaml`:

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
  output_file: /var/lib/wazuh-enrich/feeds/cve_poc.csv
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
export POC_FEED_FILE=/var/lib/wazuh-enrich/feeds/cve_poc.csv
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
  --output /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

## Ubuntu Impact Verification

Phần này được bật mặc định. Service dùng Ubuntu OVAL chính thống của Canonical để xác minh CVE/package/fixed version cho Ubuntu agent. Feed được tải theo batch và cache local, không gọi Canonical theo từng CVE hoặc từng agent.

Config mặc định:

```yaml
UBUNTU_OVAL:
  enabled: true
  max_age_hours: 24
  base_url: https://security-metadata.canonical.com/oval
  releases:
    - noble   # Ubuntu 24.04
    - jammy   # Ubuntu 22.04
    - focal   # Ubuntu 20.04
  urls:
    noble: https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2
    jammy: https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2
    focal: https://security-metadata.canonical.com/oval/com.ubuntu.focal.usn.oval.xml.bz2
```

Field được ghi thêm vào enriched/summary docs:

```text
verification_status
verification_source
verification_confidence
vendor_source
vendor_advisory_url
vendor_fixed_version
vendor_severity
fix_available
fix_status
ubuntu_release
```

Ý nghĩa trạng thái:

- `confirmed_affected`: Wazuh finding đang active và Ubuntu OVAL xác nhận installed version thấp hơn fixed version.
- `likely_affected`: Ubuntu OVAL xác nhận CVE/package, nhưng chưa có fixed version hoặc không đủ dữ liệu để compare version.
- `installed_version_at_or_above_fixed`: installed version có vẻ đã bằng hoặc cao hơn fixed version. Nếu Wazuh vẫn báo active thì nên chạy lại vulnerability detection/check inventory.
- `vendor_not_found`: Wazuh báo CVE nhưng không tìm thấy CVE/package trong Ubuntu OVAL cache của release đó.

Khi nhìn dashboard/report, bạn nên ưu tiên các dòng có `confirmed_affected=true`, `fix_available=true`, kèm `KEV=true` hoặc `public_poc=true`.

## Chạy Lần Đầu

Với layout production chạy bằng root, chạy kiểm tra như sau:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
```

Dry-run để kiểm tra:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --dry-run --log-format text enrich-all
```

Nếu ổn, enrich thật:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
```

Nếu muốn chạy thủ công ở shell hiện tại, nhớ load env và truyền config:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
```

Kiểm tra index:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/_cat/indices/wazuh-vuln-*?v"
```

## Chạy Production Bằng systemd

Service này chủ động chạy bằng root. Unit không set `User=` hoặc `Group=`, nên systemd mặc định dùng root.

Đảm bảo runtime directories thuộc root trước khi bật service:

```bash
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 700 /var/lib/wazuh-enrich
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
EnvironmentFile=/etc/wazuh-enrich/wazuh-enrich.env
ExecStart=/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py --config /etc/wazuh-enrich/config.yaml daemon
Restart=always
RestartSec=10

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
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-poc-feed
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-poc
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-agent --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml detect-new-agents
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
wazuh-vuln-enriched-*       time field: enriched_at
wazuh-vuln-cve-summary-*    time field: updated_at
wazuh-vuln-host-cve-impact-* time field: updated_at
```

Dashboard import chủ động chỉ giữ các panel cần thiết:

- Impact Filters.
- Public PoC CVEs Impacting This System.
- Hosts Affected by Public PoC CVEs.

Nếu dùng import:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

Import dashboard không nằm trong flow enrich/daemon. Dashboard chỉ đọc index đã được service cập nhật.

Panel filter và bảng host impact lấy từ `wazuh-vuln-host-cve-impact-*`. Index này có đúng 1 document cho mỗi `cve_id + agent_id`, nên bảng host không bị duplicate theo package/version. Có 2 dropdown:

```text
impact_cve_id
impact_host
```

Hai field này chỉ được ghi khi `public_poc:true`, nên dropdown không list CVE global hoặc CVE không impact.
Control import dùng subfield `.keyword` để terms aggregation không bị lỗi `Bad Request`.
Data view enriched dùng `enriched_at` làm time field để bảng host impact hiển thị trạng thái enrich mới nhất, không bị ẩn host vì `detected_at` quá cũ so với time picker.

Panel CVE summary lấy từ `wazuh-vuln-cve-summary-*` với điều kiện:

```text
public_poc:true and affected_hosts_count > 0
```

Như vậy dashboard chỉ hiện CVE có PoC công khai và đang thật sự ảnh hưởng tới host/package trong hệ thống, không hiện danh sách PoC global ngoài internet.

## Query Kiểm Tra Nhanh

Top CVE nguy hiểm:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":10,"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

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
- Chạy `python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-poc-feed`.
- Chạy `python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all`.
- Kiểm tra field `public_poc:true` trong `wazuh-vuln-cve-summary-*`.

Agent IP hiện `0.0.0.0`:

- Chạy `debug-agent-ip`, kiểm tra inventory index có `agent.host.ip`, `host.ip`, `network.ip`, hoặc field IP khác mà tool discovery tìm được.
- Chạy lại `enrich-all`.
- Enricher sẽ join các inventory index đó theo `agent.id` để lấy IP thật.

Query kiểm tra nhanh agent `002` bằng enricher:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 002
```

Query trực tiếp Wazuh Indexer tương đương:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-states-inventory-system-*,wazuh-states-inventory-interfaces-*,wazuh-states-inventory-networks-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":5,"query":{"term":{"agent.id":"002"}},"_source":["agent.id","agent.name","agent.host.ip","host.ip","network.*","related.ip","interface.*"]}'
```

Dashboard chậm:

- Đảm bảo panel đọc summary index.
- Không build dashboard trực tiếp trên raw `wazuh-states-vulnerabilities-*`.

## Test

```bash
python3 -m pytest -q
python3 -m py_compile config.py feed_sync.py risk.py alerts.py state.py summary.py wazuh_client.py vuln_enricher.py
```
