# Wazuh Vulnerability Enrichment

English version: [README.md](README.md)

Service enrich vulnerability findings cá»§a Wazuh 4.14.x báº±ng CISA KEV, FIRST EPSS, PoC metadata vÃ  Ubuntu OVAL verification. Service Ä‘á»c findings tá»« Wazuh Indexer theo batch, xÃ¡c minh package Ubuntu/fixed version báº±ng metadata chÃ­nh thá»‘ng cá»§a Canonical, ghi enriched/summary index riÃªng, gá»­i alert dáº¡ng tá»•ng há»£p, vÃ  phá»¥c vá»¥ dashboard overview.

KhÃ´ng dÃ¹ng NVD trong phase nÃ y. KhÃ´ng gá»i EPSS API theo tá»«ng CVE. KhÃ´ng query tá»«ng agent liÃªn tá»¥c.

## Production Flow

```text
Wazuh vulnerability findings
        â†“
sync KEV + EPSS + build/sync PoC feed + Ubuntu OVAL
        â†“
enrich findings
        â†“
wazuh-vuln-enriched-YYYY.MM.DD
        â†“
CVE summary + Host summary
        â†“
dashboard + aggregate alert
```

## Cap Nhat Incremental Theo Nhip Wazuh

Daemon co 2 duong update:

```text
Inventory cua agent N vua doi trong Wazuh
        -> cho inventory_stabilization_seconds
        -> query Wazuh vulnerabilities chi cua agent N
        -> replace enriched docs chi cua agent N
        -> rebuild host summary chi cua agent N
        -> rebuild CVE summary chi cho CVE agent N them hoac mat
        -> rebuild host-CVE impact row chi cua agent N
```

Khi feed doi thi van can full refresh, vi KEV, EPSS, PoC hoac Ubuntu metadata co the lam doi risk score cua finding cu tren moi host.

```text
Inventory update -> refresh incremental theo agent
Feed update      -> full refresh
Daily fallback   -> full refresh
```

Inventory watcher luu watermark trong `STATE_FILE`:

```text
last_inventory_timestamp
pending_inventory_agents
```

No khong query tung agent lien tuc. No query inventory index theo timestamp, lay danh sach `agent.id` da doi, roi xu ly theo batch co gioi han.

Daemon tá»± lÃ m:

- Sync CISA KEV má»—i 1 giá».
- Sync EPSS má»—i 24 giá».
- Build PoC feed tá»« Exploit-DB metadata náº¿u báº­t `POC_BUILD.enabled`.
- Sync PoC metadata.
- Watch Wazuh inventory index moi 60 giay va queue agent nao vua doi inventory.
- Cho 180 giay truoc khi xu ly agent da doi de Wazuh kip cap nhat vulnerability state.
- Chi enrich lai agent da doi va update incremental cac summary bi anh huong.
- Sync Ubuntu OVAL má»—i 24 giá» Ä‘á»ƒ xÃ¡c minh package bá»‹ áº£nh hÆ°á»Ÿng vÃ  fixed version.
- Enrich incremental má»—i 15 phÃºt.
- Full refresh má»—i 24 giá» hoáº·c khi feed Ä‘á»•i.
- Detect agent má»›i má»—i 5 phÃºt.

## Index ÄÆ°á»£c Táº¡o

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
wazuh-vuln-host-cve-impact-YYYY.MM.DD
```

Dashboard nÃªn Ä‘á»c 3 index nÃ y, khÃ´ng Ä‘á»c trá»±c tiáº¿p `wazuh-states-vulnerabilities-*`.

## CÃ i Äáº·t

CÃ i package cáº§n thiáº¿t vÃ  clone project vÃ o `/opt/wazuh-enrich`:

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

Náº¿u thÆ° má»¥c Ä‘Ã£ tá»“n táº¡i, update code:

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

## Cáº¥u HÃ¬nh

Credential Ä‘á»ƒ trong environment file, khÃ´ng hardcode vÃ o code.

Layout production nÃªn dÃ¹ng:

```bash
sudo mkdir -p /etc/wazuh-enrich /var/lib/wazuh-enrich/cache /var/lib/wazuh-enrich/feeds
sudo cp config.yaml /etc/wazuh-enrich/config.yaml
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 600 /etc/wazuh-enrich/config.yaml
```

Config máº·c Ä‘á»‹nh Ä‘Ã£ dÃ¹ng cÃ¡c runtime path production nÃ y:

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

POC_BUILD:
  output_file: /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

`AGENT_INVENTORY_INDEX_PATTERNS` dÃ¹ng Ä‘á»ƒ enrich IP tháº­t cá»§a agent theo batch. Wazuh vulnerability document cÃ³ thá»ƒ ghi `agent.ip: 0.0.0.0`; inventory index thÆ°á»ng cÃ³ IP tháº­t á»Ÿ `agent.host.ip`.

Táº¡o environment file:

```bash
sudo nano /etc/wazuh-enrich/wazuh-enrich.env
```

VÃ­ dá»¥ `/etc/wazuh-enrich/wazuh-enrich.env`:

```bash
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=your-password
WAZUH_CA_CERT=/etc/filebeat/certs/root-ca.pem
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

KhÃ³a quyá»n file credential:

```bash
sudo chown root:root /etc/wazuh-enrich/wazuh-enrich.env
sudo chmod 600 /etc/wazuh-enrich/wazuh-enrich.env
```

Náº¿u lab muá»‘n bá» SSL verify vá»›i Wazuh Indexer, sá»­a `/etc/wazuh-enrich/config.yaml`:

```yaml
VERIFY_SSL: false
```

Production nÃªn dÃ¹ng:

```yaml
VERIFY_SSL: true
WAZUH_CA_CERT: /path/to/root-ca.pem
```

## PoC Feed

Máº·c Ä‘á»‹nh config dÃ¹ng Exploit-DB metadata:

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

Muá»‘n daemon tá»± build PoC feed thÃ¬ báº­t:

```yaml
POC_BUILD:
  enabled: true
```

Náº¿u muá»‘n dÃ¹ng file local tá»± quáº£n lÃ½:

```bash
export POC_FEED_FILE=/var/lib/wazuh-enrich/feeds/cve_poc.csv
```

Format CSV:

```csv
cve,url,source
CVE-2026-0001,https://www.exploit-db.com/exploits/12345,Exploit-DB
```

Tool build thá»§ cÃ´ng váº«n cÃ³ sáºµn:

```bash
python3 tools/build_poc_feed.py \
  --exploitdb-csv https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
  --output /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

## Ubuntu Impact Verification

Pháº§n nÃ y Ä‘Æ°á»£c báº­t máº·c Ä‘á»‹nh. Service dÃ¹ng Ubuntu OVAL vÃ  Ubuntu OSV chÃ­nh thá»‘ng cá»§a Canonical Ä‘á»ƒ xÃ¡c minh CVE/package/fixed version cho Ubuntu agent. OVAL dÃ¹ng cho USN/fixed-version patch data. OSV mirror dá»¯ liá»‡u Ubuntu Security Tracker vÃ  cÃ³ cáº£ CVE/package Ä‘Ã£ biáº¿t bá»‹ áº£nh hÆ°á»Ÿng dÃ¹ chÆ°a cÃ³ security update. Feed Ä‘Æ°á»£c táº£i theo batch vÃ  cache local, khÃ´ng gá»i Canonical theo tá»«ng CVE hoáº·c tá»«ng agent.

Config máº·c Ä‘á»‹nh:

```yaml
UBUNTU_OVAL:
  enabled: true
  max_age_hours: 24
  base_url: https://security-metadata.canonical.com/oval
  osv_enabled: true
  osv_url: https://security-metadata.canonical.com/osv/osv-all.tar.xz
  osv_max_age_hours: 24
  releases:
    - noble   # Ubuntu 24.04
    - jammy   # Ubuntu 22.04
    - focal   # Ubuntu 20.04
  urls:
    noble: https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2
    jammy: https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2
    focal: https://security-metadata.canonical.com/oval/com.ubuntu.focal.usn.oval.xml.bz2
```

Field Ä‘Æ°á»£c ghi thÃªm vÃ o enriched/summary docs:

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

Ã nghÄ©a tráº¡ng thÃ¡i:

- `confirmed_affected`: Wazuh finding Ä‘ang active vÃ  Ubuntu OVAL xÃ¡c nháº­n installed version tháº¥p hÆ¡n fixed version.
- `likely_affected`: Ubuntu OVAL/OSV xÃ¡c nháº­n CVE/package, nhÆ°ng chÆ°a cÃ³ fixed version hoáº·c khÃ´ng Ä‘á»§ dá»¯ liá»‡u Ä‘á»ƒ compare version.
- `installed_version_at_or_above_fixed`: installed version cÃ³ váº» Ä‘Ã£ báº±ng hoáº·c cao hÆ¡n fixed version. Náº¿u Wazuh váº«n bÃ¡o active thÃ¬ nÃªn cháº¡y láº¡i vulnerability detection/check inventory.
- `vendor_not_found`: Wazuh bÃ¡o CVE nhÆ°ng khÃ´ng tÃ¬m tháº¥y CVE/package trong Ubuntu OVAL cache cá»§a release Ä‘Ã³.

Khi nhÃ¬n dashboard/report, báº¡n nÃªn Æ°u tiÃªn cÃ¡c dÃ²ng cÃ³ `confirmed_affected=true`, `fix_available=true`, kÃ¨m `KEV=true` hoáº·c `public_poc=true`.

RiÃªng Ubuntu kernel, Wazuh thÆ°á»ng tráº£ binary package nhÆ° `linux-image-6.8.0-36-generic`, cÃ²n Canonical tracking CVE theo source package nhÆ° `linux`. Enricher sáº½ map cÃ¡c kernel binary package phá»• biáº¿n vá» `linux` Ä‘á»ƒ trÃ¡nh bÃ¡o sai `vendor_not_found`.

## Cháº¡y Láº§n Äáº§u

Vá»›i layout production cháº¡y báº±ng root, cháº¡y kiá»ƒm tra nhÆ° sau:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
```

Dry-run Ä‘á»ƒ kiá»ƒm tra:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --dry-run --log-format text enrich-all
```

Dry-run mac dinh khong ghi index, khong save state, va khong gui Telegram. Neu muon test alert Telegram that trong luc van khong ghi index/state:

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

Gui mot Telegram test message that ma khong can chay enrichment:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml test-alert
```

Náº¿u á»•n, enrich tháº­t:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
```

Náº¿u muá»‘n cháº¡y thá»§ cÃ´ng á»Ÿ shell hiá»‡n táº¡i, nhá»› load env vÃ  truyá»n config:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
```

Kiá»ƒm tra index:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/_cat/indices/wazuh-vuln-*?v"
```

## Cháº¡y Production Báº±ng systemd

Service nÃ y chá»§ Ä‘á»™ng cháº¡y báº±ng root. Unit khÃ´ng set `User=` hoáº·c `Group=`, nÃªn systemd máº·c Ä‘á»‹nh dÃ¹ng root.

Äáº£m báº£o runtime directories thuá»™c root trÆ°á»›c khi báº­t service:

```bash
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 700 /var/lib/wazuh-enrich
```

Táº¡o service:

```bash
sudo nano /etc/systemd/system/wazuh-enrich.service
```

Ná»™i dung:

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

Báº­t service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-enrich
sudo systemctl status wazuh-enrich
```

Xem log:

```bash
sudo journalctl -u wazuh-enrich -f
```

Reload service sau khi sua `/etc/wazuh-enrich/config.yaml` hoac `/etc/wazuh-enrich/wazuh-enrich.env`:

```bash
sudo systemctl reload wazuh-enrich
sudo journalctl -u wazuh-enrich -n 50 --no-pager
```

Reload gui `SIGHUP` toi daemon. Process van chay, save state hien tai, doc lai config, reconnect Wazuh Indexer, rebuild feed client, va giu config cu neu config moi bi loi.

## CLI ChÃ­nh

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

Log máº·c Ä‘á»‹nh lÃ  JSON. Khi Ä‘á»c terminal:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --log-format text --dry-run run-once
```

## Priority

```text
P0: KEV=true, hoáº·c EPSS >= 0.7 vÃ  CVSS >= 8
P1: EPSS >= 0.3, hoáº·c CVSS >= 8
P2: CVSS >= 6
P3: cÃ²n láº¡i
```

Risk score:

```text
(epss_score * 50) + (cvss_score * 3) + (30 náº¿u kev=true)
```

PoC hiá»‡n lÃ  enrichment signal:

```text
public_poc
poc_count
poc_references
poc_sources
```

## Alert

Alert chá»‰ gá»­i khi cÃ³ tÃ­n hiá»‡u quan trá»ng:

- CVE náº±m trong KEV.
- Priority P0.
- EPSS vÆ°á»£t threshold.
- Agent má»›i cÃ³ P0/P1.
- CVE chuyá»ƒn tá»« non-KEV sang KEV.
- CVE áº£nh hÆ°á»Ÿng nhiá»u agent.

VÃ­ dá»¥:

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

Báº¡n cÃ³ thá»ƒ tá»± táº¡o dashboard thá»§ cÃ´ng hoáº·c import saved objects trong `dashboard/`.

Data views cáº§n cÃ³:

```text
wazuh-vuln-enriched-*       time field: enriched_at
wazuh-vuln-cve-summary-*    time field: updated_at
wazuh-vuln-host-cve-impact-* time field: updated_at
```

Dashboard import chá»§ Ä‘á»™ng chá»‰ giá»¯ cÃ¡c panel cáº§n thiáº¿t:

- Impact Filters.
- Public PoC CVEs Impacting This System.
- Hosts Affected by Public PoC CVEs.

Náº¿u dÃ¹ng import:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

Import dashboard khÃ´ng náº±m trong flow enrich/daemon. Dashboard chá»‰ Ä‘á»c index Ä‘Ã£ Ä‘Æ°á»£c service cáº­p nháº­t.

Panel filter vÃ  báº£ng host impact láº¥y tá»« `wazuh-vuln-host-cve-impact-*`. Index nÃ y cÃ³ Ä‘Ãºng 1 document cho má»—i `cve_id + agent_id`, nÃªn báº£ng host khÃ´ng bá»‹ duplicate theo package/version. CÃ³ 2 dropdown:

```text
impact_cve_id
impact_host
```

Hai field nÃ y chá»‰ Ä‘Æ°á»£c ghi khi `public_poc:true`, nÃªn dropdown khÃ´ng list CVE global hoáº·c CVE khÃ´ng impact.
Control import dÃ¹ng subfield `.keyword` Ä‘á»ƒ terms aggregation khÃ´ng bá»‹ lá»—i `Bad Request`.
Data view enriched dÃ¹ng `enriched_at` lÃ m time field Ä‘á»ƒ báº£ng host impact hiá»ƒn thá»‹ tráº¡ng thÃ¡i enrich má»›i nháº¥t, khÃ´ng bá»‹ áº©n host vÃ¬ `detected_at` quÃ¡ cÅ© so vá»›i time picker.

Panel CVE summary láº¥y tá»« `wazuh-vuln-cve-summary-*` vá»›i Ä‘iá»u kiá»‡n:

```text
public_poc:true and affected_hosts_count > 0
```

NhÆ° váº­y dashboard chá»‰ hiá»‡n CVE cÃ³ PoC cÃ´ng khai vÃ  Ä‘ang tháº­t sá»± áº£nh hÆ°á»Ÿng tá»›i host/package trong há»‡ thá»‘ng, khÃ´ng hiá»‡n danh sÃ¡ch PoC global ngoÃ i internet.

## Query Kiá»ƒm Tra Nhanh

Top CVE nguy hiá»ƒm:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":10,"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

CVE cÃ³ public PoC vÃ  Ä‘ang impact há»‡ thá»‘ng:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"term":{"public_poc":true}},{"range":{"affected_hosts_count":{"gte":1}}}]}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

Host bá»‹ áº£nh hÆ°á»Ÿng bá»Ÿi CVE cÃ³ public PoC:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-enriched-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":100,"query":{"term":{"public_poc":true}},"sort":[{"risk_score":"desc"}]}'
```

## Troubleshooting

KhÃ´ng cÃ³ finding:

- Kiá»ƒm tra index `wazuh-states-vulnerabilities-*`.
- Kiá»ƒm tra Wazuh Vulnerability Detection Ä‘Ã£ báº­t index.

CISA bá»‹ cháº·n:

- Set `CISA_KEV_FILE` tá»›i JSON local.
- Hoáº·c dÃ¹ng mirror ná»™i bá»™.

PoC khÃ´ng hiá»‡n:

- Báº­t `POC_BUILD.enabled: true` hoáº·c set `POC_FEED_FILE`.
- Cháº¡y `python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-poc-feed`.
- Cháº¡y `python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all`.
- Kiá»ƒm tra field `public_poc:true` trong `wazuh-vuln-cve-summary-*`.

Agent IP hiá»‡n `0.0.0.0`:

- Cháº¡y `debug-agent-ip`, kiá»ƒm tra inventory index cÃ³ `agent.host.ip`, `host.ip`, `network.ip`, hoáº·c field IP khÃ¡c mÃ  tool discovery tÃ¬m Ä‘Æ°á»£c.
- Cháº¡y láº¡i `enrich-all`.
- Enricher sáº½ join cÃ¡c inventory index Ä‘Ã³ theo `agent.id` Ä‘á»ƒ láº¥y IP tháº­t.

Query kiá»ƒm tra nhanh agent `002` báº±ng enricher:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 002
```

Query trá»±c tiáº¿p Wazuh Indexer tÆ°Æ¡ng Ä‘Æ°Æ¡ng:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-states-inventory-system-*,wazuh-states-inventory-interfaces-*,wazuh-states-inventory-networks-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":5,"query":{"term":{"agent.id":"002"}},"_source":["agent.id","agent.name","agent.host.ip","host.ip","network.*","related.ip","interface.*"]}'
```

Dashboard cháº­m:

- Äáº£m báº£o panel Ä‘á»c summary index.
- KhÃ´ng build dashboard trá»±c tiáº¿p trÃªn raw `wazuh-states-vulnerabilities-*`.

## Test

```bash
python3 -m pytest -q
python3 -m py_compile config.py feed_sync.py risk.py alerts.py state.py summary.py wazuh_client.py vuln_enricher.py
```
