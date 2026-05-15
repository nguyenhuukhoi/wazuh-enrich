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
- Khi daemon start lần đầu, chạy full refresh một lần rồi mark `startup_full_refresh_done` trong `STATE_FILE`.
- Full refresh mỗi 24 giờ hoặc khi feed fingerprint đổi.
- Tự full refresh một lần khi daily enriched index của ngày hiện tại chưa có document.
- Detect agent mới mỗi 5 phút.

## Index Được Tạo

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
wazuh-vuln-host-cve-impact-YYYY.MM.DD
wazuh-vuln-enriched-latest
wazuh-vuln-cve-summary-latest
wazuh-vuln-host-summary-latest
wazuh-vuln-host-cve-impact-latest
```

Daily index giữ lịch sử theo ngày. `*-latest` giữ trạng thái hiện tại và là index dashboard nên đọc. Dashboard không nên đọc trực tiếp `wazuh-states-vulnerabilities-*`.

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
Enrichment cycle -> đối chiếu với Wazuh current state để xóa finding đã hết
Feed update      -> full refresh
First startup    -> full refresh một lần, rồi mark startup_full_refresh_done
Daily fallback   -> full refresh
```

Mỗi incremental enrichment cycle sẽ so sánh `wazuh-vuln-enriched-latest` với current vulnerability state của Wazuh. Nếu Wazuh không còn finding đó nữa, document stale trong `*-latest` sẽ bị xóa trước khi rebuild CVE/host summary. Nhờ vậy dashboard cập nhật đúng sau khi patch mà không phải chờ scheduled full refresh tiếp theo.

Startup full refresh dùng để tạo snapshot ban đầu cho dashboard. Nó chỉ chạy một lần, sau đó ghi `startup_full_refresh_done: true` vào `STATE_FILE`. Reload config không chạy lại, restart service cũng không chạy lại vì state đã được mark. Nếu muốn ép chạy startup full refresh lại, set `startup_full_refresh_done` về `false` trong state file hoặc chạy `enrich-all` thủ công.

Daily fallback cần vì enriched index được tách theo ngày. Sau 00:00, `wazuh-vuln-enriched-YYYY.MM.DD` là index mới. Nếu daemon thấy index hôm nay chưa có document và chưa từng refresh index đó, nó sẽ chạy full refresh một lần rồi lưu tên index vào `STATE_FILE` bằng key `last_daily_full_refresh_index`.

Ví dụ:

```json
{
  "last_daily_full_refresh_index": "wazuh-vuln-enriched-2026.05.12"
}
```

State key này có nghĩa là: "daemon đã chạy fallback full refresh một lần cho daily index này rồi". Ở vòng loop sau, nếu index đó vẫn rỗng, daemon sẽ không chạy full refresh lại nữa. Việc này cần thiết vì có trường hợp hệ thống thật sự không có vulnerability finding; nếu không có guard này, daemon sẽ thấy index rỗng ở mỗi vòng loop và full refresh Wazuh Indexer liên tục.

Quyết định daily fallback:

```text
Index enriched hôm nay rỗng + chưa mark trong state -> chạy full refresh một lần
Index enriched hôm nay rỗng + đã mark rồi           -> bỏ qua full refresh
Sang ngày mới, index name đổi                       -> cho phép fallback full refresh một lần nữa
```

Inventory watcher lưu watermark trong `STATE_FILE`:

```text
last_inventory_timestamp
pending_inventory_agents
last_daily_full_refresh_index
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
WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USERNAME=wazuh
WAZUH_API_PASSWORD=your-wazuh-api-password
WAZUH_API_CA_CERT=
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
exploitability_status
exposure_status
patch_decision
impact_assessment
recommended_action
mitigation_status
workaround_verified
workaround_id
workaround_source
workaround_source_url
workaround_executor
workaround_playbook
workaround_apply_status
workaround_verify_status
workaround_verified_at
workaround_check_passed
workaround_check_failed
workaround_passed_checks
workaround_failed_checks
workaround_policy_ids
workaround_check_ids
workaround_check_titles
```

Ý nghĩa trạng thái:

- `confirmed_affected`: Wazuh finding đang active và Ubuntu OVAL cho thấy installed version thấp hơn fixed version.
- `likely_affected`: Ubuntu OVAL/OSV xác nhận CVE/package nhưng thiếu fixed version hoặc không đủ dữ liệu để compare.
- `installed_version_at_or_above_fixed`: installed version có vẻ đã bằng hoặc cao hơn fixed version. Nếu Wazuh vẫn báo active thì nên chạy lại vulnerability detection/check inventory.
- `vendor_not_found`: Wazuh báo CVE nhưng không tìm thấy CVE/package trong Ubuntu metadata cache của release đó.

Kernel Ubuntu: Wazuh thường báo binary package như `linux-image-6.8.0-36-generic`, còn Canonical hay tracking CVE theo source package `linux`. Enricher map các kernel binary package phổ biến về `linux` để tránh false `vendor_not_found`.

Kernel có một rule riêng rất quan trọng. Sau khi bạn patch và reboot sang kernel mới, package kernel cũ như `linux-image-6.8.0-36-generic` có thể vẫn còn installed. Wazuh vẫn có thể báo CVE trên package cũ đó. Khi enricher thấy package kernel bị CVE không phải kernel đang chạy, nó sẽ không coi là `patch_now`, mà gắn:

```text
exposure_status: non_running_kernel_installed
patch_decision: cleanup_old_kernel
```

Ý nghĩa: host đang không chạy kernel vulnerable đó, nhưng bạn nên giữ kernel đã fix làm default boot và purge old `linux-image-*` / `linux-modules-*` packages. Sau khi xóa kernel cũ và Wazuh inventory/vulnerability detection chạy lại, finding đó mới biến mất khỏi Wazuh.

`patch_decision` là field chính để quyết định có nên patch hệ thống không:

```text
patch_now       -> vendor xác nhận affected và threat/exposure cao
workaround_active -> package vẫn vulnerable, nhưng Ansible đã verify workaround trên host
patch_scheduled -> vendor xác nhận affected và đã có fixed version
cleanup_old_kernel -> kernel package cũ còn installed nhưng không phải kernel đang chạy
monitor         -> affected hoặc có thể affected, nhưng exploitability thấp hoặc chưa có fix
no_action       -> installed version đã bằng hoặc cao hơn fixed version của Ubuntu
needs_review    -> Wazuh báo finding nhưng vendor metadata chưa xác nhận đúng package/release
```

Logic này cố ý thận trọng:

- `KEV=yes` nghĩa là đã bị khai thác ngoài thực tế, nên ưu tiên hơn EPSS thấp.
- `public_poc=yes` chỉ tăng độ gấp sau khi CVE đó được xác định đang impact hệ thống.
- `vendor_not_found` nhưng threat cao sẽ thành `needs_review`, không tự động coi là `patch_now`.
- Kernel finding chỉ thật sự gấp nếu vulnerable package khớp với running kernel. Kernel cũ không còn running sẽ được xem là việc cleanup, không phải runtime critical impact.

## Verify Workaround Bằng Ansible

Dùng Ansible để apply/verify workaround, còn `wazuh-enrich` chỉ đọc kết quả verification. App không SSH vào agent và không cần SCA/osquery cho flow này.

Config:

```yaml
WORKAROUND_FEED_FILE: /var/lib/wazuh-enrich/feeds/cve_workarounds.yaml
WORKAROUND_RESULT_FILE: /var/lib/wazuh-enrich/feeds/workaround_results.json
SCA_WORKAROUND_ENABLED: false
WAZUH_SCA_INDEX_PATTERN: wazuh-states-sca-*,wazuh-enrich-sca-results-*
WORKAROUND_VERIFICATION_PRIORITY: sca_first
WORKAROUND_COLLECTOR:
  enabled: false
  output_file: /var/lib/wazuh-enrich/feeds/cve_workarounds.yaml
  sources:
    - ubuntu
```

`WORKAROUND_VERIFICATION_PRIORITY` quyết định khi cùng một `agent_id + cve_id` có cả Ansible và SCA verification:

```text
sca_first     -> SCA override Ansible. Đây là behavior cũ.
ansible_first -> Ansible override SCA.
```

## Sync SCA Index Tự Tạo

Một số môi trường Wazuh 4.14 có SCA pass trong agent/UI nhưng không tạo index `wazuh-states-sca-*` trong Wazuh Indexer. `wazuh-enrich` có thể tự gọi Wazuh Manager API, lấy SCA policy/check result, rồi ghi vào index riêng:

```yaml
WAZUH_API_URL: https://127.0.0.1:55000
WAZUH_API_USERNAME: ${WAZUH_API_USERNAME}
WAZUH_API_PASSWORD: ${WAZUH_API_PASSWORD}
WAZUH_API_VERIFY_SSL: false

SCA_WORKAROUND_ENABLED: true
WAZUH_SCA_INDEX_PATTERN: wazuh-states-sca-*,wazuh-enrich-sca-results-*
SCA_SYNC:
  enabled: true
  interval_seconds: 900
  output_index_prefix: wazuh-enrich-sca-results
  policy_query: workaround
  page_limit: 500
  max_agents_per_run: 1000
```

Chạy sync một lần:

```bash
/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py \
  --config /etc/wazuh-enrich/config.yaml \
  --log-format text \
  sync-sca
```

Sau đó enrich lại:

```bash
/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py \
  --config /etc/wazuh-enrich/config.yaml \
  --log-format text \
  enrich-all
```

SCA sync chỉ lấy policy/check match `SCA_SYNC.policy_query` từ các agent đang có vulnerability finding, rồi ghi vào `wazuh-enrich-sca-results-YYYY.MM.DD`.

`WORKAROUND_FEED_FILE` là metadata curated để dashboard biết workaround lấy từ đâu và playbook nào xử lý:

```yaml
workarounds:
  - cve_id: CVE-2026-31431
    workaround_id: copy-fail-algif-aead
    title: Copy Fail algif_aead mitigation
    source_url: https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available
    executor: ansible
    playbook: playbooks/cve_2026_31431_copy_fail.yml
    notes: Upgrade kmod hoặc install algif_aead /bin/false, rồi verify module không loaded.
```

Collector tự tìm workaround candidate:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-workaround-feed --cve CVE-2026-31431
```

Hoặc lấy CVE đang impact hệ thống từ `wazuh-vuln-cve-summary-latest`:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-workaround-feed --from-latest-impact
```

Collector chỉ ghi candidate vào feed. Record mới sẽ có `review_status: needs_review`; bạn vẫn cần đọc vendor guidance, tạo/approve playbook Ansible, rồi chạy Ansible verify. Collector không tự đánh dấu host đã mitigate.

`WORKAROUND_RESULT_FILE` do Ansible verification job ghi ra:

```json
[
  {
    "agent_id": "001",
    "agent_name": "ubuntu-1",
    "cve_id": "CVE-2026-31431",
    "workaround_id": "copy-fail-algif-aead",
    "source": "ansible",
    "apply_status": "applied",
    "verify_status": "passed",
    "verified_at": "2026-05-15T10:30:00Z",
    "checks": {
      "kmod_fixed_or_manual_disable": true,
      "algif_aead_not_loaded": true
    },
    "evidence": {
      "kmod_version": "31+20240202-2ubuntu7.2",
      "module_loaded": false,
      "manual_disable_file": "/etc/modprobe.d/manual-disable-algif_aead.conf"
    }
  }
]
```

Join key:

```text
agent_id + cve_id
```

Nên khai báo `wazuh_agent_id` trong Ansible inventory để output join chắc:

```ini
[ubuntu]
ubuntu-1 ansible_host=10.0.0.10 wazuh_agent_id=001
ubuntu-2 ansible_host=10.0.0.11 wazuh_agent_id=002
```

Copy file mẫu trên server:

```bash
sudo mkdir -p /var/lib/wazuh-enrich/feeds
sudo cp feeds/cve_workarounds.yaml.example /var/lib/wazuh-enrich/feeds/cve_workarounds.yaml
sudo cp feeds/workaround_results.json.example /var/lib/wazuh-enrich/feeds/workaround_results.json
```

Dùng playbook mẫu Copy Fail làm điểm bắt đầu:

```bash
cp ansible/cve_2026_31431_copy_fail.yml.example playbooks/cve_2026_31431_copy_fail.yml
```

Chỉ verify:

```bash
ansible-playbook -i inventory.ini playbooks/cve_2026_31431_copy_fail.yml \
  -e workaround_result_output=/var/lib/wazuh-enrich/feeds/workaround_results.json
```

Apply manual workaround rồi verify:

```bash
ansible-playbook -i inventory.ini playbooks/cve_2026_31431_copy_fail.yml \
  -e apply_workaround=true \
  -e workaround_result_output=/var/lib/wazuh-enrich/feeds/workaround_results.json
```

Logic:

```text
verify_status passed và mọi checks true -> mitigation_status: mitigated
verify_status failed hoặc có check false -> mitigation_status: not_mitigated
không có result theo agent_id + CVE      -> mitigation_status: unknown
```

Nếu finding đang là `patch_now` nhưng `mitigation_status` thành `mitigated`, app đổi thành:

```text
patch_decision: workaround_active
```

Nghĩa là package vẫn vulnerable và vẫn cần patch sau, nhưng workaround đã được verify nên giảm rủi ro khai thác ngay lúc này và không còn nằm trong alert mặc định `Critical Real Impact`.

Sau đó enrich lại:

```bash
/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py \
  --config /etc/wazuh-enrich/config.yaml \
  --log-format text \
  enrich-all
```

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
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-workaround-feed --from-latest-impact
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-poc
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-sca
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-agent --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml process-inventory-updates
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml detect-new-agents
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml test-alert
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-sca-workaround --agent-id 001 --cve-id CVE-2026-31431
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

Config alert:

```yaml
ALERT_THRESHOLDS:
  epss_high: 0.7
  epss_medium: 0.3
  cve_many_agents: 25
  alert_scope: critical_real_impact
  send_all_impacted_cves: false
  send_all_alerts: false
  public_poc_only: false
  alert_interval_seconds: 0
  max_top_cves: 10
```

`alert_scope` chọn nhóm CVE mà Telegram sẽ gửi. Mặc định là `critical_real_impact`.

```text
critical_real_impact -> patch_now + vendor confirmed/likely affected + có exploit signal
needs_review         -> CVE có threat cao nhưng vendor/package confirmation chưa đủ
patch_scheduled      -> vendor xác nhận affected, nên lên lịch patch, hoặc cần cleanup kernel cũ
all                  -> mọi CVE đủ điều kiện alert
```

`send_all_alerts: false` là mặc định cho production. Alert được dedup bằng `STATE_FILE`, nên cùng một CVE/key không bị gửi lại ở mỗi cycle.

Khi muốn mọi CVE đang impact hệ thống đều đủ điều kiện alert, bật:

```yaml
ALERT_THRESHOLDS:
  send_all_impacted_cves: true
  max_top_cves: 0
```

Tùy chọn này vẫn chỉ dùng CVE từ Wazuh findings/enriched summaries, không gửi CVE global ngoài internet.

Khi cần test hoặc review incident ngắn hạn, có thể bật gửi tất cả alert đủ điều kiện ở mỗi cycle:

```yaml
ALERT_THRESHOLDS:
  send_all_alerts: true
  max_top_cves: 0
```

Nếu muốn mỗi cycle đều gửi lại mọi CVE đang impact hệ thống, bật cả `send_all_impacted_cves: true` và `send_all_alerts: true`.

Dùng `public_poc_only: true` khi bạn chỉ muốn alert những CVE có public PoC metadata. Filter này chạy sau khi đã biết CVE đó đang impact hệ thống, nên ý nghĩa là "CVE có public PoC và đang ảnh hưởng hệ thống này", không phải mọi CVE có PoC trên internet:

```yaml
ALERT_THRESHOLDS:
  send_all_impacted_cves: true
  send_all_alerts: true
  alert_scope: critical_real_impact
  public_poc_only: true
  alert_interval_seconds: 3600
  max_top_cves: 0
```

`alert_interval_seconds` là khoảng cách tối thiểu giữa 2 lần aggregate cycle alert. Nó chỉ áp dụng cho alert cycle bình thường từ `process_cycle`; alert baseline của agent mới vẫn được check ngay khi detect, nhưng dùng cùng logic `alert_scope` và cùng format alert với cycle alert. Lần alert đầu tiên sau khi start service sẽ gửi ngay nếu `STATE_FILE` chưa có `last_alert_sent_by_type.cycle`. Nếu service restart và lần gửi cycle alert trước vẫn còn trong khoảng interval, service sẽ không spam Telegram sau restart.

Option này không tạo scheduler alert riêng. Alert chỉ được evaluate khi enrichment/inventory processing chạy. Nếu `alert_interval_seconds` nhỏ hơn `SCHEDULE.enrichment_seconds`, nhịp gửi thực tế vẫn bị giới hạn bởi enrichment cycle.

`max_top_cves: 0` nghĩa là đưa toàn bộ CVE match điều kiện vào Telegram message. Cẩn thận khi bật trên môi trường lớn vì message có thể rất dài hoặc vượt giới hạn Telegram.

Ví dụ:

```text
CRITICAL - Critical Real Impact CVEs impacting system

Summary:
- Alert scope: critical_real_impact
- Affected agents: 2
- Patch now CVEs: 2
- Needs review CVEs: 1
- Vendor confirmed affected: 2
- Fix available CVEs: 2
- P0 CVEs: 4
- KEV CVEs: 2
- Public PoC CVEs: 1
- EPSS >= 0.7: 3

Top CVEs to decide patching:
1. CVE-2025-0001 | patch=patch_now | Ubuntu=confirmed_affected | exploit=exploited_in_wild | KEV=yes | PoC=yes | EPSS=0.94 | CVSS=9.8 | hosts=72 | package=openssl | fix=yes | action=Patch now.
```

## Dashboard

Tạo data view:

```text
wazuh-vuln-enriched-latest        time field: enriched_at
wazuh-vuln-cve-summary-latest     time field: updated_at
wazuh-vuln-host-cve-impact-latest time field: updated_at
```

Dashboard dùng `*-latest` để nhìn trạng thái hiện tại và tránh duplicate cùng một CVE qua nhiều daily index. Daily index `YYYY.MM.DD` vẫn được ghi để lưu lịch sử/trend.

Cách hiểu đơn giản:

- `wazuh-vuln-*-YYYY.MM.DD`: dữ liệu lịch sử theo ngày.
- `wazuh-vuln-*-latest`: snapshot hiện tại, được replace sau mỗi lần enrich/update thành công.
- Dashboard/filter dùng `*-latest`.
- Alert giữ logic hiện tại: alert được tính từ cycle enrichment hiện tại, không scan toàn bộ daily summary index.

Dashboard import là tùy chọn và tách khỏi flow enrichment:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

Dashboard hiện có:

- Impact Filters.
- Critical Real Impact CVEs và host.
- Needs Review CVEs và host.
- Patch Scheduled CVEs và host.

## Kiểm Tra Nhanh

Critical Real Impact CVEs:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-latest/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"term":{"patch_decision":"patch_now"}},{"terms":{"verification_status":["confirmed_affected","likely_affected"]}},{"range":{"affected_hosts_count":{"gte":1}}}],"should":[{"term":{"exploitability_status":"exploited_in_wild"}},{"term":{"public_poc":true}},{"range":{"epss_score":{"gte":0.7}}}],"minimum_should_match":1}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

Needs Review CVEs:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-latest/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"range":{"affected_hosts_count":{"gte":1}}}],"should":[{"term":{"patch_decision":"needs_review"}},{"bool":{"filter":[{"terms":{"verification_status":["vendor_not_found","needs_manual_check","not_verified"]}}],"should":[{"term":{"kev":true}},{"term":{"public_poc":true}},{"range":{"epss_score":{"gte":0.7}}}],"minimum_should_match":1}}],"minimum_should_match":1}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
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
