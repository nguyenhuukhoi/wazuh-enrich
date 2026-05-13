#!/usr/bin/env python3
import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alerts import AlertManager
from config import Settings, load_config
from feed_sync import FeedSync
from risk import normalize_finding
from state import StateStore
from summary import build_cve_summary, build_host_cve_impact_summary, build_host_summary, overview_metrics
from tools.build_poc_feed import build_poc_feed
from wazuh_client import WazuhIndexerClient


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        message = f"{timestamp} {record.levelname:<7} {record.name}: {record.getMessage()}"
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        return message


def configure_logging(level: str, log_format: str = "text") -> None:
    handler = logging.StreamHandler()
    formatter = JsonFormatter() if log_format == "json" else TextFormatter()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


LOG = logging.getLogger("vuln_enricher")


RELOAD_REQUESTED = False


def latest_index(prefix: str) -> str:
    return f"{prefix}-latest"


def latest_indices(settings: Settings) -> dict[str, str]:
    return {
        "enriched_index": latest_index(settings.enriched_index_prefix),
        "cve_summary_index": latest_index(settings.cve_summary_index_prefix),
        "host_summary_index": latest_index(settings.host_summary_index_prefix),
        "host_cve_impact_index": latest_index(settings.host_cve_impact_index_prefix),
    }


def replace_latest_indices(
    client: WazuhIndexerClient,
    settings: Settings,
    enriched_docs: list[dict[str, Any]],
    cve_summaries: list[dict[str, Any]],
    host_summaries: list[dict[str, Any]],
    host_cve_impacts: list[dict[str, Any]],
) -> dict[str, str]:
    indices = latest_indices(settings)
    client.delete_by_query(indices["enriched_index"], {"match_all": {}})
    client.bulk_index(indices["enriched_index"], enriched_docs, ["cve_id", "agent_id", "package_name", "package_version"])
    client.delete_by_query(indices["cve_summary_index"], {"match_all": {}})
    client.bulk_index(indices["cve_summary_index"], cve_summaries, ["cve_id"])
    client.delete_by_query(indices["host_summary_index"], {"match_all": {}})
    client.bulk_index(indices["host_summary_index"], host_summaries, ["agent_id"])
    client.delete_by_query(indices["host_cve_impact_index"], {"match_all": {}})
    client.bulk_index(indices["host_cve_impact_index"], host_cve_impacts, ["cve_id", "agent_id"])
    return indices


def request_reload(_signum: int, _frame: Any) -> None:
    global RELOAD_REQUESTED
    RELOAD_REQUESTED = True


def load_local_or_sync_feeds(
    settings: Settings,
    force: bool = False,
) -> tuple[
    set[str],
    dict[str, Any],
    dict[str, Any],
    dict[tuple[str, str, str], Any],
    dict[tuple[str, str, str], Any],
]:
    feed_sync = FeedSync(
        cache_dir=settings.cache_dir,
        kev_url=settings.cisa_kev_url,
        epss_url=settings.epss_url,
        timeout=settings.request_timeout_seconds,
        kev_file=settings.cisa_kev_file,
        poc_file=settings.poc_feed_file,
        ubuntu_oval=settings.ubuntu_oval,
    )
    kev, epss, poc = feed_sync.sync_all(force=force)
    ubuntu = feed_sync.sync_ubuntu_oval(force=False)
    ubuntu_osv = feed_sync.sync_ubuntu_osv(force=False)
    return kev, epss, poc, ubuntu, ubuntu_osv


def build_feed_sync(settings: Settings) -> FeedSync:
    return FeedSync(
        cache_dir=settings.cache_dir,
        kev_url=settings.cisa_kev_url,
        epss_url=settings.epss_url,
        timeout=settings.request_timeout_seconds,
        kev_file=settings.cisa_kev_file,
        poc_file=settings.poc_feed_file,
        ubuntu_oval=settings.ubuntu_oval,
    )


def sync_feeds(settings: Settings, force: bool = False) -> None:
    feed_sync = build_feed_sync(settings)
    kev_cves, epss, poc = feed_sync.sync_all(force=force)
    ubuntu = feed_sync.sync_ubuntu_oval(force=False)
    ubuntu_osv = feed_sync.sync_ubuntu_osv(force=False)
    LOG.info(
        "feeds_ready kev_cves=%s epss_records=%s poc_records=%s ubuntu_oval_records=%s ubuntu_osv_records=%s",
        len(kev_cves),
        len(epss),
        len(poc),
        len(ubuntu),
        len(ubuntu_osv),
    )


def sync_poc(settings: Settings) -> None:
    feed_sync = build_feed_sync(settings)
    poc = feed_sync.sync_poc()
    LOG.info("poc_feed_ready poc_records=%s", len(poc))


def build_poc_metadata(settings: Settings) -> int:
    cfg = settings.poc_build
    if not cfg.get("enabled"):
        LOG.info("poc_build skipped=true reason=disabled")
        return 0
    output = Path(str(cfg.get("output_file") or settings.poc_feed_file or "feeds/cve_poc.csv"))
    count = build_poc_feed(
        output=output,
        exploitdb_csv=cfg.get("exploitdb_csv"),
        nuclei_templates=cfg.get("nuclei_templates"),
        poc_in_github=cfg.get("poc_in_github"),
        trickest_cve=cfg.get("trickest_cve"),
    )
    LOG.info("poc_build_done output=%s records=%s", output, count)
    return count


def enrich(
    settings: Settings,
    client: WazuhIndexerClient,
    state: StateStore,
    agent_id: str | None = None,
    full: bool = False,
    dry_run: bool = False,
    send_alerts: bool = True,
    dry_run_send_alerts: bool = False,
) -> dict[str, Any]:
    kev_cves, epss_records, poc_records, ubuntu_records, ubuntu_osv_records = load_local_or_sync_feeds(settings)
    since = None if full or agent_id else state.data.get("last_processed_timestamp")
    enriched_docs: list[dict[str, Any]] = []
    malformed = 0
    latest_detected_at: str | None = None
    agent_metadata = client.agent_metadata()

    for source in client.iter_vulnerability_findings(agent_id=agent_id, since=since):
        try:
            doc = normalize_finding(
                source,
                kev_cves,
                epss_records,
                poc_records,
                agent_metadata,
                ubuntu_records,
                ubuntu_osv_records,
            )
            if not doc:
                malformed += 1
                continue
            enriched_docs.append(doc)
            detected_at = doc.get("detected_at")
            if detected_at and (latest_detected_at is None or detected_at > latest_detected_at):
                latest_detected_at = detected_at
        except Exception as exc:
            malformed += 1
            LOG.warning("finding_enrich_failed error=%s source_id=%s", exc, source.get("_wazuh_source_id"))

    enriched_index = client.index_name(settings.enriched_index_prefix)
    cve_summary_index = client.index_name(settings.cve_summary_index_prefix)
    host_summary_index = client.index_name(settings.host_summary_index_prefix)
    host_cve_impact_index = client.index_name(settings.host_cve_impact_index_prefix)
    latest = latest_indices(settings)

    if not dry_run:
        client.ensure_templates()
        client.bulk_index(
            enriched_index,
            enriched_docs,
            ["cve_id", "agent_id", "package_name", "package_version"],
        )
        if not full:
            client.bulk_index(
                latest["enriched_index"],
                enriched_docs,
                ["cve_id", "agent_id", "package_name", "package_version"],
            )

    summary_source = enriched_docs
    if not full and not dry_run:
        summary_source = list(client.iter_index_sources(latest["enriched_index"]))

    cve_summaries = build_cve_summary(summary_source)
    host_summaries = build_host_summary(summary_source)
    host_cve_impacts = build_host_cve_impact_summary(summary_source)
    metrics = overview_metrics(summary_source, cve_summaries, host_summaries)

    if not dry_run:
        client.bulk_index(cve_summary_index, cve_summaries, ["cve_id"])
        client.bulk_index(host_summary_index, host_summaries, ["agent_id"])
        client.bulk_index(host_cve_impact_index, host_cve_impacts, ["cve_id", "agent_id"])
        replace_latest_indices(client, settings, summary_source, cve_summaries, host_summaries, host_cve_impacts)

    if send_alerts:
        alerts = AlertManager(
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
            thresholds=settings.alert_thresholds,
            state=state,
            timeout=settings.request_timeout_seconds,
            dry_run=dry_run and not dry_run_send_alerts,
        )
        alerts.process_cycle(summary_source, cve_summaries)

    if not agent_id:
        state.set_last_processed_timestamp(latest_detected_at)

    result = {
        "enriched_docs": len(enriched_docs),
        "malformed": malformed,
        "unique_cves": metrics["unique_cves"],
        "vulnerable_agents": metrics["vulnerable_agents"],
        "enriched_index": enriched_index,
        "cve_summary_index": cve_summary_index,
        "host_summary_index": host_summary_index,
        "host_cve_impact_index": host_cve_impact_index,
        "latest_indices": latest,
        "dry_run": dry_run,
    }
    LOG.info("enrichment_done %s", json.dumps(result, sort_keys=True))
    return result


def enrich_agent_incremental(
    settings: Settings,
    client: WazuhIndexerClient,
    state: StateStore,
    agent_id: str,
    dry_run: bool = False,
    send_alerts: bool = True,
    dry_run_send_alerts: bool = False,
) -> dict[str, Any]:
    kev_cves, epss_records, poc_records, ubuntu_records, ubuntu_osv_records = load_local_or_sync_feeds(settings)
    enriched_index = client.index_name(settings.enriched_index_prefix)
    cve_summary_index = client.index_name(settings.cve_summary_index_prefix)
    host_summary_index = client.index_name(settings.host_summary_index_prefix)
    host_cve_impact_index = client.index_name(settings.host_cve_impact_index_prefix)
    latest = latest_indices(settings)

    old_docs = list(client.iter_index_sources(latest["enriched_index"], {"term": {"agent_id": agent_id}}))
    old_cves = {str(doc.get("cve_id", "")) for doc in old_docs if doc.get("cve_id")}
    agent_metadata = client.agent_metadata()
    new_docs: list[dict[str, Any]] = []
    malformed = 0
    for source in client.iter_vulnerability_findings(agent_id=agent_id):
        try:
            doc = normalize_finding(
                source,
                kev_cves,
                epss_records,
                poc_records,
                agent_metadata,
                ubuntu_records,
                ubuntu_osv_records,
            )
            if doc:
                new_docs.append(doc)
            else:
                malformed += 1
        except Exception as exc:
            malformed += 1
            LOG.warning("agent_finding_enrich_failed agent_id=%s error=%s source_id=%s", agent_id, exc, source.get("_wazuh_source_id"))

    new_cves = {str(doc.get("cve_id", "")) for doc in new_docs if doc.get("cve_id")}
    affected_cves = sorted(old_cves | new_cves)

    if not dry_run:
        client.ensure_templates()
        client.delete_by_query(enriched_index, {"term": {"agent_id": agent_id}})
        client.bulk_index(enriched_index, new_docs, ["cve_id", "agent_id", "package_name", "package_version"])
        client.delete_by_query(latest["enriched_index"], {"term": {"agent_id": agent_id}})
        client.bulk_index(latest["enriched_index"], new_docs, ["cve_id", "agent_id", "package_name", "package_version"])

        current_agent_docs = list(client.iter_index_sources(latest["enriched_index"], {"term": {"agent_id": agent_id}}))
        host_summaries = build_host_summary(current_agent_docs)
        if host_summaries:
            client.bulk_index(host_summary_index, host_summaries, ["agent_id"])
            client.bulk_index(latest["host_summary_index"], host_summaries, ["agent_id"])
        else:
            client.delete_by_query(host_summary_index, {"term": {"agent_id": agent_id}})
            client.delete_by_query(latest["host_summary_index"], {"term": {"agent_id": agent_id}})

        client.delete_by_query(host_cve_impact_index, {"term": {"agent_id": agent_id}})
        client.delete_by_query(latest["host_cve_impact_index"], {"term": {"agent_id": agent_id}})
        host_cve_impacts = build_host_cve_impact_summary(current_agent_docs)
        client.bulk_index(host_cve_impact_index, host_cve_impacts, ["cve_id", "agent_id"])
        client.bulk_index(latest["host_cve_impact_index"], host_cve_impacts, ["cve_id", "agent_id"])

        cve_summaries = []
        for cve_id in affected_cves:
            docs = list(client.iter_index_sources(latest["enriched_index"], {"term": {"cve_id": cve_id}}))
            summaries = build_cve_summary(docs)
            if summaries:
                cve_summaries.extend(summaries)
            else:
                client.delete_by_query(cve_summary_index, {"term": {"cve_id": cve_id}})
                client.delete_by_query(latest["cve_summary_index"], {"term": {"cve_id": cve_id}})
        client.bulk_index(cve_summary_index, cve_summaries, ["cve_id"])
        client.bulk_index(latest["cve_summary_index"], cve_summaries, ["cve_id"])
    else:
        current_agent_docs = new_docs
        cve_summaries = build_cve_summary(new_docs)
        host_summaries = build_host_summary(new_docs)
        host_cve_impacts = build_host_cve_impact_summary(new_docs)

    if send_alerts:
        AlertManager(
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
            thresholds=settings.alert_thresholds,
            state=state,
            timeout=settings.request_timeout_seconds,
            dry_run=dry_run and not dry_run_send_alerts,
        ).process_cycle(current_agent_docs, cve_summaries)

    result = {
        "agent_id": agent_id,
        "old_docs": len(old_docs),
        "new_docs": len(new_docs),
        "malformed": malformed,
        "affected_cves": len(affected_cves),
        "host_summaries": len(host_summaries),
        "host_cve_impacts": len(host_cve_impacts),
        "dry_run": dry_run,
    }
    LOG.info("agent_incremental_enrichment_done %s", json.dumps(result, sort_keys=True))
    return result


def process_inventory_updates(
    settings: Settings,
    client: WazuhIndexerClient,
    state: StateStore,
    dry_run: bool = False,
    dry_run_send_alerts: bool = False,
) -> dict[str, Any]:
    timestamp_fields = settings.inventory_watch_timestamp_fields
    max_agents = int(settings.schedule.get("max_inventory_agents_per_cycle", 100))
    stabilization_seconds = int(settings.schedule.get("inventory_stabilization_seconds", 180))
    last_inventory_timestamp = state.data.get("last_inventory_timestamp")

    if not last_inventory_timestamp:
        latest = client.latest_inventory_timestamp(timestamp_fields)
        state.set_last_inventory_timestamp(latest)
        result = {"initialized": True, "last_inventory_timestamp": latest, "queued_agents": 0, "processed_agents": 0}
        LOG.info("inventory_watch_initialized %s", json.dumps(result, sort_keys=True))
        return result

    agents, newest = client.inventory_agents_updated_since(str(last_inventory_timestamp), timestamp_fields, max_agents)
    for agent_id in agents:
        state.queue_inventory_agent(agent_id)
    state.set_last_inventory_timestamp(newest)

    processed = []
    for agent_id in state.due_inventory_agents(stabilization_seconds, max_agents):
        enrich_agent_incremental(
            settings,
            client,
            state,
            agent_id=agent_id,
            dry_run=dry_run,
            dry_run_send_alerts=dry_run_send_alerts,
        )
        if not dry_run:
            state.clear_pending_inventory_agent(agent_id)
        processed.append(agent_id)

    result = {
        "initialized": False,
        "queued_agents": len(agents),
        "pending_agents": len(state.data.get("pending_inventory_agents", {})),
        "processed_agents": len(processed),
        "last_inventory_timestamp": state.data.get("last_inventory_timestamp"),
    }
    LOG.info("inventory_updates_processed %s", json.dumps(result, sort_keys=True))
    return result


def detect_new_agents(
    settings: Settings,
    client: WazuhIndexerClient,
    state: StateStore,
    dry_run: bool = False,
    dry_run_send_alerts: bool = False,
) -> dict[str, int]:
    kev_cves, epss_records, poc_records, ubuntu_records, ubuntu_osv_records = load_local_or_sync_feeds(settings)
    alerts = AlertManager(
        bot_token=settings.telegram_bot_token,
        chat_id=settings.telegram_chat_id,
        thresholds=settings.alert_thresholds,
        state=state,
        timeout=settings.request_timeout_seconds,
        dry_run=dry_run and not dry_run_send_alerts,
    )
    new_agents = 0
    baseline_dir = settings.cache_dir / "baselines"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    agent_metadata = client.agent_metadata()

    for agent in client.list_agents_with_vulnerabilities():
        agent_id = agent["agent_id"]
        if state.is_agent_seen(agent_id):
            continue
        new_agents += 1
        enriched_docs = []
        for source in client.iter_vulnerability_findings(agent_id=agent_id):
            doc = normalize_finding(
                source,
                kev_cves,
                epss_records,
                poc_records,
                agent_metadata,
                ubuntu_records,
                ubuntu_osv_records,
            )
            if doc:
                enriched_docs.append(doc)

        report = {
            "agent_id": agent_id,
            "agent_name": agent.get("agent_name", ""),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(enriched_docs),
            "unique_cves": len({doc["cve_id"] for doc in enriched_docs}),
            "p0_count": len([doc for doc in enriched_docs if doc["priority"] == "P0"]),
            "p1_count": len([doc for doc in enriched_docs if doc["priority"] == "P1"]),
            "kev_count": len([doc for doc in enriched_docs if doc["kev"]]),
            "top_findings": sorted(enriched_docs, key=lambda doc: doc["risk_score"], reverse=True)[:25],
        }
        if not dry_run:
            report_path = baseline_dir / f"agent-{agent_id}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
        alerts.process_new_agent_baseline(agent_id, agent.get("agent_name", ""), enriched_docs)
        state.mark_agent_seen(agent_id)
        LOG.info("new_agent_baseline_done agent_id=%s findings=%s", agent_id, len(enriched_docs))

    result = {"new_agents": new_agents}
    LOG.info("detect_new_agents_done %s", json.dumps(result, sort_keys=True))
    return result


def debug_agent_ip(settings: Settings, client: WazuhIndexerClient, agent_id: str) -> dict[str, Any]:
    result = client.sample_agent_inventory(agent_id)
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    return result


def test_alert(settings: Settings, state: StateStore, dry_run: bool = False) -> None:
    AlertManager(
        bot_token=settings.telegram_bot_token,
        chat_id=settings.telegram_chat_id,
        thresholds=settings.alert_thresholds,
        state=state,
        timeout=settings.request_timeout_seconds,
        dry_run=dry_run,
    ).send_message(
        "Wazuh enrich test alert\n\nTelegram delivery is working for wazuh-enrich."
    )


def run_once(settings: Settings, dry_run: bool = False, dry_run_send_alerts: bool = False) -> None:
    state = StateStore(settings.state_file)
    client = WazuhIndexerClient(settings)
    sync_feeds(settings)
    process_inventory_updates(settings, client, state, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
    enrich(settings, client, state, full=False, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
    detect_new_agents(settings, client, state, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
    if not dry_run:
        state.save()


def current_enriched_index(settings: Settings, client: WazuhIndexerClient) -> str:
    return client.index_name(settings.enriched_index_prefix)


def mark_daily_full_refresh(settings: Settings, client: WazuhIndexerClient, state: StateStore) -> None:
    state.data["last_daily_full_refresh_index"] = current_enriched_index(settings, client)


def daily_full_refresh_required(settings: Settings, client: WazuhIndexerClient, state: StateStore) -> tuple[bool, str, int | None]:
    enriched_index = current_enriched_index(settings, client)
    if state.data.get("last_daily_full_refresh_index") == enriched_index:
        return False, enriched_index, None

    count = client.index_doc_count(enriched_index)
    if count is None:
        return False, enriched_index, None
    if count > 0:
        state.data["last_daily_full_refresh_index"] = enriched_index
        return False, enriched_index, count
    return True, enriched_index, count


def daemon(config_path: str, settings: Settings, dry_run: bool = False, dry_run_send_alerts: bool = False) -> None:
    global RELOAD_REQUESTED
    state = StateStore(settings.state_file)
    client = WazuhIndexerClient(settings)
    feed_sync = build_feed_sync(settings)
    schedule = build_daemon_schedule(settings)
    last_run = {key: 0.0 for key in schedule}
    last_run["full_refresh_seconds"] = time.monotonic()
    install_reload_handler()
    LOG.info("daemon_started schedule=%s dry_run=%s", schedule, dry_run)
    while True:
        now = time.monotonic()
        try:
            if RELOAD_REQUESTED:
                RELOAD_REQUESTED = False
                try:
                    if not dry_run:
                        state.save()
                    settings = load_config(config_path)
                    state = StateStore(settings.state_file)
                    client = WazuhIndexerClient(settings)
                    feed_sync = build_feed_sync(settings)
                    schedule = build_daemon_schedule(settings)
                    last_run = {key: last_run.get(key, 0.0) for key in schedule}
                    last_run.setdefault("full_refresh_seconds", now)
                    LOG.info("daemon_reloaded config=%s schedule=%s", config_path, schedule)
                except Exception:
                    LOG.exception("daemon_reload_failed keeping_previous_config=true")
                    continue
            feeds_changed = False
            if now - last_run["kev_sync_seconds"] >= schedule["kev_sync_seconds"]:
                before = feed_sync.fingerprints()
                feed_sync.sync_kev()
                after = feed_sync.fingerprints()
                feeds_changed = feeds_changed or before.get("kev") != after.get("kev")
                last_run["kev_sync_seconds"] = now
            if now - last_run["epss_sync_seconds"] >= schedule["epss_sync_seconds"]:
                before = feed_sync.fingerprints()
                feed_sync.sync_epss()
                after = feed_sync.fingerprints()
                feeds_changed = feeds_changed or before.get("epss") != after.get("epss")
                last_run["epss_sync_seconds"] = now
            if settings.poc_build.get("enabled") and now - last_run["poc_build_seconds"] >= schedule["poc_build_seconds"]:
                before = feed_sync.fingerprints()
                build_poc_metadata(settings)
                feed_sync.sync_poc()
                after = feed_sync.fingerprints()
                feeds_changed = feeds_changed or before.get("poc") != after.get("poc")
                last_run["poc_build_seconds"] = now
            if settings.ubuntu_oval.get("enabled") and now - last_run["ubuntu_oval_sync_seconds"] >= schedule["ubuntu_oval_sync_seconds"]:
                before = feed_sync.fingerprints()
                feed_sync.sync_ubuntu_oval()
                after = feed_sync.fingerprints()
                feeds_changed = feeds_changed or before != after
                last_run["ubuntu_oval_sync_seconds"] = now
            if settings.ubuntu_oval.get("osv_enabled") and now - last_run["ubuntu_osv_sync_seconds"] >= schedule["ubuntu_osv_sync_seconds"]:
                before = feed_sync.fingerprints()
                feed_sync.sync_ubuntu_osv()
                after = feed_sync.fingerprints()
                feeds_changed = feeds_changed or before != after
                last_run["ubuntu_osv_sync_seconds"] = now
            before = feed_sync.fingerprints()
            feed_sync.sync_poc()
            after = feed_sync.fingerprints()
            feeds_changed = feeds_changed or before.get("poc") != after.get("poc")
            if feeds_changed:
                LOG.info("feed_change_detected full_refresh=true")
                enrich(settings, client, state, full=True, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
                state.data["feed_fingerprints"] = after
                mark_daily_full_refresh(settings, client, state)
                last_run["full_refresh_seconds"] = now
                last_run["enrichment_seconds"] = now
            if now - last_run["full_refresh_seconds"] >= schedule["full_refresh_seconds"]:
                LOG.info("scheduled_full_refresh_started")
                enrich(settings, client, state, full=True, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
                state.data["feed_fingerprints"] = feed_sync.fingerprints()
                mark_daily_full_refresh(settings, client, state)
                last_run["full_refresh_seconds"] = now
                last_run["enrichment_seconds"] = now
            required, enriched_index, doc_count = daily_full_refresh_required(settings, client, state)
            if required:
                LOG.info("daily_enriched_index_empty full_refresh=true index=%s docs=%s", enriched_index, doc_count)
                enrich(settings, client, state, full=True, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
                mark_daily_full_refresh(settings, client, state)
                last_run["full_refresh_seconds"] = now
                last_run["enrichment_seconds"] = now
            if now - last_run["enrichment_seconds"] >= schedule["enrichment_seconds"]:
                enrich(settings, client, state, full=False, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
                last_run["enrichment_seconds"] = now
            if now - last_run["inventory_watch_seconds"] >= schedule["inventory_watch_seconds"]:
                process_inventory_updates(settings, client, state, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
                last_run["inventory_watch_seconds"] = now
            if now - last_run["detect_new_agents_seconds"] >= schedule["detect_new_agents_seconds"]:
                detect_new_agents(settings, client, state, dry_run=dry_run, dry_run_send_alerts=dry_run_send_alerts)
                last_run["detect_new_agents_seconds"] = now
            if not dry_run:
                state.save()
        except Exception:
            LOG.exception("daemon_cycle_failed")
        time.sleep(10)


def build_daemon_schedule(settings: Settings) -> dict[str, int]:
    return {
        "kev_sync_seconds": settings.schedule.get("kev_sync_seconds", 3600),
        "epss_sync_seconds": settings.schedule.get("epss_sync_seconds", 86400),
        "enrichment_seconds": settings.schedule.get("enrichment_seconds", 900),
        "full_refresh_seconds": settings.schedule.get("full_refresh_seconds", 86400),
        "ubuntu_oval_sync_seconds": settings.schedule.get("ubuntu_oval_sync_seconds", 86400),
        "ubuntu_osv_sync_seconds": settings.schedule.get("ubuntu_osv_sync_seconds", 86400),
        "inventory_watch_seconds": settings.schedule.get("inventory_watch_seconds", 60),
        "poc_build_seconds": int(settings.poc_build.get("interval_seconds", 86400)),
        "detect_new_agents_seconds": settings.schedule.get("detect_new_agents_seconds", 300),
    }


def install_reload_handler() -> None:
    if not hasattr(signal, "SIGHUP"):
        LOG.info("reload_signal_unavailable platform=%s", sys.platform)
        return
    signal.signal(signal.SIGHUP, request_reload)
    LOG.info("reload_signal_ready signal=SIGHUP")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wazuh vulnerability enrichment service")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Do not write indices or send Telegram alerts")
    parser.add_argument(
        "--dry-run-send-alerts",
        action="store_true",
        help="With --dry-run, keep index/state writes disabled but send Telegram alerts for testing.",
    )
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="json",
        help="Console log format. Defaults to json for production log collectors.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sync-feeds")
    sub.add_parser("sync-poc")
    sub.add_parser("build-poc-feed")
    sub.add_parser("enrich-all")
    agent_parser = sub.add_parser("enrich-agent")
    agent_parser.add_argument("--agent-id", required=True)
    sub.add_parser("detect-new-agents")
    sub.add_parser("process-inventory-updates")
    sub.add_parser("test-alert")
    debug_ip_parser = sub.add_parser("debug-agent-ip")
    debug_ip_parser.add_argument("--agent-id", required=True)
    sub.add_parser("run-once")
    sub.add_parser("daemon")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_format)
    try:
        settings = load_config(args.config)
        state = StateStore(settings.state_file)
        client = WazuhIndexerClient(settings)

        if args.command == "sync-feeds":
            sync_feeds(settings, force=True)
        elif args.command == "sync-poc":
            sync_poc(settings)
        elif args.command == "build-poc-feed":
            build_poc_metadata(settings)
        elif args.command == "enrich-all":
            enrich(
                settings,
                client,
                state,
                full=True,
                dry_run=args.dry_run,
                dry_run_send_alerts=args.dry_run_send_alerts,
            )
        elif args.command == "enrich-agent":
            enrich_agent_incremental(
                settings,
                client,
                state,
                agent_id=args.agent_id,
                dry_run=args.dry_run,
                dry_run_send_alerts=args.dry_run_send_alerts,
            )
        elif args.command == "detect-new-agents":
            detect_new_agents(
                settings,
                client,
                state,
                dry_run=args.dry_run,
                dry_run_send_alerts=args.dry_run_send_alerts,
            )
        elif args.command == "process-inventory-updates":
            process_inventory_updates(
                settings,
                client,
                state,
                dry_run=args.dry_run,
                dry_run_send_alerts=args.dry_run_send_alerts,
            )
        elif args.command == "test-alert":
            test_alert(settings, state, dry_run=args.dry_run)
        elif args.command == "debug-agent-ip":
            debug_agent_ip(settings, client, args.agent_id)
        elif args.command == "run-once":
            run_once(settings, dry_run=args.dry_run, dry_run_send_alerts=args.dry_run_send_alerts)
            return 0
        elif args.command == "daemon":
            daemon(args.config, settings, dry_run=args.dry_run, dry_run_send_alerts=args.dry_run_send_alerts)
            return 0

        if not args.dry_run:
            state.save()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        LOG.exception("command_failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
