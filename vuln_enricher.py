#!/usr/bin/env python3
import argparse
import json
import logging
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
from summary import build_cve_summary, build_host_summary, overview_metrics
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
        return f"{timestamp} {record.levelname:<7} {record.name}: {record.getMessage()}"


def configure_logging(level: str, log_format: str = "text") -> None:
    handler = logging.StreamHandler()
    formatter = JsonFormatter() if log_format == "json" else TextFormatter()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


LOG = logging.getLogger("vuln_enricher")


def load_local_or_sync_feeds(settings: Settings, force: bool = False) -> tuple[set[str], dict[str, Any], dict[str, Any]]:
    feed_sync = FeedSync(
        cache_dir=settings.cache_dir,
        kev_url=settings.cisa_kev_url,
        epss_url=settings.epss_url,
        timeout=settings.request_timeout_seconds,
        kev_file=settings.cisa_kev_file,
        poc_file=settings.poc_feed_file,
    )
    return feed_sync.sync_all(force=force)


def build_feed_sync(settings: Settings) -> FeedSync:
    return FeedSync(
        cache_dir=settings.cache_dir,
        kev_url=settings.cisa_kev_url,
        epss_url=settings.epss_url,
        timeout=settings.request_timeout_seconds,
        kev_file=settings.cisa_kev_file,
        poc_file=settings.poc_feed_file,
    )


def sync_feeds(settings: Settings, force: bool = False) -> None:
    kev_cves, epss, poc = build_feed_sync(settings).sync_all(force=force)
    LOG.info("feeds_ready kev_cves=%s epss_records=%s poc_records=%s", len(kev_cves), len(epss), len(poc))


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
) -> dict[str, Any]:
    kev_cves, epss_records, poc_records = load_local_or_sync_feeds(settings)
    since = None if full or agent_id else state.data.get("last_processed_timestamp")
    enriched_docs: list[dict[str, Any]] = []
    malformed = 0
    latest_detected_at: str | None = None

    for source in client.iter_vulnerability_findings(agent_id=agent_id, since=since):
        try:
            doc = normalize_finding(source, kev_cves, epss_records, poc_records)
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

    if not dry_run:
        client.ensure_templates()
        client.bulk_index(
            enriched_index,
            enriched_docs,
            ["cve_id", "agent_id", "package_name", "package_version"],
        )

    summary_source = enriched_docs
    if not full and not dry_run:
        summary_source = list(client.iter_index_sources(enriched_index))

    cve_summaries = build_cve_summary(summary_source)
    host_summaries = build_host_summary(summary_source)
    metrics = overview_metrics(summary_source, cve_summaries, host_summaries)

    if not dry_run:
        client.bulk_index(cve_summary_index, cve_summaries, ["cve_id"])
        client.bulk_index(host_summary_index, host_summaries, ["agent_id"])

    if send_alerts:
        alerts = AlertManager(
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
            thresholds=settings.alert_thresholds,
            state=state,
            timeout=settings.request_timeout_seconds,
            dry_run=dry_run,
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
        "dry_run": dry_run,
    }
    LOG.info("enrichment_done %s", json.dumps(result, sort_keys=True))
    return result


def detect_new_agents(
    settings: Settings,
    client: WazuhIndexerClient,
    state: StateStore,
    dry_run: bool = False,
) -> dict[str, int]:
    kev_cves, epss_records, poc_records = load_local_or_sync_feeds(settings)
    alerts = AlertManager(
        bot_token=settings.telegram_bot_token,
        chat_id=settings.telegram_chat_id,
        thresholds=settings.alert_thresholds,
        state=state,
        timeout=settings.request_timeout_seconds,
        dry_run=dry_run,
    )
    new_agents = 0
    baseline_dir = settings.cache_dir / "baselines"
    baseline_dir.mkdir(parents=True, exist_ok=True)

    for agent in client.list_agents_with_vulnerabilities():
        agent_id = agent["agent_id"]
        if state.is_agent_seen(agent_id):
            continue
        new_agents += 1
        enriched_docs = []
        for source in client.iter_vulnerability_findings(agent_id=agent_id):
            doc = normalize_finding(source, kev_cves, epss_records, poc_records)
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


def run_once(settings: Settings, dry_run: bool = False) -> None:
    state = StateStore(settings.state_file)
    client = WazuhIndexerClient(settings)
    sync_feeds(settings)
    enrich(settings, client, state, full=False, dry_run=dry_run)
    detect_new_agents(settings, client, state, dry_run=dry_run)
    if not dry_run:
        state.save()


def daemon(settings: Settings, dry_run: bool = False) -> None:
    state = StateStore(settings.state_file)
    client = WazuhIndexerClient(settings)
    feed_sync = build_feed_sync(settings)
    schedule = {
        "kev_sync_seconds": settings.schedule.get("kev_sync_seconds", 3600),
        "epss_sync_seconds": settings.schedule.get("epss_sync_seconds", 86400),
        "enrichment_seconds": settings.schedule.get("enrichment_seconds", 900),
        "full_refresh_seconds": settings.schedule.get("full_refresh_seconds", 86400),
        "poc_build_seconds": int(settings.poc_build.get("interval_seconds", 86400)),
        "detect_new_agents_seconds": settings.schedule.get("detect_new_agents_seconds", 300),
    }
    last_run = {key: 0.0 for key in schedule}
    last_run["full_refresh_seconds"] = time.monotonic()
    LOG.info("daemon_started schedule=%s dry_run=%s", schedule, dry_run)
    while True:
        now = time.monotonic()
        try:
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
            before = feed_sync.fingerprints()
            feed_sync.sync_poc()
            after = feed_sync.fingerprints()
            feeds_changed = feeds_changed or before.get("poc") != after.get("poc")
            if feeds_changed:
                LOG.info("feed_change_detected full_refresh=true")
                enrich(settings, client, state, full=True, dry_run=dry_run)
                state.data["feed_fingerprints"] = after
                last_run["full_refresh_seconds"] = now
                last_run["enrichment_seconds"] = now
            if now - last_run["full_refresh_seconds"] >= schedule["full_refresh_seconds"]:
                LOG.info("scheduled_full_refresh_started")
                enrich(settings, client, state, full=True, dry_run=dry_run)
                state.data["feed_fingerprints"] = feed_sync.fingerprints()
                last_run["full_refresh_seconds"] = now
                last_run["enrichment_seconds"] = now
            if now - last_run["enrichment_seconds"] >= schedule["enrichment_seconds"]:
                enrich(settings, client, state, full=False, dry_run=dry_run)
                last_run["enrichment_seconds"] = now
            if now - last_run["detect_new_agents_seconds"] >= schedule["detect_new_agents_seconds"]:
                detect_new_agents(settings, client, state, dry_run=dry_run)
                last_run["detect_new_agents_seconds"] = now
            if not dry_run:
                state.save()
        except Exception:
            LOG.exception("daemon_cycle_failed")
        time.sleep(10)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wazuh vulnerability enrichment service")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Do not write indices or send Telegram alerts")
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
            enrich(settings, client, state, full=True, dry_run=args.dry_run)
        elif args.command == "enrich-agent":
            enrich(settings, client, state, agent_id=args.agent_id, full=True, dry_run=args.dry_run)
        elif args.command == "detect-new-agents":
            detect_new_agents(settings, client, state, dry_run=args.dry_run)
        elif args.command == "run-once":
            run_once(settings, dry_run=args.dry_run)
            return 0
        elif args.command == "daemon":
            daemon(settings, dry_run=args.dry_run)
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
