#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from typing import Any

import requests
from requests import Response


DEFAULT_DASHBOARD_TITLE = "Wazuh Vulnerability Enrichment Overview"
DEFAULT_NDJSON = Path(__file__).with_name("wazuh-vuln-enrichment.ndjson")
RELATED_INDEX_PATTERNS = [
    "wazuh-vuln-enriched-*",
    "wazuh-vuln-cve-summary-*",
    "wazuh-vuln-host-summary-*",
]


class SavedObjectsClient:
    def __init__(
        self,
        dashboard_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        tenant: str | None = None,
    ):
        self.dashboard_url = dashboard_url.rstrip("/")
        self.auth = (username, password)
        self.verify_ssl = verify_ssl
        self.headers = {"osd-xsrf": "true"}
        if tenant:
            self.headers["securitytenant"] = tenant

    def request(self, method: str, path: str, **kwargs: Any) -> Response:
        response = requests.request(
            method,
            f"{self.dashboard_url}{path}",
            auth=self.auth,
            headers={**self.headers, **kwargs.pop("headers", {})},
            verify=self.verify_ssl,
            timeout=60,
            **kwargs,
        )
        if response.status_code >= 400 and response.status_code != 404:
            raise RuntimeError(f"{method} {path} failed: {response.status_code} {response.text}")
        return response

    def find(self, object_type: str, search: str, search_fields: str | None = None) -> list[dict[str, Any]]:
        params = {"type": object_type, "search": search, "per_page": 1000}
        if search_fields:
            params["search_fields"] = search_fields
        response = self.request("GET", "/api/saved_objects/_find", params=params)
        if response.status_code == 404:
            return []
        return response.json().get("saved_objects", [])

    def delete(self, object_type: str, object_id: str) -> bool:
        response = self.request("DELETE", f"/api/saved_objects/{object_type}/{object_id}")
        return response.status_code != 404

    def import_file(self, ndjson_path: Path, overwrite: bool = True) -> dict[str, Any]:
        params = {"overwrite": str(overwrite).lower()}
        with ndjson_path.open("rb") as handle:
            response = self.request(
                "POST",
                "/api/saved_objects/_import",
                params=params,
                files={"file": (ndjson_path.name, handle, "application/ndjson")},
            )
        return response.json()


def env_or_arg(value: str | None, env_name: str) -> str:
    resolved = value or os.getenv(env_name)
    if not resolved:
        raise SystemExit(f"Missing --{env_name.lower().replace('_', '-')} or environment variable {env_name}")
    return resolved


def collect_dashboard_objects(client: SavedObjectsClient, title: str) -> list[tuple[str, str, str]]:
    dashboards = client.find("dashboard", title, "title")
    objects: list[tuple[str, str, str]] = []
    for dashboard in dashboards:
        if dashboard.get("attributes", {}).get("title") != title:
            continue
        objects.append(("dashboard", dashboard["id"], title))
        for ref in dashboard.get("references", []):
            if ref.get("type") in {"visualization", "search"} and ref.get("id"):
                objects.append((ref["type"], ref["id"], ref.get("name", "")))
    return objects


def collect_index_patterns(client: SavedObjectsClient) -> list[tuple[str, str, str]]:
    objects: list[tuple[str, str, str]] = []
    for title in RELATED_INDEX_PATTERNS:
        for item in client.find("index-pattern", title, "title"):
            if item.get("attributes", {}).get("title") == title:
                objects.append(("index-pattern", item["id"], title))
    return objects


def dedupe(objects: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    seen = set()
    unique = []
    for object_type, object_id, title in objects:
        key = (object_type, object_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append((object_type, object_id, title))
    return unique


def command_list(client: SavedObjectsClient, title: str) -> int:
    objects = dedupe(collect_dashboard_objects(client, title) + collect_index_patterns(client))
    if not objects:
        print("No matching saved objects found.")
        return 0
    for object_type, object_id, object_title in objects:
        print(f"{object_type}/{object_id}\t{object_title}")
    return 0


def command_delete(client: SavedObjectsClient, title: str, dry_run: bool) -> int:
    objects = dedupe(collect_dashboard_objects(client, title) + collect_index_patterns(client))
    if not objects:
        print("No matching saved objects found.")
        return 0
    for object_type, object_id, object_title in objects:
        label = f"{object_type}/{object_id}"
        if dry_run:
            print(f"Would delete {label}\t{object_title}")
            continue
        deleted = client.delete(object_type, object_id)
        status = "deleted" if deleted else "not_found"
        print(f"{status} {label}\t{object_title}")
    return 0


def command_import(client: SavedObjectsClient, ndjson_path: Path, overwrite: bool) -> int:
    result = client.import_file(ndjson_path, overwrite=overwrite)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Wazuh enrichment dashboard saved objects.")
    parser.add_argument("command", choices=["list", "delete", "import", "reimport"])
    parser.add_argument("--dashboard-url", default=os.getenv("WAZUH_DASHBOARD_URL", "https://127.0.0.1:443"))
    parser.add_argument("--username", default=os.getenv("WAZUH_INDEXER_USERNAME"))
    parser.add_argument("--password", default=os.getenv("WAZUH_INDEXER_PASSWORD"))
    parser.add_argument("--tenant", help="Optional Wazuh/OpenSearch security tenant, for example global")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("--title", default=DEFAULT_DASHBOARD_TITLE)
    parser.add_argument("--file", default=str(DEFAULT_NDJSON), help="NDJSON file for import/reimport")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted")
    parser.add_argument("--no-overwrite", action="store_true", help="Disable overwrite during import")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    client = SavedObjectsClient(
        dashboard_url=args.dashboard_url,
        username=env_or_arg(args.username, "WAZUH_INDEXER_USERNAME"),
        password=env_or_arg(args.password, "WAZUH_INDEXER_PASSWORD"),
        verify_ssl=not args.no_verify_ssl,
        tenant=args.tenant,
    )
    if args.command == "list":
        return command_list(client, args.title)
    if args.command == "delete":
        return command_delete(client, args.title, args.dry_run)
    if args.command == "import":
        return command_import(client, Path(args.file), overwrite=not args.no_overwrite)
    if args.command == "reimport":
        command_delete(client, args.title, dry_run=False)
        return command_import(client, Path(args.file), overwrite=not args.no_overwrite)
    raise AssertionError(f"Unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
