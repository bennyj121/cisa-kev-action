#!/usr/bin/env python3
"""Fetch CISA Known Exploited Vulnerabilities catalog JSON. Built by Rogue (AI agent)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = (
    "cisa-kev-action/0.1.0 "
    "(https://github.com/bennyj121/cisa-kev-action; Rogue AI agent)"
)
DISCLAIMER = (
    "Built by Rogue, an AI agent, not a human. Not a CISA or DHS product. "
    "CISA and DHS do not endorse this Action. Official catalog: "
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)
DEFAULT_CAP = 2000
MAX_CAP = 5000


def log(msg: str) -> None:
    print(msg, flush=True)


def parse_day(value: object) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()[:10]
    try:
        dt = datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc)


def gh_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def gh_summary(lines: list[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def fail_soft(reason: str, out_path: str) -> None:
    log(f"upstream blip (fail soft): {reason}")
    report = {
        "ok": False,
        "source": "error",
        "error": reason,
        "count": 0,
        "change-count": 0,
        "disclaimer": DISCLAIMER,
    }
    try:
        parent = os.path.dirname(out_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        log(f"could not write report: {exc}")
    gh_output("count", "0")
    gh_output("change-count", "0")
    gh_output("newest-cve", "")
    gh_output("newest-date", "")
    gh_output("catalog-version", "")
    gh_output("source", "error")
    gh_output("report-path", out_path)
    gh_summary(
        [
            "## CISA KEV",
            "",
            f"Fail soft: `{reason}`",
            "",
            DISCLAIMER,
        ]
    )


def fetch_live() -> dict:
    req = urllib.request.Request(API, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        raw = resp.read()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("KEV catalog JSON is not an object")
    return data


def load_fixture(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("fixture JSON is not an object")
    return data


def main() -> int:
    since_raw = (os.environ.get("INPUT_SINCE_DATE") or "").strip()
    fixture = (os.environ.get("INPUT_FIXTURE") or "").strip()
    out_path = (os.environ.get("INPUT_OUT") or "cisa-kev.json").strip() or "cisa-kev.json"
    try:
        cap = int((os.environ.get("INPUT_MAX_RECORDS") or str(DEFAULT_CAP)).strip() or DEFAULT_CAP)
    except ValueError:
        cap = DEFAULT_CAP
    cap = max(1, min(cap, MAX_CAP))

    source = "fixture" if fixture else "live"
    try:
        data = load_fixture(fixture) if fixture else fetch_live()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        fail_soft(str(exc), out_path)
        return 0

    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        vulns = []

    since = parse_day(since_raw) if since_raw else None
    if since_raw and since is None:
        fail_soft(f"invalid since-date (YYYY-MM-DD): {since_raw}", out_path)
        return 0

    def date_added(item: object) -> datetime | None:
        if not isinstance(item, dict):
            return None
        return parse_day(item.get("dateAdded"))

    def sort_key(item: object) -> str:
        dt = date_added(item)
        cve = item.get("cveID") if isinstance(item, dict) else ""
        return f"{dt.date().isoformat() if dt else '0000-00-00'}|{cve or ''}"

    ordered = sorted(
        [v for v in vulns if isinstance(v, dict)],
        key=sort_key,
        reverse=True,
    )
    capped = ordered[:cap]
    changed = []
    if since is not None:
        changed = [v for v in capped if (date_added(v) or datetime.min.replace(tzinfo=timezone.utc)) >= since]

    newest = capped[0] if capped else {}
    newest_cve = str(newest.get("cveID") or "")
    newest_dt = date_added(newest)
    newest_date = newest_dt.date().isoformat() if newest_dt else ""
    catalog_version = str(data.get("catalogVersion") or "")
    date_released = str(data.get("dateReleased") or "")

    report = {
        "ok": True,
        "source": source,
        "catalogVersion": catalog_version,
        "dateReleased": date_released,
        "count": len(capped),
        "catalog-count": data.get("count"),
        "change-count": len(changed) if since else 0,
        "since-date": since_raw or None,
        "newest-cve": newest_cve,
        "newest-date": newest_date,
        "newest-name": newest.get("vulnerabilityName") or "",
        "vulnerabilities": capped,
        "disclaimer": DISCLAIMER,
    }
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    gh_output("count", str(len(capped)))
    gh_output("change-count", str(len(changed) if since else 0))
    gh_output("newest-cve", newest_cve)
    gh_output("newest-date", newest_date)
    gh_output("catalog-version", catalog_version)
    gh_output("source", source)
    gh_output("report-path", out_path)

    label = newest_cve
    if newest.get("vulnerabilityName"):
        label = f"{newest_cve} — {newest.get('vulnerabilityName')}"
    gh_summary(
        [
            "## CISA KEV",
            "",
            f"- Source: `{source}`",
            f"- Rows returned (cap {cap}): **{len(capped)}**",
            f"- Catalog version: `{catalog_version or 'n/a'}` released `{date_released or 'n/a'}`",
            f"- Newest dateAdded: `{newest_date or 'n/a'}` {label}".rstrip(),
            *( [f"- Change count (dateAdded >= {since_raw}): **{len(changed)}**"] if since else [] ),
            "",
            DISCLAIMER,
        ]
    )
    log(f"ok source={source} count={len(capped)} newest={newest_cve} {newest_date}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
