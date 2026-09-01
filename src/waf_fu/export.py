"""Batch export modes: curl script, JSON, HAR."""

from __future__ import annotations

import json
from pathlib import Path

from waf_fu.replay.curl import to_curl

# ═══════════════════════════════════════════════════════════════════════════════
# Batch export modes (non-interactive, kept for scripting)
# ═══════════════════════════════════════════════════════════════════════════════


def write_curl_script(requests, output, delay=0.0):
    with open(output, "w") as fh:
        fh.write("#!/usr/bin/env bash\n")
        fh.write(f"# Auto-generated WAF log replay — {len(requests)} requests\n")
        fh.write("set -euo pipefail\n\n")
        for i, req in enumerate(requests, 1):
            fh.write(f"echo '>>> [{i}/{len(requests)}] {req.method} {req.full_url}'\n")
            fh.write(to_curl(req) + "\n")
            fh.write("echo\n")
            if delay > 0:
                fh.write(f"sleep {delay}\n")
            fh.write("\n")
    Path(output).chmod(0o755)


def export_json(requests, output):
    data = [
        {
            "timestamp": r.datetime_utc.isoformat(),
            "method": r.method,
            "url": r.full_url,
            "headers": r.headers,
            "cookies": r.cookies,
            "body": r.body,
            "client_ip": r.client_ip,
            "country": r.country,
            "action": r.action,
            "terminating_rule": r.terminating_rule_id,
            "labels": r.labels,
        }
        for r in requests
    ]
    Path(output).write_text(json.dumps(data, indent=2))


def export_har(requests, output):
    entries = []
    for req in requests:
        entry = {
            "startedDateTime": req.datetime_utc.isoformat(),
            "time": 0,
            "request": {
                "method": req.method,
                "url": req.full_url,
                "httpVersion": req.http_version,
                "cookies": [],
                "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                "queryString": [],
                "headersSize": -1,
                "bodySize": len(req.body.encode()) if req.body else 0,
            },
            "response": {
                "status": 0,
                "statusText": "",
                "httpVersion": "",
                "cookies": [],
                "headers": [],
                "content": {"size": 0, "mimeType": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
        }
        if req.body:
            entry["request"]["postData"] = {
                "mimeType": req.content_type or "application/octet-stream",
                "text": req.body,
            }
        entries.append(entry)
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "waf_replay.py", "version": "2.0"},
            "entries": entries,
        }
    }
    Path(output).write_text(json.dumps(har, indent=2))
