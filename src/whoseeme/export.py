"""Standalone HTML export of an audit.

Every string in an audit ultimately comes from a scraped page -- display names,
bios, evidence quoting them -- so every one is HTML-escaped, and the page's
Content-Security-Policy forbids scripts and remote resources outright. Opening
an export can neither run a hostile bio as code nor fetch anything from the
network (which would tell a third party you opened it).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import Any
from urllib.parse import urlparse

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

_STYLE = """
body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1c1c1e;background:#fff}
h1{font-size:1.6rem;margin:0 0 .25rem}h2{font-size:1.15rem;margin:2rem 0 .75rem}
.muted{color:#6b6b70}.card{border:1px solid #e3e3e8;border-radius:10px;padding:.9rem 1rem;margin:.6rem 0}
.sev{display:inline-block;font-size:.75rem;font-weight:600;text-transform:uppercase;padding:.1rem .5rem;border-radius:99px;margin-right:.5rem}
.high{background:#fde2e1;color:#9b1c1c}.medium{background:#fdf0d5;color:#8a5300}.low{background:#e6eefc;color:#1e4a9e}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #eee;vertical-align:top}
a{color:#1e4a9e;word-break:break-all}
@media (prefers-color-scheme:dark){body{background:#111113;color:#e8e8ea}.card{border-color:#2c2c30}
td,th{border-color:#2c2c30}.muted{color:#9a9aa0}a{color:#8fb2ff}}
"""


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _safe_href(url: str) -> str:
    """Only http(s) links survive; anything else (javascript:, data:) is dropped."""
    try:
        scheme = urlparse(url).scheme.lower()
    except ValueError:
        return ""
    return _e(url) if scheme in {"http", "https"} else ""


def _link(url: str, text: str | None = None) -> str:
    href = _safe_href(url)
    label = _e(text if text is not None else url)
    if not href:
        return label
    return f'<a href="{href}" rel="noopener noreferrer" target="_blank">{label}</a>'


def render_html(audit: dict[str, Any]) -> str:
    summary = audit.get("summary", {})
    sev = summary.get("findings", {})
    accounts = {a["key"]: a for a in audit.get("accounts", [])}
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>whoseeme report</title>",
        f"<style>{_STYLE}</style></head><body>",
        "<h1>What a stranger could link to you</h1>",
        f'<p class="muted">Handles: {_e(", ".join(audit.get("handles", [])))} &middot; '
        f"generated {_e(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))} by whoseeme</p>",
        f'<p>{_e(summary.get("accounts", 0))} accounts traced to you '
        f'({_e(summary.get("confirmed", 0))} you confirmed, '
        f'{_e(summary.get("linked_by_evidence", 0))} linked to them by evidence). '
        f'Findings: <span class="sev high">{_e(sev.get("high", 0))} high</span>'
        f'<span class="sev medium">{_e(sev.get("medium", 0))} medium</span>'
        f'<span class="sev low">{_e(sev.get("low", 0))} low</span></p>',
    ]
    if not summary.get("avatar_matching", True):
        parts.append(
            '<p class="muted">Avatar matching was unavailable, so reused profile pictures '
            "could not be detected.</p>"
        )

    parts.append("<h2>Findings</h2>")
    findings = audit.get("findings", [])
    if not findings:
        parts.append('<p class="muted">No findings.</p>')
    for finding in findings:
        parts.append(
            f'<div class="card"><span class="sev {_e(finding["severity"])}">'
            f'{_e(finding["severity"])}</span><strong>{_e(finding["title"])}</strong>'
            f'<p>{_e(finding["evidence"])}</p><p class="muted">{_e(finding["advice"])}</p></div>'
        )

    edges = audit.get("links", [])
    if edges:
        parts.append("<h2>How your accounts connect</h2><table><tr><th>Account</th>"
                     "<th>Account</th><th>Linked by</th></tr>")
        for edge in edges:
            a, b = accounts.get(edge["a"], {}), accounts.get(edge["b"], {})
            via = ", ".join(k.replace("_", " ") for k in edge["via"])
            parts.append(f"<tr><td>{_e(a.get('site', edge['a']))}</td>"
                         f"<td>{_e(b.get('site', edge['b']))}</td><td>{_e(via)}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Your accounts</h2><table><tr><th>Site</th><th>Profile</th>"
                 "<th>How it was traced</th><th>Delete it</th></tr>")
    for account in audit.get("accounts", []):
        fix = account.get("remediation")
        delete = (
            f'{_link(fix["url"], "instructions")} <span class="muted">({_e(fix["difficulty"])})</span>'
            if fix else '<span class="muted">no guidance on file</span>'
        )
        via = account.get("linked_via") or {}
        traced = "you confirmed it" if account.get("source") == "confirmed" else via.get("text", "linked to your accounts")
        parts.append(f"<tr><td>{_e(account['site'])}</td><td>{_link(account['url'])}</td>"
                     f"<td>{_e(traced)}</td><td>{delete}</td></tr>")
    parts.append("</table>")

    unconfirmed = audit.get("unconfirmed", [])
    if unconfirmed:
        parts.append(
            f"<h2>Found under your handle, not linked to you ({len(unconfirmed)})</h2>"
            '<p class="muted">These share a handle with you but nothing ties them to your '
            "confirmed accounts. They may belong to other people.</p><table>"
        )
        for row in unconfirmed:
            parts.append(f"<tr><td>{_e(row['site'])}</td><td>{_link(row['url'])}</td>"
                         f"<td>{_e(row['status'])}</td></tr>")
        parts.append("</table>")

    parts.append(
        '<p class="muted">Deletion guidance from '
        f'{_link("https://github.com/jdm-contrib/jdm", "JustDeleteMe")} (MIT).</p>'
        "</body></html>"
    )
    return "\n".join(parts)


def render_json(audit: dict[str, Any]) -> str:
    return json.dumps(audit, indent=2, ensure_ascii=False)
