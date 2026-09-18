"""Scan -> "which of these are you?" -> trace evidence -> findings -> remediation.

Searching a handle is not a self-audit. A common handle matches hundreds of
accounts belonging to other people, plus the scanner's own false positives, and
reporting those as "your exposure" would be wrong and alarming. So the audit
starts from accounts the user confirms as theirs (anchors) and follows only
concrete evidence outward from them -- see evidence.py for exactly what counts.
aliens-eye's correlation is used for the avatar hashes it computes, not for its
clusters, which are an investigator's looser "likely the same person" hint.
Everything else found under the same handle is reported separately as
unconfirmed, never mixed into the findings.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from aliens_eye import api

from .evidence import KIND_TEXT, trace
from .findings import Account, analyze, links
from .models import url_key
from .remediation import RemediationIndex

HIT_STATUSES = ("Found", "Maybe")
MAX_HANDLES = 5


# --- inputs -----------------------------------------------------------------


def candidate_handles(handles: Iterable[str], email: str | None = None) -> list[str]:
    """Deduplicated, validated handles, plus those derivable from an email.

    The email is only mined for handle-shaped strings (its local part and its
    splits). It is never sent anywhere, and password-reset endpoints are never
    probed to test whether it is registered.
    """
    from aliens_eye.core.variations import usernames_from_email

    raw = [h.strip() for h in handles if h and h.strip()]
    if email and "@" in email:
        raw.extend(usernames_from_email(email))
    seen: dict[str, str] = {}
    for handle in raw:
        if 2 <= len(handle) <= 64:
            seen.setdefault(handle.lower(), handle)
    return list(seen.values())[:MAX_HANDLES]


# --- scanning ---------------------------------------------------------------


async def scan_handles(
    handles: list[str],
    *,
    sites: dict[str, str] | None = None,
    on_result: Callable[[str, dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Scan every handle and merge the reports into one.

    One merged report means correlation sees all handles together, so accounts
    under different handles can still be linked by avatar or cross-links.
    """
    merged: dict[str, Any] = {"variations": {}, "handles": list(handles)}
    for handle in handles:
        report = await api.scan(handle, sites=sites, on_result=on_result)
        merged["variations"].update(report.get("variations", {}))
    return merged


def hits(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Found/Maybe results, flattened for display. Found first."""
    rows = []
    for handle, block in report.get("variations", {}).items():
        for site, info in (block.get("sites") or {}).items():
            if info.get("status") not in HIT_STATUSES:
                continue
            profile = (info.get("ai_analysis") or {}).get("signals", {}).get("profile") or {}
            rows.append({
                "key": f"{handle}:{site}",
                "handle": handle,
                "site": site,
                "url": info.get("url", ""),
                "status": info.get("status"),
                "confidence": info.get("confidence", 0),
                # Structured names only: the fallback is the page <title>.
                "name": profile.get("name", "") if profile.get("name_from_profile") else "",
            })
    rows.sort(key=lambda r: (HIT_STATUSES.index(r["status"]), -r["confidence"], r["site"]))
    return rows


# --- anchors and linkage ----------------------------------------------------


def resolve_anchor_urls(report: dict[str, Any], urls: Iterable[str]) -> tuple[set[str], list[str]]:
    """Map profile URLs the user supplied onto result keys.

    Returns ``(keys, unmatched_urls)``. Matching ignores scheme, ``www.``,
    trailing slashes and case, since people paste URLs in every form.
    """
    index = {url_key(row["url"]): row["key"] for row in hits(report)}
    keys, unmatched = set(), []
    for url in urls:
        key = index.get(url_key(url.strip()))
        if key:
            keys.add(key)
        else:
            unmatched.append(url)
    return keys, unmatched


def _avatar_hashes(correlation: dict[str, Any]) -> dict[str, str]:
    """Avatar hash per account key.

    aliens-eye >= 2.5 returns every considered profile; clusters are read too so
    an older result without ``profiles`` still yields what it can.
    """
    members = list(correlation.get("profiles") or [])
    for cluster in correlation.get("clusters", []):
        members.extend(cluster.get("members", []))
    return {
        f"{m.get('variation', '')}:{m.get('site', '')}": m["avatar_hash"]
        for m in members
        if m.get("avatar_hash")
    }


def _accounts(report: dict[str, Any], keys: set[str], hashes: dict[str, str]) -> list[Account]:
    accounts = []
    for handle, block in report.get("variations", {}).items():
        for site, info in (block.get("sites") or {}).items():
            key = f"{handle}:{site}"
            if key not in keys:
                continue
            profile = (info.get("ai_analysis") or {}).get("signals", {}).get("profile") or {}
            accounts.append(Account(
                handle=handle,
                site=site,
                url=info.get("url", ""),
                status=info.get("status", ""),
                name=profile.get("name", "") if profile.get("name_from_profile") else "",
                bio=profile.get("bio", "") or "",
                avatar_hash=hashes.get(key, ""),
            ))
    return sorted(accounts, key=lambda a: a.key)


# --- the audit --------------------------------------------------------------


def build_audit(
    report: dict[str, Any],
    correlation: dict[str, Any],
    anchors: set[str],
    rejected: set[str] = frozenset(),
    remediation: RemediationIndex | None = None,
) -> dict[str, Any]:
    """Assemble the report the user sees.

    ``anchors`` are accounts the user marked as theirs; ``rejected`` are ones
    they marked as not theirs. A rejection always wins, including over
    evidence: the user knows their accounts better than a heuristic does, and no
    chain of evidence is followed through a rejected account.
    """
    remediation = remediation or RemediationIndex.load()
    rejected = set(rejected)
    anchors = set(anchors) - rejected
    hashes = _avatar_hashes(correlation)

    # Candidates: every Found hit, plus the anchors whatever their status (the
    # user vouched for those). Maybe hits are mostly bot walls and error pages,
    # so they can be confirmed by hand but never pulled in by evidence.
    found = {row["key"] for row in hits(report) if row["status"] == "Found"}
    candidates = _accounts(report, found | anchors, hashes)
    reached = trace(candidates, anchors, rejected)
    yours = set(reached)

    accounts = [a for a in candidates if a.key in yours]
    by_key = {a.key: a for a in accounts}
    findings = analyze(accounts)

    account_rows = []
    for account in accounts:
        fix = remediation.lookup(account.url)
        edge = reached[account.key]
        linked_via = None
        if edge is not None:
            other = edge.a if edge.b == account.key else edge.b
            linked_via = {
                "kind": edge.kind,
                "from": other,
                "from_site": by_key[other].site if other in by_key else other,
                "text": f"{KIND_TEXT[edge.kind]} your {by_key[other].site if other in by_key else other}",
                "detail": edge.detail,
            }
        account_rows.append({
            **account.to_dict(),
            "source": "confirmed" if account.key in anchors else "linked",
            "linked_via": linked_via,
            "findings": [i for i, f in enumerate(findings) if account.key in f.accounts],
            "remediation": fix.to_dict() if fix else None,
        })

    unconfirmed = [
        row for row in hits(report)
        if row["key"] not in yours and row["key"] not in rejected
    ]

    by_severity: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        by_severity[finding.severity] += 1

    return {
        "handles": report.get("handles") or list(report.get("variations", {})),
        "summary": {
            "accounts": len(accounts),
            "confirmed": len(anchors & yours),
            "linked_by_evidence": len(yours - anchors),
            "unconfirmed": len(unconfirmed),
            "findings": by_severity,
            "avatar_matching": bool(correlation.get("avatar_hashing")),
        },
        "accounts": account_rows,
        "findings": [f.to_dict() for f in findings],
        "links": links(findings),
        "unconfirmed": unconfirmed,
    }


async def correlate(report: dict[str, Any]) -> dict[str, Any]:
    """Correlate a merged report. Private avatar addresses stay blocked."""
    return await api.correlate(report)
