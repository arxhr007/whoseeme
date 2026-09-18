"""Exposure rules: what a stranger could learn, and link, from your accounts.

Every rule here is a heuristic over public profile fields, and the evidence text
says so where it matters. There is deliberately no single "privacy score": one
number would imply a precision these rules do not have. The output is a list of
concrete findings, each naming the accounts and the evidence behind it.

A trap worth knowing: when a page has no real profile fields, the scanner falls
back to page-level metadata -- the site's favicon as "avatar", the <title> as
"name", the site's meta description as "bio". Treated as personal data, that
would report a site's own logo as your avatar. So names are used only when they
came from a structured profile field, and contact details are ignored when they
belong to the site itself.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .evidence import avatar_match
from .models import Account, looks_like_personal_name, norm, personal_name_in, url_key
from .remediation import host_of

__all__ = ["Account", "Finding", "analyze", "links", "looks_like_personal_name"]

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

# Handle reuse on this many sites or more is rated medium rather than low.
HANDLE_REUSE_MEDIUM_AT = 5

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Phone-shaped: optional +, then digits with spaces/dots/dashes/parens. Commas are
# excluded so follower counts like "12,345,678" never match.
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


@dataclass
class Finding:
    kind: str
    severity: str
    accounts: list[str]
    title: str
    evidence: str
    advice: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- helpers ----------------------------------------------------------------


def _site_owns(email: str, account_url: str) -> bool:
    """True when an address belongs to the site itself (support@github.com on GitHub)."""
    domain = email.rsplit("@", 1)[-1].lower().rstrip(".")
    host = host_of(account_url)
    return bool(host) and (domain == host or host.endswith("." + domain) or domain.endswith("." + host))


def _label(accounts: dict[str, Account], keys: list[str]) -> str:
    """Site names, one per service, so the text agrees with the counts."""
    per_service: dict[str, str] = {}
    for key in sorted(keys):
        if key in accounts:
            per_service.setdefault(accounts[key].service, accounts[key].site)
    sites = sorted(per_service.values())
    if len(sites) <= 3:
        return ", ".join(sites)
    return f"{', '.join(sites[:3])} and {len(sites) - 3} more"


# --- rules ------------------------------------------------------------------


def contact_in_bio(accounts: list[Account]) -> list[Finding]:
    findings = []
    for account in accounts:
        emails = sorted({e for e in _EMAIL_RE.findall(account.bio) if not _site_owns(e, account.url)})
        phones = sorted(
            {p.strip() for p in _PHONE_RE.findall(account.bio) if sum(c.isdigit() for c in p) >= 9}
        )
        if not (emails or phones):
            continue
        found = [f"email {e}" for e in emails] + [f"phone-like number {p}" for p in phones]
        findings.append(Finding(
            kind="contact_in_bio",
            severity=HIGH,
            accounts=[account.key],
            title=f"Contact details in your {account.site} bio",
            evidence=f"Your public bio on {account.site} contains " + "; ".join(found) + ".",
            advice="Remove direct contact details from public bios, or use an alias address you "
                   "can retire. Phone detection is a pattern match and can misfire; check it.",
            details={"emails": emails, "phones": phones},
        ))
    return findings


def avatar_reuse(accounts: list[Account]) -> list[Finding]:
    """Accounts on different services showing the same picture.

    Uses the same strict test as linkage (evidence.avatar_match): near-identical
    and detailed enough to be a real photo rather than a flat logo.
    """
    with_hash = [a for a in accounts if a.avatar_hash]
    parent = {a.key: a.key for a in with_hash}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for i, a in enumerate(with_hash):
        for b in with_hash[i + 1:]:
            if a.service != b.service and avatar_match(a.avatar_hash, b.avatar_hash):
                parent[find(b.key)] = find(a.key)

    groups: dict[str, list[Account]] = {}
    for account in with_hash:
        groups.setdefault(find(account.key), []).append(account)

    findings = []
    for group in groups.values():
        if len({a.service for a in group}) < 2:
            continue
        keys = sorted(a.key for a in group)
        lookup = {a.key: a for a in group}
        findings.append(Finding(
            kind="avatar_reuse",
            severity=HIGH,
            accounts=keys,
            title=f"Same profile picture on {len({a.service for a in group})} sites",
            evidence=f"The same image is your avatar on {_label(lookup, keys)}. Anyone who "
                     "finds one of these accounts can match the others by picture alone.",
            advice="Use a different picture per site, or no photo, on accounts you don't "
                   "want tied together.",
        ))
    return findings


def cross_links(accounts: list[Account]) -> list[Finding]:
    """A bio that links out to another of your accounts."""
    by_url = {url_key(a.url): a for a in accounts}
    findings = []
    for account in accounts:
        targets = []
        for url in _URL_RE.findall(account.bio):
            target = by_url.get(url_key(url.rstrip(".,;:!?")))
            if target is not None and target.service != account.service:
                targets.append(target)
        if not targets:
            continue
        keys = sorted({account.key, *(t.key for t in targets)})
        sites = ", ".join(sorted({t.site for t in targets}))
        findings.append(Finding(
            kind="cross_link",
            severity=MEDIUM,
            accounts=keys,
            title=f"Your {account.site} bio links to your {sites}",
            evidence=f"The public bio on {account.site} links directly to your account on {sites}.",
            advice="Links between accounts turn separate identities into one. Remove them "
                   "where you want the accounts kept apart.",
        ))
    return findings


def names(accounts: list[Account]) -> list[Finding]:
    """Real names shown in titles, and any display name reused across services.

    Counted per *service*: GitHub's profile and sponsors pages carrying the same
    og:title is one site repeating itself, not a name reused.
    """
    findings = []
    real: dict[str, list[Account]] = {}
    for account in accounts:
        found = personal_name_in(account.name, account.handle)
        if found:
            real.setdefault(norm(found), []).append(account)
    for group in real.values():
        shown = personal_name_in(group[0].name, group[0].handle)
        services = {a.service for a in group}
        keys = sorted(a.key for a in group)
        lookup = {a.key: a for a in group}
        findings.append(Finding(
            kind="real_name",
            severity=MEDIUM,
            accounts=keys,
            title=f"Your name appears on {len(services)} site{'s' if len(services) > 1 else ''}",
            evidence=f"\"{shown}\" is shown on {_label(lookup, keys)}. It looks like a real "
                     "name -- a guess from its shape, so check it.",
            advice="If you don't want these accounts tied to your legal identity, use a "
                   "display name that isn't your real one.",
        ))

    reused: dict[str, list[Account]] = {}
    for account in accounts:
        if account.name and not personal_name_in(account.name, account.handle):
            reused.setdefault(norm(account.name), []).append(account)
    for group in reused.values():
        services = {a.service for a in group}
        if len(services) < 2:
            continue
        keys = sorted(a.key for a in group)
        lookup = {a.key: a for a in group}
        findings.append(Finding(
            kind="name_reuse",
            severity=MEDIUM,
            accounts=keys,
            title=f"Same display name on {len(services)} sites",
            evidence=f"\"{group[0].name}\" is your display name on {_label(lookup, keys)}.",
            advice="A distinctive display name links accounts as well as a handle does.",
        ))
    return findings


def handle_reuse(accounts: list[Account]) -> list[Finding]:
    by_handle: dict[str, list[Account]] = {}
    for account in accounts:
        by_handle.setdefault(account.handle.lower(), []).append(account)

    findings = []
    for group in by_handle.values():
        sites = {a.service for a in group}   # services, not pages of one service
        if len(sites) < 2:
            continue
        keys = sorted(a.key for a in group)
        lookup = {a.key: a for a in group}
        severity = MEDIUM if len(sites) >= HANDLE_REUSE_MEDIUM_AT else LOW
        findings.append(Finding(
            kind="handle_reuse",
            severity=severity,
            accounts=keys,
            title=f"Handle \"{group[0].handle}\" used on {len(sites)} sites",
            evidence=f"You use \"{group[0].handle}\" on {_label(lookup, keys)}. Searching that "
                     "one handle finds all of them.",
            advice="Reusing a handle is the easiest link to follow. Vary it on accounts you "
                   "want kept separate.",
        ))
    return findings


RULES = (contact_in_bio, avatar_reuse, cross_links, names, handle_reuse)


def analyze(accounts: list[Account]) -> list[Finding]:
    """Run every rule and return findings, most severe first."""
    findings = [finding for rule in RULES for finding in rule(accounts)]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.kind, f.accounts))
    return findings


def links(findings: list[Finding]) -> list[dict[str, Any]]:
    """Pairwise edges between accounts, with why they connect.

    Handle reuse is left out: it connects every account sharing a handle to
    every other, which would bury the more specific links in noise. It is
    reported as its own finding instead.
    """
    edges: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        if finding.kind == "handle_reuse" or len(finding.accounts) < 2:
            continue
        keys = finding.accounts
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                edges.setdefault(tuple(sorted((a, b))), set()).add(finding.kind)
    return [
        {"a": a, "b": b, "via": sorted(kinds)}
        for (a, b), kinds in sorted(edges.items())
    ]
