"""What counts as evidence that two accounts share an owner.

whoseeme tells people "a stranger could link this account to you", so the bar is
deliberately higher than aliens-eye's clustering, which is an investigator's
hint ("likely the same person"). Getting this wrong is not a small error: a
first end-to-end run on a real handle traced 227 accounts to one confirmed
GitHub profile, nearly all of them strangers or false positives, before these
rules existed.

Every rule requires the two accounts to be on **different services** -- two
pages of one service (twitch.tv and its /team page) trivially share a logo and
tie together no separate identities.

* ``same_avatar`` -- near-identical images (dhash within 4 bits) that carry
  enough detail (at least 16 bits set). On a live scan, the only matches between
  unrelated sites were sparse hashes (9-15 bits: flat logos and placeholders) at
  distance 7-8, while genuine image reuse matched at 0.
* ``links_to`` -- one bio contains the other account's profile URL.
* ``mentions`` -- one bio @-mentions the handle the other was found under, and
  the two were found under *different* handles. A page mentioning the handle
  that was searched for is noise: many sites print it in their own page chrome.
* ``same_name`` -- identical display names that look like a personal name.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any

from .models import Account, norm, personal_name_in, url_key

AVATAR_MAX_HAMMING = 4
AVATAR_MIN_BITS = 16

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
_HANDLE_RE = re.compile(r"@([A-Za-z0-9_.]{2,30})")

KIND_TEXT = {
    "same_avatar": "same profile picture as",
    "links_to": "linked from the bio of",
    "mentions": "mentioned by",
    "same_name": "same name as",
}


@dataclass(frozen=True)
class Edge:
    a: str
    b: str
    kind: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _bits(hex_hash: str) -> int | None:
    try:
        return bin(int(hex_hash, 16)).count("1")
    except (TypeError, ValueError):
        return None


def avatar_match(a: str, b: str) -> bool:
    """Same picture, and a picture with enough detail to mean something."""
    bits_a, bits_b = _bits(a), _bits(b)
    if bits_a is None or bits_b is None:
        return False
    if min(bits_a, bits_b) < AVATAR_MIN_BITS:
        return False
    return bin(int(a, 16) ^ int(b, 16)).count("1") <= AVATAR_MAX_HAMMING


def _mentions(account: Account) -> set[str]:
    return {h.lower().rstrip(".") for h in _HANDLE_RE.findall(account.bio)}


def _links(account: Account) -> set[str]:
    return {url_key(u.rstrip(".,;:!?")) for u in _URL_RE.findall(account.bio)}


def pair_evidence(a: Account, b: Account) -> Edge | None:
    """The strongest reason two accounts share an owner, or None."""
    if a.key == b.key or not a.service or a.service == b.service:
        return None
    if a.avatar_hash and b.avatar_hash and avatar_match(a.avatar_hash, b.avatar_hash):
        return Edge(a.key, b.key, "same_avatar",
                    f"{a.site} and {b.site} show the same profile picture")
    if url_key(b.url) in _links(a):
        return Edge(a.key, b.key, "links_to", f"the {a.site} bio links to the {b.site} profile")
    if url_key(a.url) in _links(b):
        return Edge(a.key, b.key, "links_to", f"the {b.site} bio links to the {a.site} profile")
    if a.handle.lower() != b.handle.lower():
        if b.handle.lower() in _mentions(a):
            return Edge(a.key, b.key, "mentions", f"the {a.site} bio mentions @{b.handle}")
        if a.handle.lower() in _mentions(b):
            return Edge(a.key, b.key, "mentions", f"the {b.site} bio mentions @{a.handle}")
    name_a, name_b = personal_name_in(a.name, a.handle), personal_name_in(b.name, b.handle)
    if name_a and norm(name_a) == norm(name_b):
        return Edge(a.key, b.key, "same_name", f"{a.site} and {b.site} both show the name \"{name_a}\"")
    return None


def trace(
    accounts: list[Account],
    anchors: set[str],
    rejected: set[str] = frozenset(),
) -> dict[str, Edge | None]:
    """Everything reachable from the anchors through evidence, and how.

    Returns ``{key: edge}`` where ``edge`` is how that account was first reached
    (``None`` for an anchor). Breadth-first, so each account is reached by the
    shortest chain of evidence back to something the user confirmed. Rejected
    accounts are neither reached nor traversed: a chain never runs through an
    account the user said isn't theirs.
    """
    by_key = {a.key: a for a in accounts if a.key not in rejected}
    reached: dict[str, Edge | None] = {k: None for k in anchors if k in by_key}
    queue = deque(reached)
    while queue:
        current = by_key[queue.popleft()]
        for other in by_key.values():
            if other.key in reached:
                continue
            edge = pair_evidence(current, other)
            if edge is not None:
                reached[other.key] = edge
                queue.append(other.key)
    return reached
