"""The account record every rule reads, and the small helpers they share."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from .remediation import host_of

_NAME_TOKEN_RE = re.compile(r"^[^\W\d_][^\W\d_'’-]*(?:['’-][^\W\d_]+)*\.?$", re.UNICODE)

# Words that show up in page titles, brand names and error or bot-wall pages,
# never in a person's name. Error pages matter most: their og:title is often
# structured metadata ("Internal Server Error"), and two sites failing the same
# way would otherwise "share your name". Includes common German forms seen on
# live scans ("Interner Serverfehler").
_NOT_NAME_WORDS = {
    "profile", "user", "users", "account", "page", "home", "official", "team",
    "the", "and", "of", "on", "for", "with", "channel", "videos", "photos",
    "music", "blog", "news", "shop", "store", "app", "login", "sign", "welcome",
    "error", "internal", "server", "found", "not", "forbidden", "denied", "access",
    "unavailable", "maintenance", "oops", "sorry", "missing", "blocked", "captcha",
    "verify", "verification", "human", "robot", "moment", "attention", "required",
    "loading", "redirecting", "gateway", "timeout", "request", "service", "bad",
    "interner", "serverfehler", "fehler", "nicht", "gefunden", "seite",
}

# Second-level labels under which the registrable domain is three labels deep
# (example.co.uk). Not the full public-suffix list: a miss only means two sites
# under the same country suffix are treated as one service, which errs toward
# claiming fewer links, never more.
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"}


@dataclass
class Account:
    """One account, reduced to the public fields the rules read."""

    handle: str
    site: str
    url: str
    status: str = "Found"
    name: str = ""          # structured display name only; "" if none
    bio: str = ""
    avatar_hash: str = ""   # 16-hex dhash from correlation; "" if unavailable

    @property
    def key(self) -> str:
        return f"{self.handle}:{self.site}"

    @property
    def service(self) -> str:
        return service_of(self.url)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "key": self.key}


def norm(text: str) -> str:
    return " ".join(re.findall(r"\w+", (text or "").lower()))


def service_of(url: str) -> str:
    """The service a URL belongs to, approximated by its registrable domain.

    twitch.tv/arx and twitch.tv/team/arx are one service; arx.tumblr.com and
    tumblr.com/arx are one service. Evidence between two pages of the same
    service says nothing about a stranger linking separate identities.
    """
    host = host_of(url)
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def url_key(url: str) -> str:
    """URL identity ignoring scheme, ``www.``, case, and a trailing slash."""
    try:
        path = urlparse(url).path
    except ValueError:
        return ""
    return f"{host_of(url)}{path.rstrip('/').lower()}"


# Separators sites put between a name and their own branding in og:title:
# "Name - GitHub", "Name | Medium", "Name · GitHub", "Name • Instagram", "Name on X".
_TITLE_SPLIT_RE = re.compile(r"\s+(?:[-|·•—–:]|on)\s+", re.IGNORECASE)
_PARENS_RE = re.compile(r"\(([^()]*)\)")


def personal_name_in(title: str, handle: str = "") -> str:
    """The personal name embedded in a profile title, or "".

    Titles wrap the name in site branding: "Aaron Thomas (@arx) on X",
    "arx (Aaron Thomas) · GitHub", "Aaron Thomas - Medium". Testing the whole
    string misses the name; this tries the leading segment with any
    parenthesised part removed, then each parenthesised part on its own.
    """
    title = (title or "").strip()
    if not title:
        return ""
    candidates = [title]
    bare = _PARENS_RE.sub(" ", title)
    candidates.append(_TITLE_SPLIT_RE.split(bare)[0])
    candidates.extend(_PARENS_RE.findall(title))
    for candidate in candidates:
        candidate = " ".join(candidate.split())
        if looks_like_personal_name(candidate, handle):
            return candidate
    return ""


def looks_like_personal_name(name: str, handle: str = "") -> bool:
    """Heuristic: 2-4 capitalised alphabetic words, not the handle, not a title.

    Deliberately conservative -- it prefers missing a name to calling a page
    title or a brand someone's real name.
    """
    words = (name or "").split()
    if not 2 <= len(words) <= 4:
        return False
    if norm(name).replace(" ", "") == norm(handle).replace(" ", ""):
        return False
    for word in words:
        if not _NAME_TOKEN_RE.match(word) or not word[0].isupper():
            return False
        if word.lower().rstrip(".") in _NOT_NAME_WORDS:
            return False
    return True
