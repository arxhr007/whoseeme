"""Fixtures shaped exactly like aliens-eye's report and correlation output."""

import pytest

from whoseeme.remediation import RemediationIndex


def site_entry(url, status="Found", name="", bio="", structured=True, confidence=90):
    return {
        "url": url,
        "status": status,
        "confidence": confidence,
        "ai_analysis": {
            "signals": {
                "profile": {
                    "name": name,
                    "bio": bio,
                    "avatar": "",
                    "name_from_profile": structured,
                }
            }
        },
    }


@pytest.fixture
def report():
    """Handle "arx": three accounts that are you, two strangers, one miss.

    github <-> devto share an avatar (a correlation cluster); reddit links to
    github from its bio. gitlab and tumblr belong to other people.
    """
    return {
        "handles": ["arx"],
        "variations": {
            "arx": {
                "sites": {
                    "github": site_entry(
                        "https://github.com/arx", name="Aaron Thomas",
                        bio="Security person. aaron@proton.me",
                    ),
                    "devto": site_entry("https://dev.to/arx", name="Aaron Thomas"),
                    "reddit": site_entry(
                        "https://www.reddit.com/user/arx", name="",
                        bio="also https://github.com/arx",
                    ),
                    "gitlab": site_entry("https://gitlab.com/arx", name="Arx Corp Official"),
                    "tumblr": site_entry("https://arx.tumblr.com", status="Maybe", structured=False),
                    "vimeo": site_entry("https://vimeo.com/arx", status="Not Found"),
                }
            }
        },
    }


@pytest.fixture
def correlation():
    return {
        "avatar_hashing": True,
        "profiles_considered": 4,
        "clusters": [
            {
                "size": 3,
                "reasons": ["avatar", "shared-link"],
                "members": [
                    {"variation": "arx", "site": "github", "avatar_hash": "ffff000011112222"},
                    {"variation": "arx", "site": "devto", "avatar_hash": "ffff000011112223"},
                    {"variation": "arx", "site": "reddit", "avatar_hash": None},
                ],
            },
        ],
    }


@pytest.fixture
def remediation():
    return RemediationIndex([
        {"name": "GitHub", "url": "https://github.com/settings/admin", "difficulty": "easy",
         "domains": ["github.com"]},
        {"name": "Reddit", "url": "https://www.reddit.com/settings/account", "difficulty": "easy",
         "domains": ["reddit.com", "old.reddit.com"]},
        {"name": "Tumblr", "url": "https://www.tumblr.com/settings/account", "difficulty": "medium",
         "domains": ["tumblr.com"]},
    ])
