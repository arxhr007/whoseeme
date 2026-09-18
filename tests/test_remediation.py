import json

import pytest

from whoseeme.remediation import RemediationIndex, _parents, host_of


@pytest.mark.parametrize("url,host", [
    ("https://www.GitHub.com/arx", "github.com"),
    ("https://gitlab.com:8443/x", "gitlab.com"),
    ("https://arx.tumblr.com", "arx.tumblr.com"),
    ("not a url", ""),
    ("", ""),
])
def test_host_of(url, host):
    assert host_of(url) == host


def test_parents_stop_before_a_bare_suffix():
    assert _parents("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert _parents("localhost") == []


def test_lookup_matches_per_user_subdomains(remediation):
    assert remediation.lookup("https://arx.tumblr.com").service == "Tumblr"


def test_lookup_uses_every_listed_domain(remediation):
    assert remediation.lookup("https://old.reddit.com/u/arx").service == "Reddit"


def test_unknown_or_bad_urls_have_no_guidance(remediation):
    assert remediation.lookup("https://nowhere.example/arx") is None
    assert remediation.lookup("javascript:alert(1)") is None


def test_first_entry_wins_on_shared_domains():
    index = RemediationIndex([
        {"name": "A", "url": "https://a", "domains": ["shared.com"]},
        {"name": "B", "url": "https://b", "domains": ["shared.com"]},
    ])
    assert index.lookup("https://shared.com/x").service == "A"


def test_entries_without_a_url_are_skipped():
    index = RemediationIndex([{"name": "Broken", "domains": ["broken.com"]}])
    assert index.lookup("https://broken.com") is None


def test_packaged_dataset_loads_and_covers_major_sites():
    index = RemediationIndex.load()
    assert len(index) > 2000
    for url in ("https://github.com/x", "https://www.reddit.com/user/x", "https://x.tumblr.com"):
        assert index.lookup(url) is not None, url


def test_packaged_dataset_is_english_only_and_slim():
    """scripts/update_jdm.py strips ~30 translations; a raw copy would bloat the wheel."""
    from importlib import resources

    entries = json.loads((resources.files("whoseeme.data") / "jdm_sites.json").read_text("utf-8"))
    allowed = {"name", "url", "difficulty", "domains", "notes", "email", "email_subject", "email_body"}
    assert all(set(e) <= allowed for e in entries)


def test_attribution_ships_with_the_data():
    from importlib import resources

    license_text = (resources.files("whoseeme.data") / "LICENSE-JDM").read_text("utf-8")
    assert "MIT" in license_text
