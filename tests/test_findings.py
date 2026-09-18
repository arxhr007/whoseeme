"""Exposure rules: each fires on what it should, and stays quiet on the traps."""

import pytest

from whoseeme.findings import (
    HIGH,
    LOW,
    MEDIUM,
    Account,
    analyze,
    avatar_reuse,
    contact_in_bio,
    cross_links,
    handle_reuse,
    links,
    looks_like_personal_name,
    names,
)


def acct(site, handle="arx", url=None, **kw):
    return Account(handle=handle, site=site, url=url or f"https://{site}.com/{handle}", **kw)


# --- contact details ----------------------------------------------------------


def test_personal_email_in_bio_is_high():
    [finding] = contact_in_bio([acct("github", bio="reach me at aaron@proton.me")])
    assert finding.severity == HIGH
    assert finding.details["emails"] == ["aaron@proton.me"]


def test_the_sites_own_address_is_not_your_contact_detail():
    """A site's meta description often names its support address; it isn't yours."""
    assert contact_in_bio([acct("github", bio="Questions? support@github.com")]) == []
    assert contact_in_bio([acct("github", bio="press@mail.github.com")]) == []


def test_phone_numbers_are_detected():
    [finding] = contact_in_bio([acct("reddit", bio="call +1 (415) 555-0132 anytime")])
    assert finding.details["phones"] == ["+1 (415) 555-0132"]


@pytest.mark.parametrize("bio", [
    "12,345,678 followers",          # commas: follower counts
    "joined 2021-09-22",             # dates have too few digits
    "top 1000 in the world",
    "v1.2.3 released",
])
def test_numbers_that_are_not_phones(bio):
    assert contact_in_bio([acct("x", bio=bio)]) == []


# --- avatars ------------------------------------------------------------------


def test_same_avatar_on_two_sites_is_high():
    accounts = [acct("github", avatar_hash="ffff000011112222"), acct("devto", avatar_hash="ffff000011112223")]
    [finding] = avatar_reuse(accounts)
    assert finding.severity == HIGH
    assert finding.accounts == ["arx:devto", "arx:github"]


def test_different_avatars_do_not_match():
    accounts = [acct("github", avatar_hash="ffffffffffffffff"), acct("devto", avatar_hash="0000000000000000")]
    assert avatar_reuse(accounts) == []


def test_missing_or_garbage_hashes_are_ignored():
    accounts = [acct("github", avatar_hash=""), acct("devto", avatar_hash="not-hex"),
                acct("reddit", avatar_hash="ffff000011112222")]
    assert avatar_reuse(accounts) == []


# --- cross links --------------------------------------------------------------


def test_bio_linking_to_your_other_account():
    accounts = [
        acct("github", url="https://github.com/arx"),
        acct("reddit", url="https://www.reddit.com/user/arx", bio="see https://github.com/arx."),
    ]
    [finding] = cross_links(accounts)
    assert finding.severity == MEDIUM
    assert set(finding.accounts) == {"arx:github", "arx:reddit"}


def test_link_matching_ignores_www_and_trailing_slash():
    accounts = [
        acct("github", url="https://github.com/arx"),
        acct("reddit", url="https://reddit.com/u/arx", bio="https://www.github.com/arx/"),
    ]
    assert len(cross_links(accounts)) == 1


def test_links_to_strangers_are_not_findings():
    accounts = [acct("reddit", url="https://reddit.com/u/arx", bio="https://github.com/someone-else")]
    assert cross_links(accounts) == []


# --- names --------------------------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("Aaron Thomas", True),
    ("Mary-Jane O'Neil", True),
    ("Jean-Luc Picard Jr.", True),
    ("José García", True),
    ("GitHub Profile", False),       # page-title words
    ("The Beatles", False),
    ("aaron thomas", False),         # conservative: lowercase is not assumed a name
    ("Aaron", False),                # one word
    ("arx", False),                  # the handle itself
    ("R2 D2", False),                # digits
])
def test_personal_name_heuristic(name, expected):
    assert looks_like_personal_name(name, handle="arx") is expected


def test_real_name_across_sites_is_one_finding():
    accounts = [acct("github", name="Aaron Thomas"), acct("devto", name="Aaron  Thomas")]
    [finding] = names(accounts)
    assert finding.kind == "real_name"
    assert len(finding.accounts) == 2


def test_nickname_reused_is_name_reuse():
    accounts = [acct("github", name="xX_arx_Xx"), acct("devto", name="xX_arx_Xx")]
    [finding] = names(accounts)
    assert finding.kind == "name_reuse"


def test_nickname_on_one_site_is_nothing():
    assert names([acct("github", name="xX_arx_Xx")]) == []


# --- handles ------------------------------------------------------------------


def test_handle_reuse_severity_scales_with_count():
    few = [acct(s) for s in ("a", "b", "c")]
    many = [acct(s) for s in ("a", "b", "c", "d", "e")]
    assert handle_reuse(few)[0].severity == LOW
    assert handle_reuse(many)[0].severity == MEDIUM


def test_single_site_handle_is_not_reuse():
    assert handle_reuse([acct("github")]) == []


# --- aggregate ----------------------------------------------------------------


def test_analyze_orders_most_severe_first():
    accounts = [
        acct("github", name="Aaron Thomas", bio="aaron@proton.me", avatar_hash="ffff000011112222"),
        acct("devto", name="Aaron Thomas", avatar_hash="ffff000011112222"),
    ]
    severities = [f.severity for f in analyze(accounts)]
    assert severities == sorted(severities, key=["high", "medium", "low"].index)


def test_hostile_bio_is_carried_as_inert_data():
    """Findings quote scraped text; they must not transform or execute it."""
    bio = '<img src=x onerror=alert(1)> aaron@proton.me'
    [finding] = contact_in_bio([acct("github", bio=bio)])
    assert finding.details["emails"] == ["aaron@proton.me"]


def test_links_exclude_handle_reuse_and_merge_reasons():
    accounts = [
        acct("github", name="Aaron Thomas", avatar_hash="ffff000011112222"),
        acct("devto", name="Aaron Thomas", avatar_hash="ffff000011112222"),
    ]
    edges = links(analyze(accounts))
    assert edges == [{"a": "arx:devto", "b": "arx:github", "via": ["avatar_reuse", "real_name"]}]


@pytest.mark.parametrize("title", ["Internal Server Error", "Interner Serverfehler", "Page Not Found"])
def test_error_page_titles_are_never_your_name(title):
    """Regression: 'Internal Server Error' passed the name shape test."""
    assert not looks_like_personal_name(title, "arx")
    assert names([acct("a", name=title), acct("b", name=title)])[0].kind == "name_reuse"


# --- names inside titles, and counting services not pages --------------------

from whoseeme.models import personal_name_in  # noqa: E402


@pytest.mark.parametrize("title,expected", [
    ("Aaron Thomas (@arxhr007) on X", "Aaron Thomas"),        # X / Twitter
    ("arxhr007 (Aaron Thomas) · GitHub", "Aaron Thomas"),     # GitHub <title>
    ("Aaron Thomas - Medium", "Aaron Thomas"),
    ("Jean-Luc Picard | LinkedIn", "Jean-Luc Picard"),
    ("Aaron Thomas", "Aaron Thomas"),
    ("arxhr007 - Overview", ""),                              # GitHub og:title: no name
    ("Internal Server Error", ""),
    ("Just A Moment (Cloudflare)", ""),
    ("", ""),
])
def test_personal_name_in_real_title_shapes(title, expected):
    """Live scan: the real name was missed because the whole title was tested."""
    assert personal_name_in(title, "arxhr007") == expected


def test_real_name_found_inside_a_decorated_title():
    [finding] = names([acct("twitter", handle="arxhr007", name="Aaron Thomas (@arxhr007) on X")])
    assert finding.kind == "real_name"
    assert '"Aaron Thomas"' in finding.evidence


def test_two_pages_of_one_service_are_not_name_reuse():
    """GitHub's profile and sponsors pages share an og:title; that's one site."""
    accounts = [
        acct("github", url="https://github.com/arx", name="arx - Overview"),
        acct("github.sponsors", url="https://github.com/sponsors/arx", name="arx - Overview"),
    ]
    assert names(accounts) == []


def test_handle_reuse_counts_services_not_pages():
    accounts = [
        acct("github", url="https://github.com/arx"),
        acct("github.sponsors", url="https://github.com/sponsors/arx"),
    ]
    assert handle_reuse(accounts) == []
