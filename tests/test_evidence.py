"""Evidence rules: calibrated on a real scan where the naive version traced 227
strangers and false positives to one confirmed account."""

import pytest

from whoseeme.evidence import AVATAR_MIN_BITS, avatar_match, pair_evidence, trace
from whoseeme.models import Account, service_of

DETAILED = "ffff000011112222"   # 24 bits set: a real photo's worth of detail


def acct(site, handle="arx", url=None, **kw):
    return Account(handle=handle, site=site, url=url or f"https://{site}.com/{handle}", **kw)


# --- services ---------------------------------------------------------------------


@pytest.mark.parametrize("url,service", [
    ("https://twitch.tv/arx", "twitch.tv"),
    ("https://www.twitch.tv/team/arx", "twitch.tv"),
    ("https://arx.tumblr.com", "tumblr.com"),
    ("https://shop.example.co.uk/arx", "example.co.uk"),
    ("https://github.com/arx", "github.com"),
])
def test_service_of(url, service):
    assert service_of(url) == service


# --- avatars ----------------------------------------------------------------------


def test_identical_detailed_images_match():
    assert avatar_match(DETAILED, DETAILED)


def test_near_identical_within_four_bits_match():
    assert avatar_match(DETAILED, "ffff00001111222f")   # 2 bits off


def test_five_bits_apart_is_not_a_match():
    other = "ffff00001111223d"   # 0x22 ^ 0x3d = 0x1f: exactly five bits flipped
    assert bin(int(DETAILED, 16) ^ int(other, 16)).count("1") == 5
    assert not avatar_match(DETAILED, other)


@pytest.mark.parametrize("sparse", [
    "0000a04b0ba00000",   # loco, 11 bits: matched monkeytype at distance 7 in a live scan
    "0000606868400000",   # netvibes, 9 bits
    "000094d4d4e40000",   # twitch.team, 15 bits: matched wikipedia at distance 8
])
def test_sparse_images_never_match_even_exactly(sparse):
    """Flat logos and placeholders collide across unrelated sites."""
    assert bin(int(sparse, 16)).count("1") < AVATAR_MIN_BITS
    assert not avatar_match(sparse, sparse)


def test_garbage_hashes_do_not_match():
    assert not avatar_match("zz", DETAILED)
    assert not avatar_match("", "")


# --- pair evidence -----------------------------------------------------------------


def test_same_service_is_never_evidence():
    """twitch and twitch.team share the site's own image, not yours."""
    a = acct("twitch", url="https://twitch.tv/arx", avatar_hash=DETAILED)
    b = acct("twitch.team", url="https://twitch.tv/team/arx", avatar_hash=DETAILED)
    assert pair_evidence(a, b) is None


def test_same_avatar_across_services():
    edge = pair_evidence(acct("github", avatar_hash=DETAILED), acct("devto", avatar_hash=DETAILED))
    assert edge.kind == "same_avatar"


def test_bio_link_in_either_direction():
    github = acct("github", url="https://github.com/arx")
    reddit = acct("reddit", url="https://reddit.com/u/arx", bio="code: https://github.com/arx.")
    assert pair_evidence(github, reddit).kind == "links_to"
    assert pair_evidence(reddit, github).kind == "links_to"


def test_mentioning_the_searched_handle_is_not_evidence():
    """The live bug: Twitter's 'latest posts from @arx' chained 227 profiles."""
    twitter = acct("twitter", bio="The latest posts from @arx")
    other = acct("github")
    assert pair_evidence(twitter, other) is None


def test_mention_across_different_handles_is_evidence():
    main = acct("github", handle="arx")
    alt = acct("reddit", handle="aaron.t", bio="main account is @arx")
    assert pair_evidence(main, alt).kind == "mentions"


def test_same_personal_name_is_evidence():
    edge = pair_evidence(acct("github", name="Aaron Thomas"), acct("gitlab", name="Aaron Thomas"))
    assert edge.kind == "same_name"


@pytest.mark.parametrize("name", [
    "Flickr", "Arx Corp Official", "arx",
    "Internal Server Error",      # error pages carry this as og:title
    "Interner Serverfehler",      # seen on a live scan
    "Page Not Found",
    "Access Denied",
    "Just A Moment",              # Cloudflare challenge
])
def test_brand_and_chrome_names_are_not_evidence(name):
    assert pair_evidence(acct("a", name=name), acct("b", name=name)) is None


# --- tracing -------------------------------------------------------------------------


def test_trace_follows_chains_and_records_how():
    github = acct("github", url="https://github.com/arx", avatar_hash=DETAILED)
    devto = acct("devto", avatar_hash=DETAILED)
    reddit = acct("reddit", url="https://reddit.com/u/arx", bio="https://devto.com/arx")
    reached = trace([github, devto, reddit], {github.key})
    assert reached[github.key] is None
    assert reached[devto.key].kind == "same_avatar"
    assert reached[reddit.key].kind == "links_to"


def test_trace_never_runs_through_a_rejected_account():
    github = acct("github", avatar_hash=DETAILED)
    middle = acct("devto", avatar_hash=DETAILED, url="https://devto.com/arx")
    far = acct("reddit", url="https://reddit.com/u/arx", bio="https://devto.com/arx")
    reached = trace([github, middle, far], {github.key}, rejected={middle.key})
    assert set(reached) == {github.key}


def test_trace_ignores_anchors_not_among_candidates():
    assert trace([acct("github")], {"arx:missing"}) == {}


def test_self_mention_star_does_not_form():
    """Regression for the 228-account result: one echoing page links nothing."""
    twitter = acct("twitter", bio="The latest posts from @arx")
    others = [acct(f"site{i}") for i in range(50)]
    reached = trace([twitter, *others], {others[0].key})
    assert set(reached) == {others[0].key}
