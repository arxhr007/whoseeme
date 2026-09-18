"""The "is this me?" flow: only what links back to your confirmed accounts counts."""

from whoseeme import pipeline


def test_candidate_handles_dedupes_and_validates():
    assert pipeline.candidate_handles(["arx", "ARX", " arx ", "a", ""]) == ["arx"]


def test_candidate_handles_mines_an_email():
    handles = pipeline.candidate_handles(["arx"], "john.doe@example.com")
    assert handles[0] == "arx"
    assert "john.doe" in handles and "johndoe" in handles


def test_candidate_handles_caps_the_count():
    assert len(pipeline.candidate_handles([f"user{i}" for i in range(20)])) == pipeline.MAX_HANDLES


def test_hits_lists_found_before_maybe_and_skips_misses(report):
    rows = pipeline.hits(report)
    statuses = [r["status"] for r in rows]
    assert "Not Found" not in statuses
    assert statuses == sorted(statuses, key=["Found", "Maybe"].index)


def test_hits_drop_title_fallback_names(report):
    """tumblr's 'name' is page chrome (name_from_profile False) and must not show."""
    tumblr = next(r for r in pipeline.hits(report) if r["site"] == "tumblr")
    assert tumblr["name"] == ""


def test_anchor_urls_match_loosely(report):
    keys, unmatched = pipeline.resolve_anchor_urls(
        report, ["http://www.GitHub.com/arx/", "https://nope.example/arx"]
    )
    assert keys == {"arx:github"}
    assert unmatched == ["https://nope.example/arx"]


def test_nothing_links_from_a_strangers_account(report, correlation, remediation):
    """Anchoring on an account with no evidence edges traces only that account."""
    audit = pipeline.build_audit(report, correlation, {"arx:gitlab"}, remediation=remediation)
    assert [a["key"] for a in audit["accounts"]] == ["arx:gitlab"]


def test_each_linked_account_says_how_it_was_reached(report, correlation, remediation):
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    by_site = {a["site"]: a for a in audit["accounts"]}
    assert by_site["github"]["linked_via"] is None
    assert by_site["devto"]["linked_via"]["kind"] == "same_avatar"
    assert by_site["reddit"]["linked_via"]["kind"] == "links_to"
    assert by_site["reddit"]["linked_via"]["from_site"] == "github"


def test_cluster_membership_alone_does_not_link(report, remediation):
    """aliens-eye clusters are a looser hint; without evidence nothing is traced."""
    correlation = {"avatar_hashing": True, "profiles": [], "clusters": [
        {"size": 2, "reasons": ["bio"], "members": [
            {"variation": "arx", "site": "github", "avatar_hash": None},
            {"variation": "arx", "site": "gitlab", "avatar_hash": None},
        ]},
    ]}
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    assert "arx:gitlab" not in {a["key"] for a in audit["accounts"]}


def test_hashes_come_from_all_profiles_not_just_clusters(report, remediation):
    correlation = {"avatar_hashing": True, "clusters": [], "profiles": [
        {"variation": "arx", "site": "github", "avatar_hash": "ffff000011112222"},
        {"variation": "arx", "site": "devto", "avatar_hash": "ffff000011112222"},
    ]}
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    assert "arx:devto" in {a["key"] for a in audit["accounts"]}


def test_maybe_hits_are_never_pulled_in_by_evidence(report, correlation, remediation):
    """Maybe is mostly bot walls; only the user can vouch for one."""
    site = report["variations"]["arx"]["sites"]["tumblr"]
    site["ai_analysis"]["signals"]["profile"]["bio"] = "https://github.com/arx"
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    assert "arx:tumblr" not in {a["key"] for a in audit["accounts"]}


def test_a_maybe_anchor_is_honoured(report, correlation, remediation):
    audit = pipeline.build_audit(report, correlation, {"arx:tumblr"}, remediation=remediation)
    assert "arx:tumblr" in {a["key"] for a in audit["accounts"]}


def test_audit_traces_linked_accounts_and_keeps_strangers_out(report, correlation, remediation):
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    keys = {a["key"] for a in audit["accounts"]}
    assert keys == {"arx:github", "arx:devto", "arx:reddit"}
    assert {r["site"] for r in audit["unconfirmed"]} == {"gitlab", "tumblr"}
    assert audit["summary"]["confirmed"] == 1
    assert audit["summary"]["linked_by_evidence"] == 2


def test_strangers_contribute_no_findings(report, correlation, remediation):
    """gitlab's 'Arx Corp Official' must not become 'your name', nor any finding."""
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    for finding in audit["findings"]:
        assert "arx:gitlab" not in finding["accounts"]
        assert "arx:tumblr" not in finding["accounts"]


def test_rejection_beats_evidence(report, correlation, remediation):
    """The user knows their accounts better than a heuristic does."""
    audit = pipeline.build_audit(
        report, correlation, {"arx:github"}, rejected={"arx:reddit"}, remediation=remediation
    )
    keys = {a["key"] for a in audit["accounts"]}
    assert "arx:reddit" not in keys
    assert "arx:reddit" not in {r["key"] for r in audit["unconfirmed"]}


def test_rejecting_an_anchor_removes_it(report, correlation, remediation):
    audit = pipeline.build_audit(
        report, correlation, {"arx:github"}, rejected={"arx:github"}, remediation=remediation
    )
    assert audit["accounts"] == []


def test_audit_expected_findings(report, correlation, remediation):
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    kinds = {f["kind"] for f in audit["findings"]}
    assert {"contact_in_bio", "avatar_reuse", "real_name", "cross_link", "handle_reuse"} <= kinds


def test_audit_attaches_deletion_guidance(report, correlation, remediation):
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    by_site = {a["site"]: a for a in audit["accounts"]}
    assert by_site["github"]["remediation"]["service"] == "GitHub"
    assert by_site["devto"]["remediation"] is None  # not in the fixture index


def test_account_rows_point_at_their_findings(report, correlation, remediation):
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    github = next(a for a in audit["accounts"] if a["site"] == "github")
    for index in github["findings"]:
        assert "arx:github" in audit["findings"][index]["accounts"]


def test_without_avatar_hashes_other_evidence_still_links(report, remediation):
    """No Pillow / no hashes: the picture link is gone, but devto still shares the
    name "Aaron Thomas" and reddit's bio still links to the GitHub profile."""
    audit = pipeline.build_audit(report, {"clusters": [], "avatar_hashing": False},
                                 {"arx:github"}, remediation=remediation)
    by_site = {a["site"]: a for a in audit["accounts"]}
    assert set(by_site) == {"github", "devto", "reddit"}
    assert by_site["devto"]["linked_via"]["kind"] == "same_name"
    assert by_site["reddit"]["linked_via"]["kind"] == "links_to"
    assert audit["summary"]["avatar_matching"] is False


async def test_scan_handles_merges_reports(monkeypatch):
    calls = []

    async def fake_scan(handle, **kwargs):
        calls.append(handle)
        return {"variations": {handle: {"sites": {}}}}

    monkeypatch.setattr(pipeline.api, "scan", fake_scan)
    merged = await pipeline.scan_handles(["arx", "aaron.t"], sites={})
    assert calls == ["arx", "aaron.t"]
    assert set(merged["variations"]) == {"arx", "aaron.t"}
    assert merged["handles"] == ["arx", "aaron.t"]


async def test_correlate_keeps_private_avatars_blocked(monkeypatch):
    seen = {}

    async def fake_correlate(report, **kwargs):
        seen.update(kwargs)
        return {"clusters": []}

    monkeypatch.setattr(pipeline.api, "correlate", fake_correlate)
    await pipeline.correlate({"variations": {}})
    assert seen.get("allow_private_avatars", False) is False
