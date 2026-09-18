"""HTML export: scraped text stays inert, nothing loads from the network."""

import json

from whoseeme import export, pipeline

HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>"\'&'


def audit_with(report, correlation, remediation, **overrides):
    audit = pipeline.build_audit(report, correlation, {"arx:github"}, remediation=remediation)
    audit.update(overrides)
    return audit


def test_hostile_strings_are_escaped_everywhere(report, correlation, remediation):
    report["variations"]["arx"]["sites"]["github"]["ai_analysis"]["signals"]["profile"]["name"] = HOSTILE
    audit = audit_with(report, correlation, remediation)
    audit["findings"].append({
        "kind": "x", "severity": "high", "accounts": [], "title": HOSTILE,
        "evidence": HOSTILE, "advice": HOSTILE,
    })
    audit["handles"] = [HOSTILE]
    html = export.render_html(audit)
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_non_http_links_are_not_clickable(report, correlation, remediation):
    audit = audit_with(report, correlation, remediation)
    audit["accounts"][0]["url"] = "javascript:alert(1)"
    html = export.render_html(audit)
    assert 'href="javascript' not in html


def test_csp_blocks_scripts_and_remote_loads(report, correlation, remediation):
    html = export.render_html(audit_with(report, correlation, remediation))
    assert "default-src 'none'" in html
    assert "script-src" not in html  # nothing is allowed beyond default-src 'none'
    assert '<meta name="referrer" content="no-referrer">' in html
    assert "<img" not in html


def test_external_links_do_not_leak_referrers(report, correlation, remediation):
    html = export.render_html(audit_with(report, correlation, remediation))
    assert 'rel="noopener noreferrer"' in html


def test_json_export_round_trips(report, correlation, remediation):
    audit = audit_with(report, correlation, remediation)
    assert json.loads(export.render_json(audit)) == json.loads(json.dumps(audit))
