import json

import pytest

from whoseeme import cli, pipeline


@pytest.fixture
def offline(monkeypatch, report, correlation, remediation):
    """Headless audit with the network and dataset swapped for fixtures."""

    async def scan_handles(handles, sites=None, on_result=None):
        return {**report, "handles": handles}

    async def correlate(rep):
        return correlation

    monkeypatch.setattr(pipeline, "scan_handles", scan_handles)
    monkeypatch.setattr(pipeline, "correlate", correlate)
    monkeypatch.setattr(pipeline.RemediationIndex, "load", classmethod(lambda cls, path=None: remediation))
    monkeypatch.setattr("aliens_eye.api.load_sites", lambda exclude_nsfw=False: {"github": "x"})


async def run(argv, lines=None):
    lines = [] if lines is None else lines
    args = cli.build_parser().parse_args(argv)
    code = await cli.run_audit(args, out=lines.append)
    return code, lines


async def test_audit_writes_reports(offline, tmp_path):
    out_json, out_html = tmp_path / "r.json", tmp_path / "r.html"
    code, lines = await run(["audit", "arx", "--anchor", "https://github.com/arx",
                             "--json", str(out_json), "--html", str(out_html)])
    assert code == 0
    audit = json.loads(out_json.read_text("utf-8"))
    assert {a["site"] for a in audit["accounts"]} == {"github", "devto", "reddit"}
    assert "What a stranger could link to you" in out_html.read_text("utf-8")
    assert any("accounts traced to you" in line for line in lines)


async def test_unmatched_anchor_lists_what_was_found(offline):
    code, lines = await run(["audit", "arx", "--anchor", "https://nowhere.example/arx"])
    assert code == 2
    assert any("github.com/arx" in line for line in lines)


async def test_audit_needs_an_anchor():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["audit", "arx"])


async def test_short_handles_are_refused(offline):
    code, lines = await run(["audit", "a", "--anchor", "https://github.com/a"])
    assert code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "whoseeme" in capsys.readouterr().out


def test_no_command_starts_the_server(monkeypatch):
    called = {}

    async def fake_serve(port=0, open_browser=True):
        called.update(port=port, open_browser=open_browser)

    monkeypatch.setattr(cli.server, "serve", fake_serve)
    cli.main([])
    assert called == {"port": 0, "open_browser": True}


def test_serve_flags(monkeypatch):
    called = {}

    async def fake_serve(port=0, open_browser=True):
        called.update(port=port, open_browser=open_browser)

    monkeypatch.setattr(cli.server, "serve", fake_serve)
    cli.main(["serve", "--port", "8765", "--no-browser"])
    assert called == {"port": 8765, "open_browser": False}
