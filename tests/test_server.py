"""Local server: the guards that stop other web pages driving it, and the flow."""

import asyncio
import json

import pytest
from aiohttp import ClientSession
from aiohttp.test_utils import TestServer

from whoseeme import server

TOKEN = "test-token-123"


def parse_sse(text):
    events = []
    for block in text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "event" in lines:
            events.append((lines["event"], json.loads(lines["data"])))
    return events


class Harness:
    def __init__(self, srv, session):
        self.srv = srv
        self.session = session
        self.base = f"http://127.0.0.1:{srv.port}"

    def request(self, method, path, token=TOKEN, headers=None, **kw):
        headers = dict(headers or {})
        if token is not None:
            headers[server.TOKEN_HEADER] = token
        return self.session.request(method, self.base + path, headers=headers, **kw)


@pytest.fixture
def fakes(report, correlation):
    state = {"scans": 0, "correlations": 0, "load_sites_calls": [], "fail": False, "gate": None}

    def load_sites(exclude_nsfw=False):
        state["load_sites_calls"].append(exclude_nsfw)
        return {site: f"https://{site}.example/{{}}" for site in report["variations"]["arx"]["sites"]}

    async def scan_handles(handles, sites=None, on_result=None):
        state["scans"] += 1
        if state["gate"] is not None:
            await state["gate"].wait()
        if state["fail"]:
            raise RuntimeError("network down")
        for site, info in report["variations"]["arx"]["sites"].items():
            await on_result("arx", {"site": site, **info})
        return {**report, "handles": handles}

    async def correlate(rep):
        state["correlations"] += 1
        return correlation

    state.update(load_sites=load_sites, scan_handles=scan_handles, correlate=correlate)
    return state


@pytest.fixture
async def harness(fakes, remediation):
    app = server.create_app(
        TOKEN, set(),
        scan_handles=fakes["scan_handles"],
        correlate=fakes["correlate"],
        load_sites=fakes["load_sites"],
        remediation=remediation,
    )
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    app[server.HOSTS_KEY].update(server.loopback_hosts(srv.port))
    async with ClientSession() as session:
        yield Harness(srv, session)
    await srv.close()


async def run_scan(h, body=None):
    async with h.request("POST", "/api/scan", json=body or {"handles": "arx"}) as resp:
        assert resp.status == 200, await resp.text()
        job = await resp.json()
    async with h.request("GET", f"/api/scan/{job['job_id']}/events") as resp:
        events = parse_sse(await resp.text())
    return job, events


# --- guards ---------------------------------------------------------------------


async def test_api_rejects_a_missing_token(harness):
    async with harness.request("POST", "/api/scan", token=None, json={"handles": "arx"}) as resp:
        assert resp.status == 403


async def test_api_rejects_a_wrong_token(harness):
    async with harness.request("POST", "/api/scan", token="guess", json={"handles": "arx"}) as resp:
        assert resp.status == 403


async def test_token_in_query_string_is_accepted(harness):
    """EventSource and download links can't set headers, so ?token= must work."""
    async with harness.request("POST", f"/api/scan?token={TOKEN}", token=None,
                               json={"handles": "arx"}) as resp:
        assert resp.status == 200


@pytest.mark.parametrize("path", ["/", "/api/scan", "/static/app.js"])
async def test_foreign_host_header_is_refused(harness, path):
    """DNS rebinding: a hostile domain pointed at 127.0.0.1 arrives with its own Host."""
    method = "POST" if path == "/api/scan" else "GET"
    async with harness.request(method, path, headers={"Host": "evil.example"},
                               json={"handles": "arx"} if method == "POST" else None) as resp:
        assert resp.status == 403


async def test_other_loopback_ports_are_refused(harness):
    async with harness.request("GET", "/", headers={"Host": "127.0.0.1:1"}) as resp:
        assert resp.status == 403


async def test_security_headers_on_every_response(harness):
    for path, token in (("/", None), ("/static/app.js", None), ("/api/scan", "wrong")):
        method = "POST" if path.startswith("/api") else "GET"
        async with harness.request(method, path, token=token) as resp:
            assert resp.headers["Referrer-Policy"] == "no-referrer"
            assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
            assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
            assert resp.headers["X-Frame-Options"] == "DENY"
            assert resp.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("name", ["../server.py", "__init__.py", "index.html", "nope.js"])
async def test_static_serves_only_the_allowlist(harness, name):
    async with harness.request("GET", f"/static/{name}", token=None) as resp:
        assert resp.status == 404


# --- flow -------------------------------------------------------------------------


async def test_full_flow_scan_events_report_download(harness, fakes):
    job, events = await run_scan(harness)
    names = [name for name, _ in events]
    assert names[-1] == "done"
    assert "progress" in names and "hit" in names
    hits = dict(events)["done"]["hits"]
    assert {h["site"] for h in hits} == {"github", "devto", "reddit", "gitlab", "tumblr"}

    body = {"job_id": job["job_id"], "anchors": ["arx:github"], "rejected": ["arx:gitlab"]}
    async with harness.request("POST", "/api/report", json=body) as resp:
        assert resp.status == 200
        audit = await resp.json()
    assert {a["key"] for a in audit["accounts"]} == {"arx:github", "arx:devto", "arx:reddit"}
    assert "arx:gitlab" not in {r["key"] for r in audit["unconfirmed"]}

    for fmt, content_type in (("html", "text/html"), ("json", "application/json")):
        async with harness.request("GET", f"/api/report/{job['job_id']}.{fmt}") as resp:
            assert resp.status == 200
            assert resp.content_type == content_type
            assert "attachment" in resp.headers["Content-Disposition"]


async def test_progress_counts_reach_the_total(harness):
    job, events = await run_scan(harness)
    last = [data for name, data in events if name == "progress"][-1]
    assert last["done"] == last["total"] == job["total"]


async def test_events_replay_for_a_late_or_reconnecting_client(harness):
    job, first = await run_scan(harness)
    async with harness.request("GET", f"/api/scan/{job['job_id']}/events") as resp:
        again = parse_sse(await resp.text())
    assert again == first


async def test_correlation_runs_once_per_scan(harness, fakes):
    job, _ = await run_scan(harness)
    body = {"job_id": job["job_id"], "anchors": ["arx:github"]}
    for _ in range(3):
        async with harness.request("POST", "/api/report", json=body) as resp:
            assert resp.status == 200
    assert fakes["correlations"] == 1


async def test_report_requires_an_anchor(harness):
    job, _ = await run_scan(harness)
    async with harness.request("POST", "/api/report", json={"job_id": job["job_id"], "anchors": []}) as resp:
        assert resp.status == 400


async def test_anchor_keys_not_in_the_results_are_ignored(harness):
    job, _ = await run_scan(harness)
    body = {"job_id": job["job_id"], "anchors": ["arx:made-up"]}
    async with harness.request("POST", "/api/report", json=body) as resp:
        assert resp.status == 400


async def test_unknown_job_is_404(harness):
    async with harness.request("POST", "/api/report", json={"job_id": "nope", "anchors": ["x"]}) as resp:
        assert resp.status == 404
    async with harness.request("GET", "/api/scan/nope/events") as resp:
        assert resp.status == 404


async def test_download_before_report_is_409(harness):
    job, _ = await run_scan(harness)
    async with harness.request("GET", f"/api/report/{job['job_id']}.html") as resp:
        assert resp.status == 409


async def test_only_one_scan_at_a_time(harness, fakes):
    fakes["gate"] = asyncio.Event()
    async with harness.request("POST", "/api/scan", json={"handles": "arx"}) as resp:
        assert resp.status == 200
    async with harness.request("POST", "/api/scan", json={"handles": "arx"}) as resp:
        assert resp.status == 409
    fakes["gate"].set()


async def test_report_before_scan_finishes_is_409(harness, fakes):
    fakes["gate"] = asyncio.Event()
    async with harness.request("POST", "/api/scan", json={"handles": "arx"}) as resp:
        job = await resp.json()
    async with harness.request("POST", "/api/report",
                               json={"job_id": job["job_id"], "anchors": ["arx:github"]}) as resp:
        assert resp.status == 409
    fakes["gate"].set()


@pytest.mark.parametrize("body", [{"handles": ""}, {"handles": "a"}, {"handles": []}, {}])
async def test_scan_needs_a_usable_handle(harness, body):
    async with harness.request("POST", "/api/scan", json=body) as resp:
        assert resp.status == 400


async def test_malformed_json_is_400(harness):
    async with harness.request("POST", "/api/scan", data="{not json",
                               headers={"Content-Type": "application/json"}) as resp:
        assert resp.status == 400


async def test_adult_sites_are_opt_out(harness, fakes):
    await run_scan(harness, {"handles": "arx"})
    await run_scan(harness, {"handles": "arx", "include_adult": False})
    assert fakes["load_sites_calls"] == [False, True]


async def test_a_failed_scan_reports_an_error_event(harness, fakes):
    fakes["fail"] = True
    _, events = await run_scan(harness)
    assert events[-1][0] == "error"
    assert "network down" in events[-1][1]["message"]


async def test_oversized_bodies_are_rejected(harness):
    async with harness.request("POST", "/api/scan", data="x" * (200 * 1024),
                               headers={"Content-Type": "application/json"}) as resp:
        assert resp.status == 413
