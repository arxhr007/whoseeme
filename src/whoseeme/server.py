"""Local web app: the audit runs on your machine, in your browser.

Security model. A server on localhost that can launch scans is reachable by any
web page the user visits: a page can fire requests at 127.0.0.1, and with DNS
rebinding it can even read the responses. So:

* It binds to 127.0.0.1 only, never a public interface.
* Requests whose ``Host`` header isn't this server's own loopback address are
  refused. That defeats DNS rebinding, where a hostile domain is re-pointed at
  127.0.0.1 so the browser treats it as same-origin.
* Every ``/api`` call must carry a random token minted at startup and handed to
  the browser in the URL it opens (the same approach Jupyter uses). A page that
  merely guesses the port cannot drive a scan without it.
* ``Referrer-Policy: no-referrer`` on everything, so the token in the address bar
  never leaks to a site the user clicks through to.
* A strict Content-Security-Policy: scripts only from this server, no remote
  images at all. Scraped bios are attacker-controlled; the page renders them with
  textContent, and the CSP is the backstop if that ever slips.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from aiohttp import web

from . import export, pipeline
from .remediation import RemediationIndex

TOKEN_HEADER = "X-Whoseeme-Token"
MAX_JOBS = 8

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

JOBS_KEY = web.AppKey("jobs", OrderedDict)
TOKEN_KEY = web.AppKey("token", str)
HOSTS_KEY = web.AppKey("allowed_hosts", set)
DEPS_KEY = web.AppKey("deps", dict)


@dataclass
class Job:
    id: str
    handles: list[str]
    total: int
    done: int = 0
    found: int = 0
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    finished: bool = False
    report: dict[str, Any] | None = None
    correlation: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None
    changed: asyncio.Condition = field(default_factory=asyncio.Condition)
    correlate_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    task: asyncio.Task | None = None

    async def emit(self, name: str, data: dict[str, Any], final: bool = False) -> None:
        async with self.changed:
            self.events.append((name, data))
            if final:
                self.finished = True
            self.changed.notify_all()


# --- guards -------------------------------------------------------------------


@web.middleware
async def host_guard(request: web.Request, handler):
    if request.host not in request.app[HOSTS_KEY]:
        raise web.HTTPForbidden(text="forbidden host")
    return await handler(request)


@web.middleware
async def token_guard(request: web.Request, handler):
    if request.path.startswith("/api/"):
        presented = request.headers.get(TOKEN_HEADER) or request.query.get("token") or ""
        if not hmac.compare_digest(presented.encode(), request.app[TOKEN_KEY].encode()):
            raise web.HTTPForbidden(text="missing or invalid token")
    return await handler(request)


async def _security_headers(request: web.Request, response: web.StreamResponse) -> None:
    # A prepare hook rather than middleware: it also covers the streamed SSE
    # response and the error responses the guards raise.
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)


# --- handlers -----------------------------------------------------------------


def _static(name: str) -> bytes:
    return (resources.files("whoseeme.static") / name).read_bytes()


_CONTENT_TYPES = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}


async def index(request: web.Request) -> web.Response:
    return web.Response(body=_static("index.html"), content_type="text/html", charset="utf-8")


async def static_file(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    suffix = name[name.rfind("."):] if "." in name else ""
    if name not in {"app.js", "style.css"} or suffix not in _CONTENT_TYPES:
        raise web.HTTPNotFound()
    return web.Response(body=_static(name), content_type=_CONTENT_TYPES[suffix], charset="utf-8")


def _job(request: web.Request) -> Job:
    job = request.app[JOBS_KEY].get(request.match_info["job_id"])
    if job is None:
        raise web.HTTPNotFound(text="unknown scan")
    return job


async def _body(request: web.Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise web.HTTPBadRequest(text="expected a JSON body") from None
    if not isinstance(data, dict):
        raise web.HTTPBadRequest(text="expected a JSON object")
    return data


async def start_scan(request: web.Request) -> web.Response:
    data = await _body(request)
    jobs: OrderedDict[str, Job] = request.app[JOBS_KEY]
    if any(not job.finished for job in jobs.values()):
        # One scan at a time: several at once would hammer every site in the
        # catalogue in parallel from the user's own connection.
        raise web.HTTPConflict(text="a scan is already running")

    raw = data.get("handles") or []
    if isinstance(raw, str):
        raw = raw.replace(",", " ").split()
    handles = pipeline.candidate_handles([str(h) for h in raw], str(data.get("email") or ""))
    if not handles:
        raise web.HTTPBadRequest(text="enter at least one handle of 2 or more characters")

    deps = request.app[DEPS_KEY]
    sites = deps["load_sites"](exclude_nsfw=not bool(data.get("include_adult", True)))
    job = Job(id=uuid.uuid4().hex, handles=handles, total=len(sites) * len(handles))

    while len(jobs) >= MAX_JOBS:
        jobs.popitem(last=False)
    jobs[job.id] = job
    job.task = asyncio.create_task(_run_scan(job, sites, deps["scan_handles"]))
    return web.json_response({"job_id": job.id, "handles": handles, "total": job.total})


async def _run_scan(job: Job, sites: dict[str, str], scan_handles: Callable) -> None:
    async def on_result(handle: str, result: dict[str, Any]) -> None:
        job.done += 1
        status = result.get("status")
        if status in pipeline.HIT_STATUSES:
            job.found += 1
            await job.emit("hit", {"site": result.get("site"), "handle": handle, "status": status})
        await job.emit("progress", {"done": job.done, "total": job.total, "found": job.found})

    try:
        job.report = await scan_handles(job.handles, sites=sites, on_result=on_result)
        await job.emit("done", {"hits": pipeline.hits(job.report)}, final=True)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI instead of crashing the server
        await job.emit("error", {"message": f"Scan failed: {exc}"}, final=True)


async def scan_events(request: web.Request) -> web.StreamResponse:
    """Server-sent events. Replays from the start, so a reconnect loses nothing."""
    job = _job(request)
    response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
    await response.prepare(request)
    sent = 0
    try:
        while True:
            async with job.changed:
                await job.changed.wait_for(
                    lambda sent=sent: len(job.events) > sent or job.finished
                )
                pending = job.events[sent:]
                finished = job.finished
            for name, data in pending:
                await response.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            sent += len(pending)
            if finished and sent >= len(job.events):
                break
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return response


async def build_report(request: web.Request) -> web.Response:
    data = await _body(request)
    job = request.app[JOBS_KEY].get(str(data.get("job_id", "")))
    if job is None:
        raise web.HTTPNotFound(text="unknown scan")
    if job.report is None:
        raise web.HTTPConflict(text="the scan hasn't finished")

    valid = {row["key"] for row in pipeline.hits(job.report)}
    anchors = {str(k) for k in data.get("anchors") or []} & valid
    rejected = {str(k) for k in data.get("rejected") or []} & valid
    if not anchors:
        raise web.HTTPBadRequest(text="mark at least one account as yours")

    deps = request.app[DEPS_KEY]
    async with job.correlate_lock:  # correlation downloads avatars; do it once per scan
        if job.correlation is None:
            job.correlation = await deps["correlate"](job.report)
    job.audit = pipeline.build_audit(
        job.report, job.correlation, anchors, rejected, remediation=deps["remediation"]
    )
    return web.json_response(job.audit)


async def download(request: web.Request) -> web.Response:
    job = _job(request)
    if job.audit is None:
        raise web.HTTPConflict(text="build the report first")
    fmt = request.match_info["fmt"]
    body = export.render_html(job.audit) if fmt == "html" else export.render_json(job.audit)
    return web.Response(
        text=body,
        content_type="text/html" if fmt == "html" else "application/json",
        charset="utf-8",
        headers={"Content-Disposition": f'attachment; filename="whoseeme-report.{fmt}"'},
    )


# --- app ----------------------------------------------------------------------


def create_app(
    token: str,
    allowed_hosts: set[str],
    *,
    scan_handles: Callable = pipeline.scan_handles,
    correlate: Callable = pipeline.correlate,
    load_sites: Callable | None = None,
    remediation: RemediationIndex | None = None,
) -> web.Application:
    """Build the app. The scanning dependencies are injectable for tests."""
    if load_sites is None:
        from aliens_eye import api

        load_sites = api.load_sites

    app = web.Application(middlewares=[host_guard, token_guard], client_max_size=64 * 1024)
    app[TOKEN_KEY] = token
    app[HOSTS_KEY] = allowed_hosts
    app[JOBS_KEY] = OrderedDict()
    app[DEPS_KEY] = {
        "scan_handles": scan_handles,
        "correlate": correlate,
        "load_sites": load_sites,
        "remediation": remediation or RemediationIndex.load(),
    }
    app.on_response_prepare.append(_security_headers)
    app.router.add_get("/", index)
    app.router.add_get("/static/{name}", static_file)
    app.router.add_post("/api/scan", start_scan)
    app.router.add_get("/api/scan/{job_id}/events", scan_events)
    app.router.add_post("/api/report", build_report)
    app.router.add_get(r"/api/report/{job_id}.{fmt:(html|json)}", download)
    return app


def loopback_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}"}


async def serve(port: int = 0, open_browser: bool = True, print_fn: Callable = print) -> None:
    """Run until interrupted. ``port=0`` picks a free port."""
    import webbrowser

    token = secrets.token_urlsafe(24)
    app = create_app(token, set())
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    bound = runner.addresses[0][1]
    app[HOSTS_KEY].update(loopback_hosts(bound))

    url = f"http://127.0.0.1:{bound}/?token={token}"
    print_fn(f"whoseeme is running at {url}")
    print_fn("Everything runs on this computer. Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
