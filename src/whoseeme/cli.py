"""Command line.

    whoseeme                      open the app in your browser
    whoseeme audit HANDLE ... --anchor URL [--anchor URL] [--json F] [--html F]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Callable
from pathlib import Path

from . import __version__, export, pipeline, server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whoseeme",
        description="See what a stranger could link to you. Runs entirely on your computer.",
    )
    parser.add_argument("--version", action="version", version=f"whoseeme {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="open the app in your browser (the default)")
    serve.add_argument("--port", type=int, default=0, help="port to listen on (default: any free port)")
    serve.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")

    audit = sub.add_parser("audit", help="run an audit without the browser")
    audit.add_argument("handles", nargs="+", help="your usernames")
    audit.add_argument(
        "--anchor", action="append", required=True, metavar="URL",
        help="a profile URL you know is yours; repeat for several",
    )
    audit.add_argument("--email", help="also try usernames derived from this address (never sent anywhere)")
    audit.add_argument("--no-adult", action="store_true", help="skip adult sites")
    audit.add_argument("--json", type=Path, metavar="FILE", help="write the audit as JSON")
    audit.add_argument("--html", type=Path, metavar="FILE", help="write the audit as an HTML report")
    return parser


async def run_audit(args: argparse.Namespace, out: Callable[[str], None] = print) -> int:
    from aliens_eye import api

    handles = pipeline.candidate_handles(args.handles, args.email)
    if not handles:
        out("No usable usernames: each needs at least 2 characters.")
        return 2
    sites = api.load_sites(exclude_nsfw=args.no_adult)
    out(f"Checking {len(sites)} sites for {', '.join(handles)}. This takes a minute or two.")

    report = await pipeline.scan_handles(handles, sites=sites)
    anchors, unmatched = pipeline.resolve_anchor_urls(report, args.anchor)
    for url in unmatched:
        out(f"  not among the results, ignored: {url}")
    if not anchors:
        found = pipeline.hits(report)
        out("None of the --anchor URLs matched an account that was found.")
        if found:
            out("Accounts found (pass one of these as --anchor):")
            for row in found[:25]:
                out(f"  {row['url']}")
        return 2

    audit = pipeline.build_audit(report, await pipeline.correlate(report), anchors)
    summary = audit["summary"]
    sev = summary["findings"]
    out("")
    out(f"{summary['accounts']} accounts traced to you "
        f"({summary['confirmed']} confirmed, {summary['linked_by_evidence']} linked to them).")
    out(f"Findings: {sev['high']} high, {sev['medium']} medium, {sev['low']} low.")
    for finding in audit["findings"]:
        out(f"  [{finding['severity'].upper():6}] {finding['title']}")
    if summary["unconfirmed"]:
        out(f"{summary['unconfirmed']} more accounts share your username but aren't linked to you.")

    if args.json:
        args.json.write_text(export.render_json(audit), encoding="utf-8")
        out(f"Wrote {args.json}")
    if args.html:
        args.html.write_text(export.render_html(audit), encoding="utf-8")
        out(f"Wrote {args.html}")
    return 0


def main(argv: list[str] | None = None) -> None:
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
            except (AttributeError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "audit":
            sys.exit(asyncio.run(run_audit(args)))
        asyncio.run(server.serve(
            port=getattr(args, "port", 0),
            open_browser=not getattr(args, "no_browser", False),
        ))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
