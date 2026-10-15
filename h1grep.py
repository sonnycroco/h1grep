#!/usr/bin/env python3
"""
h1grep — grep for disclosed HackerOne reports

Queries HackerOne's public Hacktivity GraphQL API for disclosed reports and
surfaces relevant findings during recon. No API key required. Read-only.
Max 50 results/page.

Usage examples:
  # Top voted reports (best validated techniques — great starting point)
  h1grep --top-voted --limit 25

  # Highest bounty reports (signal for business-impact framing)
  h1grep --top-bounty --limit 10

  # Keyword search in titles across multiple pages
  h1grep --query "SSRF" --pages 10
  h1grep --top-voted --query "OAuth|SAML" --pages 5

  # Filter by severity (client-side)
  h1grep --top-voted --severity critical high --limit 20

  # Filter by CWE (client-side, matches CWE label substring)
  h1grep --top-voted --cwe "SSRF" "Request Forgery"

  # Program-specific disclosures
  h1grep --program shopify --pages 3

  # Lookup a program's numeric team ID
  h1grep --lookup-program gitlab

  # Full combo: top-bounty SSRF reports, critical/high only
  h1grep --top-bounty --query "SSRF" --severity critical high --pages 10

  # JSON output for piping
  h1grep --top-voted --query "XSS" --pages 5 --json

(When running from source without installing, replace `h1grep` with
`python3 h1grep.py`.)
"""

import argparse
import json
import os
import sys
import re
import time
import urllib.request
import urllib.error
from typing import NoReturn, Optional

__version__ = "0.2.1"

GRAPHQL_URL = "https://hackerone.com/graphql"
ISSUES_URL = "https://github.com/sonnycroco/h1grep/issues"
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Origin": "https://hackerone.com",
    "Referer": "https://hackerone.com/hacktivity",
}
PAGE_SIZE = 50

# HackerOne's GraphQL server crashes on named variables + substate filter + report fields.
# We build inline query strings to avoid this. Additional known crashes:
#   - disclosed_at field with substate filter
#   - sort + substate filter + report fields
REPORT_FIELDS = """... on HacktivityDocument {
  id
  severity_rating
  total_awarded_amount
  currency
  cwe
  cve_ids
  votes
  team { handle name }
  reporter { username }
  report { _id title url }
}"""

TEAM_LOOKUP_QUERY = """
query TeamLookup($handle: String!) {
  team(handle: $handle) {
    id
    _id
    handle
    name
    url
  }
}
"""


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value) -> str:
    """Strip control characters from API text before it reaches the terminal.
    Report titles are written by reporters, so an embedded escape sequence
    could otherwise recolour, hide, or rewrite what the user sees."""
    return _CONTROL_CHARS.sub("", str(value))


def die_shape_changed(context: str = "") -> NoReturn:
    """The endpoint returned HTTP 200 but the JSON did not match the expected
    schema. This is the drift signal: HackerOne's undocumented API changed
    shape. Fail with a friendly, actionable message instead of a stack trace."""
    where = f" ({context})" if context else ""
    print(
        f"[!] HackerOne API shape changed{where} — the response did not match the "
        "expected schema.\n"
        "    This usually means HackerOne updated their (undocumented) GraphQL API.\n"
        f"    Please open an issue so it can be fixed: {ISSUES_URL}",
        file=sys.stderr,
    )
    sys.exit(2)


def _post(body: dict) -> dict:
    payload = json.dumps(body).encode()
    req = urllib.request.Request(GRAPHQL_URL, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")
        print(f"[!] HTTP {e.code}: {_clean(body_text[:300])}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # 200 OK but not JSON (e.g. an HTML error/challenge page) — schema drift.
        die_shape_changed("non-JSON response")


def gql_raw(query: str) -> dict:
    return _post({"query": query})


def gql_vars(query: str, variables: dict) -> dict:
    return _post({"query": query, "variables": variables})


def lookup_program(handle: str, status_to_stderr: bool = False) -> Optional[str]:
    """Resolve a program handle, print its numeric id, and return the canonical
    handle (None if the program does not exist or is private).

    The id line is the output of --lookup-program but only a status message
    for --program, where it goes to stderr so --json stays parseable."""
    data = gql_vars(TEAM_LOOKUP_QUERY, {"handle": handle})
    team = (data.get("data") or {}).get("team")
    if not team and handle != handle.lower():
        # The lookup is case-sensitive and handles are lowercase, so retry
        # rather than reject "GitLab".
        data = gql_vars(TEAM_LOOKUP_QUERY, {"handle": handle.lower()})
        team = (data.get("data") or {}).get("team")
    if not team:
        print(f"[!] Program '{handle}' not found or is private", file=sys.stderr)
        return None
    team_id = team.get("_id")
    if team_id is None:
        die_shape_changed("team lookup")
    try:
        team_id = int(team_id)
    except (TypeError, ValueError):
        # Team ids have always been numeric; anything else means the team
        # schema changed shape.
        die_shape_changed(f"team lookup: non-numeric team id {team_id!r}")
    canonical = team.get("handle") or handle
    print(
        f"[+] {_clean(canonical)} → id={team_id}, name={_clean(team.get('name', '?'))}",
        file=sys.stderr if status_to_stderr else sys.stdout,
    )
    return canonical


def build_page_query(args, after: Optional[str] = None) -> str:
    """
    Build an inline GraphQL query for one page of results.

    Historical H1 crash rules (discovered empirically; none reproduce as of
    2026-07-31, and every mode now combines the substate filter with a sort):
    - substate filter + sort + report fields  → CRASH
    - disclosed_at field + substate filter    → CRASH
    - named variables + substate filter + report fields → CRASH

    Program filtering goes through query_string on team_handle. The
    structured team_id filter was tightened to [Int!] and then made
    unsearchable outright (2026-10). The handle must be quoted: an unquoted
    hyphenated handle is tokenized and matches other programs too
    (nodejs-ecosystem also pulls in nodejs).

    A sort is always sent. Cursors are plain offsets with no tiebreaker, and
    without a sort the order shifts between requests, so pages overlap and
    reports get skipped (a full shopify walk: 613 rows, ~520-550 unique).
    disclosed_at DESC (newest first) pages stably.
    """
    has_sort = args.top_voted or args.top_bounty
    has_program = bool(args.program_handle)

    after_str = f', after: "{_escape(after)}"' if after else ""
    if args.top_voted:
        sort_field = "votes"
    elif args.top_bounty:
        sort_field = "total_awarded_amount"
    else:
        sort_field = "disclosed_at"
    sort_str = f', sort: {{field: "{sort_field}", direction: DESC}}'

    if has_sort and not has_program:
        # Sort-only mode: no substate filter
        query_str = "query: {bool: {}}"
    else:
        query_str = 'query: {bool: {filter: [{terms: {substate: ["resolved"]}}]}}'

    if has_program:
        qs = f'team_handle:"{_escape(args.program_handle)}" AND disclosed:true'
        query_str += f', query_string: "{_escape(qs)}"'

    return (
        f'{{ search(index: CompleteHacktivityReportIndex, {query_str}, '
        f'first: {PAGE_SIZE}{after_str}{sort_str}) '
        f'{{ total_count pageInfo {{ endCursor }} nodes {{ {REPORT_FIELDS} }} }} }}'
    )


def fetch_all_pages(args) -> tuple[list[dict], bool]:
    """Fetch up to args.pages pages from the H1 GraphQL API.

    Returns (nodes, had_error). A GraphQL error stops paging but keeps whatever
    earlier pages returned; the flag lets the caller exit non-zero so a broken
    query is never mistaken for an empty result set.

    Nodes already seen on an earlier page are dropped: offset paging over
    rows tied on the sort value (equal bounties, equal votes) can return the
    same report twice.
    """
    all_nodes: list[dict] = []
    seen: set = set()
    cursor = None
    had_error = False

    for page_num in range(1, args.pages + 1):
        if page_num > 1:
            time.sleep(0.3)  # polite rate limiting

        query = build_page_query(args, after=cursor)
        data = gql_raw(query)

        if "errors" in data or data.get("data") is None:
            for err in (data.get("errors") or []):
                print(f"[!] GraphQL error (page {page_num}): {_clean(err.get('message'))}", file=sys.stderr)
            had_error = True
            break

        search = data["data"].get("search") if isinstance(data.get("data"), dict) else None
        if not isinstance(search, dict):
            die_shape_changed(f"page {page_num}: missing 'search'")
        nodes = search.get("nodes", [])
        if not isinstance(nodes, list) or not all(isinstance(n, dict) for n in nodes):
            die_shape_changed(f"page {page_num}: 'nodes' not a list of objects")
        for n in nodes:
            key = n.get("id") or (n.get("report") or {}).get("_id")
            if key is not None:
                if key in seen:
                    continue
                seen.add(key)
            all_nodes.append(n)
        page_info = search.get("pageInfo")
        cursor = page_info.get("endCursor") if isinstance(page_info, dict) else None

        if not nodes or not cursor:
            break

        # Stop early if we already have enough matches (when keyword filtering)
        if not args.query and not args.severity and not args.cwe:
            matching = len([n for n in all_nodes if n.get("report")])
            if matching >= args.limit:
                break

    return all_nodes, had_error


def apply_client_filters(nodes: list[dict], args) -> list[dict]:
    keyword_pattern = re.compile(args.query, re.IGNORECASE) if args.query else None
    severity_set = set(s.lower() for s in args.severity) if args.severity else None
    cwe_patterns = [re.compile(c, re.IGNORECASE) for c in args.cwe] if args.cwe else []

    results = []
    for node in nodes:
        report = node.get("report")
        if not report:
            continue

        title = report.get("title", "")

        if keyword_pattern and not keyword_pattern.search(title):
            continue

        if severity_set:
            node_sev = (node.get("severity_rating") or "none").lower()
            if node_sev not in severity_set:
                continue

        if cwe_patterns:
            node_cwe = node.get("cwe") or ""
            if not any(p.search(node_cwe) for p in cwe_patterns):
                continue

        results.append(node)

    return results


def _use_color() -> bool:
    """Colour only on a terminal, and never when NO_COLOR is set (no-color.org)."""
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def format_severity(s: Optional[str]) -> str:
    if not s:
        return "none"
    s = _clean(s)
    if not _use_color():
        return s.upper()
    colors = {
        "critical": "\033[91m",
        "high": "\033[33m",
        "medium": "\033[93m",
        "low": "\033[32m",
        "none": "\033[37m",
    }
    reset = "\033[0m"
    c = colors.get(s.lower(), "")
    return f"{c}{s.upper()}{reset}"


def _undisclosed_note(undisclosed: int, total_fetched: int) -> str:
    """Explain rows dropped for having no public report body. These dominate
    bounty-sorted pages, where most high-payout entries are still undisclosed."""
    return (
        f" {undisclosed} of {total_fetched} fetched are undisclosed "
        f"(bounty data only, no public report) — widen --pages for more"
    )


def print_results(results: list[dict], total_fetched: int, args, undisclosed: int = 0):
    if not results:
        print("[*] No matching results found.")
        if undisclosed:
            print(f"   {_undisclosed_note(undisclosed, total_fetched).strip()}")
        return

    print(f"\n{'='*72}")
    label_parts = []
    if args.top_voted:
        label_parts.append("top voted")
    if args.top_bounty:
        label_parts.append("top bounty")
    if args.query:
        label_parts.append(f'keyword="{args.query}"')
    if args.severity:
        label_parts.append(f"severity={','.join(args.severity)}")
    if args.program:
        label_parts.append(f"program={_clean(args.program_handle or args.program)}")
    label = " | ".join(label_parts) if label_parts else "all disclosed"
    print(f" h1grep — {label}")

    total_matches = len(results)
    shown = min(total_matches, args.limit)
    matches = "match" if total_matches == 1 else "matches"
    if shown < total_matches:
        print(
            f" showing {shown} of {total_matches} {matches} from "
            f"{total_fetched} fetched reports — raise with --limit/-n"
        )
    else:
        print(f" {total_matches} {matches} from {total_fetched} fetched reports")
    if undisclosed:
        print(_undisclosed_note(undisclosed, total_fetched))
    print(f"{'='*72}\n")

    for i, node in enumerate(results[: args.limit], 1):
        report = node.get("report", {}) or {}
        team = node.get("team", {}) or {}
        reporter = node.get("reporter", {}) or {}

        title = _clean(report.get("title", "Unknown"))
        url = _clean(report.get("url", ""))
        severity = format_severity(node.get("severity_rating"))
        cwe = _clean(node.get("cwe") or "")
        cves = _clean(", ".join(map(str, node.get("cve_ids") or [])))
        bounty = node.get("total_awarded_amount")
        currency = _clean(node.get("currency") or "USD")
        votes = _clean(node.get("votes") or 0)
        program = _clean(team.get("handle", "?"))
        reporter_name = _clean(reporter.get("username", "?"))

        bounty_str = (f"${bounty:,} {currency}" if isinstance(bounty, (int, float)) and bounty
                      else "no bounty")

        print(f"[{i:02d}] {title}")
        print(f"     Severity : {severity}  |  CWE: {cwe or 'n/a'}")
        print(f"     Program  : {program}  |  Reporter: {reporter_name}")
        if cves:
            print(f"     CVE      : {cves}")
        print(f"     Bounty   : {bounty_str}  |  Votes: {votes}")
        print(f"     URL      : {url}")
        print()


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
    return n


def main():
    """Console entry point: exit quietly on Ctrl-C or a closed pipe
    (`h1grep ... | head`) instead of dumping a traceback."""
    try:
        _main()
        sys.stdout.flush()
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # Point stdout at devnull so the interpreter's final flush can't raise again.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)


def _main():
    # Report titles are arbitrary Unicode; never crash on a terminal or
    # redirect whose encoding can't represent them.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(
        description="h1grep — grep disclosed HackerOne reports for recon and research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--query", "-q", help="Keyword regex to match in report titles (client-side)")
    parser.add_argument(
        "--severity", "-s",
        nargs="+",
        choices=["none", "low", "medium", "high", "critical"],
        metavar="LEVEL",
        help="Client-side severity filter: none low medium high critical",
    )
    parser.add_argument(
        "--cwe",
        nargs="+",
        metavar="PATTERN",
        help="Client-side CWE label filter (regex, e.g. 'SSRF' 'Traversal')",
    )
    parser.add_argument("--program", "-p", metavar="HANDLE", help="Filter by program handle")
    parser.add_argument("--lookup-program", metavar="HANDLE", help="Resolve a program handle to its numeric ID and exit")
    sort_group = parser.add_mutually_exclusive_group()
    sort_group.add_argument("--top-voted", action="store_true", help="Sort by community votes (validated techniques)")
    sort_group.add_argument("--top-bounty", action="store_true", help="Sort by bounty amount (impact framing reference)")
    parser.add_argument("--limit", "-n", type=_positive_int, default=20, help="Max results to display (default: 20)")
    parser.add_argument(
        "--pages",
        type=_positive_int,
        default=1,
        help="Number of pages to fetch (50 results/page, default: 1). Use 5-20 for keyword searches.",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted text")

    args = parser.parse_args()

    for flag, value in (("--program", args.program), ("--lookup-program", args.lookup_program)):
        if value is not None and not value.strip():
            parser.error(f"argument {flag}: handle must not be empty")

    # Validate regexes before spending any requests.
    for flag, patterns in (("--query", [args.query] if args.query else []), ("--cwe", args.cwe or [])):
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                parser.error(f"argument {flag}: invalid regex {pattern!r}: {e}")

    if args.lookup_program:
        if lookup_program(args.lookup_program.strip()) is None:
            sys.exit(1)
        return

    args.program_handle = None
    if args.program:
        args.program_handle = lookup_program(args.program.strip(), status_to_stderr=True)
        if args.program_handle is None:
            sys.exit(1)

    nodes, had_error = fetch_all_pages(args)
    results = apply_client_filters(nodes, args)
    undisclosed = sum(1 for n in nodes if not n.get("report"))

    if args.json:
        print(json.dumps(results[: args.limit], indent=2))
    else:
        print_results(results, len(nodes), args, undisclosed)

    if had_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
