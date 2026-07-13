# h1grep

**grep for disclosed HackerOne reports.** A zero-dependency CLI that searches
HackerOne's public [Hacktivity](https://hackerone.com/hacktivity) feed of
*disclosed, resolved* vulnerability reports — by keyword, severity, CWE, program,
top votes, or top bounty — and prints structured results for recon and research.

No API key. No account. Read-only. Standard-library Python only.

```
$ h1grep --top-voted --limit 3

========================================================================
 h1grep — top voted
 50 matches from 50 fetched reports
========================================================================

[01] Takeover an account that doesn't have a Shopify ID and more
     Severity : CRITICAL  |  CWE: n/a
     Program  : shopify  |  Reporter: imgnotfound
     Bounty   : no bounty  |  Votes: 2990
     URL      : https://hackerone.com/reports/867513
```

## Why

It isn't "another recon script." The value is the **reverse-engineered GraphQL
knowledge** baked in. HackerOne's public GraphQL endpoint crashes on several
otherwise-natural query shapes (substate filter + sort + report fields;
`disclosed_at` + substate; named variables + substate + report fields). `h1grep`
encodes empirically-discovered crash-avoidance rules so that searching disclosed
reports from the terminal *just works*.
Studying disclosed reports is one of the highest-signal ways to learn validated
techniques: what got voted up by the community, what paid out, and how impact was
framed for a specific program.

## Install

```bash
pip install h1grep
```

Or run straight from source (nothing to install — it's stdlib-only):

```bash
git clone https://github.com/sonnycroco/h1grep
cd h1grep
python3 h1grep.py --top-voted --limit 25
```

Requires **Python 3.9+**.

## Usage

```bash
# Top-voted reports — best validated techniques, great starting point
h1grep --top-voted --limit 25

# Highest-bounty reports — signal for business-impact framing
h1grep --top-bounty --limit 10

# Keyword search in report titles across multiple pages
h1grep --query "SSRF" --pages 10
h1grep --query "OAuth bypass" --pages 5

# Filter by severity (client-side)
h1grep --top-voted --severity critical high --limit 20

# Filter by CWE label (client-side regex)
h1grep --top-voted --cwe "SSRF" "Request Forgery"

# Program-specific disclosures
h1grep --program shopify --pages 3

# Resolve a program handle to its numeric team ID
h1grep --lookup-program gitlab

# Full combo: top-bounty SSRF reports, critical/high only
h1grep --top-bounty --query "SSRF" --severity critical high --pages 10

# JSON output for piping into jq, etc.
h1grep --top-voted --query "XSS" --pages 5 --json
```

### Options

| Flag | Description |
|------|-------------|
| `--query`, `-q` | Keyword regex matched against report titles (client-side) |
| `--severity`, `-s` | Filter by severity: `none low medium high critical` (client-side) |
| `--cwe` | Filter by CWE label regex, e.g. `"SSRF" "Traversal"` (client-side) |
| `--program`, `-p` | Filter by program handle (e.g. `shopify`) |
| `--lookup-program` | Resolve a program handle to its numeric team ID and exit |
| `--top-voted` | Sort by community votes (validated techniques) |
| `--top-bounty` | Sort by bounty amount (impact framing) |
| `--limit`, `-n` | Max results to display (default: 20) |
| `--pages` | Pages to fetch, 50 results/page (default: 1; use 5–20 for keyword searches) |
| `--json` | Emit raw JSON instead of formatted text |

Keyword, severity, and CWE filtering are applied **client-side** after fetching,
so widen `--pages` when you filter aggressively.

## How it works

1. **Query building** — inline GraphQL strings are assembled per mode to route
   around the endpoint's crash triggers. Pure sort (no program) uses server-side
   sorting; program filtering uses a substate/team filter with no server-side
   sort, then sorts client-side.
2. **Pagination** — walks pages of 50 using base64 offset cursors, sleeping
   0.3s between pages (polite rate limiting), up to `--pages`.
3. **Client-side filter & sort** — keyword/severity/CWE and the fallback sort
   are applied locally.
4. **Output** — color-coded text by default, or `--json`.

## Caveats

- **Undocumented endpoint.** `h1grep` uses the same public GraphQL endpoint the
  Hacktivity web UI calls. It is not an official API and may change without
  notice. When the response shape changes, `h1grep` fails with a clear
  *"HackerOne API shape changed — please open an issue"* message rather than a
  stack trace — please do [open an issue](https://github.com/sonnycroco/h1grep/issues)
  if you hit it.
- **Disclosed reports only.** It can only see what HackerOne has publicly
  disclosed — never private program data.
- **Read-only and rate-limited by design.** It fetches and prints; it does not
  write, submit, or scrape aggressively. Please keep it that way and be a good
  citizen of the endpoint.

## License

[Apache-2.0](LICENSE)
