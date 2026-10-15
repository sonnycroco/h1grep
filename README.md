# h1grep [![PyPI Downloads](https://static.pepy.tech/personalized-badge/h1grep?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/h1grep)

Search HackerOne's disclosed reports from your terminal.

h1grep queries the public [Hacktivity](https://hackerone.com/hacktivity) feed
and lets you filter it by keyword, severity, CWE and program, or sort it by
votes or bounty. It's handy for checking what has already been reported
against a program, and for reading the reports that paid well or that other
hunters rated highly.

You don't need an API key or an account. It only reads public data, and it's
a single Python file with no dependencies.

![h1grep --top-voted --limit 3](https://raw.githubusercontent.com/sonnycroco/h1grep/main/assets/top-voted.png)

## Install

```bash
pip install h1grep
```

Or run it from a clone. There's nothing to install:

```bash
git clone https://github.com/sonnycroco/h1grep
cd h1grep
python3 h1grep.py --top-voted --limit 25
```

Needs Python 3.9 or newer.

## Examples

### Find reports on a bug class

Keyword, severity and CWE filters run on your machine after the results are
downloaded, so fetch a few pages when you filter. Here are the top-voted
critical and high SSRF reports from the first 250 results:

```bash
h1grep --top-voted --query "SSRF" --severity critical high --pages 5
```

![SSRF search](https://raw.githubusercontent.com/sonnycroco/h1grep/main/assets/ssrf-critical-high.png)

`--query` and `--cwe` take regular expressions, so `--query "OAuth|SAML"`
works.

### Look at one program

Use `--program` before you start on a target, to see what has already been
found and paid for there. Handles aren't case-sensitive.

```bash
h1grep --program gitlab --top-bounty --pages 4
```

![GitLab reports by bounty](https://raw.githubusercontent.com/sonnycroco/h1grep/main/assets/program-gitlab.png)

### Pipe it into other tools

`--json` prints the raw results as a JSON array, so you can process them with
`jq` or your own scripts:

```bash
h1grep --top-voted --query XSS --pages 5 -n 8 --json \
  | jq -r '.[] | [.votes, .team.handle, .report.title] | @tsv'
```

![JSON piped into jq](https://raw.githubusercontent.com/sonnycroco/h1grep/main/assets/json-jq.png)

### More

```bash
h1grep                                    # newest disclosures first
h1grep --top-bounty --limit 10            # biggest payouts
h1grep --top-voted --cwe "SSRF" "Request Forgery"
h1grep --lookup-program gitlab            # handle -> numeric team ID
```

## Options

| Flag | What it does |
|------|--------------|
| `-q`, `--query` | Regex matched against report titles |
| `-s`, `--severity` | Keep only these severities: `none low medium high critical` |
| `--cwe` | Regex(es) matched against the CWE name, e.g. `"SSRF" "Traversal"` |
| `-p`, `--program` | Only reports from this program handle, e.g. `shopify` |
| `--lookup-program` | Print a program's numeric team ID and exit |
| `--top-voted` | Sort by community votes |
| `--top-bounty` | Sort by bounty paid (can't be combined with `--top-voted`) |
| `-n`, `--limit` | How many results to print (default 20) |
| `--pages` | How many pages of 50 to fetch (default 1) |
| `--json` | Print JSON instead of text |

Without `--top-voted` or `--top-bounty` you get the newest disclosures first.

Colour is only used when printing to a terminal. Set `NO_COLOR` to turn it
off. Status messages go to stderr, so `--json` output is always valid JSON.

Exit codes: `0` on success, including when nothing matched. `1` for a network
or API error, or an unknown program. `2` for bad arguments or an unexpected
API response. `130` if interrupted.

## Things to know

**This uses an undocumented API.** h1grep calls the same GraphQL endpoint the
Hacktivity page uses. It's not an official API and HackerOne changes it
without notice. It has already broken program filtering once, when the
`team_id` field stopped being searchable. If the response stops looking the way
h1grep expects, it says so and exits instead of printing garbage. If you see
that, please [open an issue](https://github.com/sonnycroco/h1grep/issues).

**`--top-bounty` needs more pages.** Most of the highest-paid reports were
never made public. HackerOne still lists them with a bounty amount but no
report, and h1grep drops them. Often only 2 to 5 of the first 50 results
survive. The header tells you how many were dropped, so raise `--pages`.

**Ties can be skipped deep in sorted results.** HackerOne pages by position
and doesn't break ties. Far down a `--top-voted` or `--top-bounty` list, a
report with the same vote count or bounty as its neighbours can fall between
two pages. The order you see is still correct, and the top of the list isn't
affected. Reports that show up on more than one page are only printed once.

**It only sees public data.** Disclosed, resolved reports only. Nothing
private.

**Be gentle with it.** h1grep waits 0.3 seconds between pages and only reads.
Please don't turn it into a scraper.

## License

[Apache-2.0](LICENSE)
