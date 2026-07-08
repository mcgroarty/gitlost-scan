# gitlost-scan

`gitlost-scan.py` is a read-only GitHub organization scanner for GitLost-style
susceptibility. It focuses on the narrow chain where attacker-controlled public
GitHub text, such as issues or comments, can reach an AI or coding-agent
workflow that may have access to private repositories and can publish output
back to a public or external location.

This is not a general GitHub security checkup. Some adjacent findings are still
reported because they help explain blast radius, but the primary result to
triage is the `gitlost-susceptibility` category.

## Background

For the vulnerability pattern this tool is built around, see Noma Security's
GitLost write-up: <https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/>.

## Requirements

- GitHub CLI: `gh`
- An authenticated GitHub CLI session: `gh auth login`
- Organization owner/admin access for best coverage
- Optional: PyYAML for more reliable workflow parsing

## Usage

Run the scan against one organization:

```bash
python3 gitlost-scan.py --org YOUR_ORG --out /private/tmp/gitlost-audit.csv
```

Useful options:

```bash
python3 gitlost-scan.py --org YOUR_ORG --include-archived
python3 gitlost-scan.py --org YOUR_ORG --include-private
python3 gitlost-scan.py --org YOUR_ORG --enterprise YOUR_ENTERPRISE
python3 gitlost-scan.py --org YOUR_ORG --out gitlost-audit.csv
```

By default, the scanner inventories all visible repositories for context but
only deep-scans public repositories. Use `--include-private` to also deep-scan
private and internal repositories.

The script prints a summary to stdout and writes detailed findings to CSV.
Generated GitLost CSV reports are ignored by this repository's `.gitignore`
because they may contain private repository names, secret names, workflow paths,
and other sensitive metadata.

## Interpreting Results

The CSV includes an `assessment_scope` column:

- `gitlost`: direct GitLost-chain evidence.
- `gitlost-context`: settings that affect exploitability or blast radius.
- `general-hygiene`: adjacent security posture findings.
- `coverage`: scan coverage or permissions limitations.

- `gitlost-susceptibility`: correlated GitLost-style exposure chain or partial
  chain. Start here.
- `workflow-output-sink`: a workflow can publish data to comments, artifacts,
  logs, summaries, or external endpoints.
- `agent-workflow`: workflow content appears to invoke or configure an AI or
  coding-agent system.
- `workflow-trigger`: workflow uses triggers that can involve untrusted public
  user-controlled text.

Some Copilot or cloud-agent settings are not available cleanly through public
REST APIs. Treat the script's manual-check list as part of the assessment.
