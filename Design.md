# Design

## Purpose

This tool assesses susceptibility to GitLost-style exposure, not overall GitHub
security posture. The scanner is meant to answer a focused question:

Can attacker-controlled public GitHub text reach an AI or coding-agent path that
may have access to private repositories and can publish output to a public or
external destination?

## Provenance

This tool and its documentation were created with substantial assistance from
LLMs, including ChatGPT and Claude. Keep that provenance visible in developer
documentation so maintenance history is honest about AI-generated work. It
feels like the right thing to do.

## Background Reference

The detection model is based on Noma Security's GitLost write-up:
<https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/>.

## GitLost Model

The scanner models GitLost as a chain with four parts:

1. A public repository accepts untrusted user-controlled text through issues,
   issue comments, discussions, pull requests, or related events.
2. A workflow, agent configuration, or coding-assistant integration may consume
   that text as instructions or context.
3. The agent may be able to read private repositories in the same organization
   or enterprise.
4. The workflow or agent can publish output to a public or external sink, such
   as an issue comment, PR comment, artifact, Actions log, step summary, or
   webhook.

The script can detect parts 1, 2, and 4 from repository content and Actions
metadata. Part 3 usually requires manual review of Copilot or agent platform
settings, so the script reports visible private repository count as blast-radius
context and marks exact private repository reachability as a manual check.

## Scanner Flow

1. Use `gh api` to read organization Actions settings, organization Actions
   secrets, and repository inventory.
2. For each repository, read Actions settings, default branch protection,
   rulesets, agent-related files, and workflow files.
3. Parse workflow YAML with PyYAML when available. Fall back to regex matching
   when PyYAML is missing or parsing fails.
4. Extract workflow signals:
   - untrusted public triggers
   - risky triggers
   - AI or coding-agent indicators
   - explicit and write-like token permissions
   - public conversation write permissions
   - output sinks
5. Emit individual findings for useful raw signals.
6. Emit a correlated `gitlost-susceptibility` finding when the repo-level
   evidence forms a GitLost-style chain or partial chain.

## Output Sinks

`workflow-output-sink` findings currently cover:

- `gh issue comment` and `gh pr comment`
- GitHub API issue or PR comment writes
- `actions/github-script` comment or review writes
- common third-party comment actions
- `actions/upload-artifact`
- GitHub step summaries or log-style output from event/comment bodies
- HTTP/webhook-style egress
- token permissions that allow writing to issues, pull requests, or discussions

These are indicators, not proof of exploitability. Review the surrounding
workflow logic before deciding whether a sink can carry agent output.

## Finding Categories

- `gitlost-susceptibility`: correlated public-input to agent/output chain.
- `workflow-output-sink`: workflow can publish to public or external locations.
- `agent-workflow`: workflow appears to invoke or configure an AI/agentic tool.
- `workflow-trigger`: workflow uses risky untrusted-input triggers.
- `workflow-permissions`: workflow token permissions are missing or broad.
- `agent-config`: repository contains files commonly used by coding agents.
- Other existing categories are adjacent hygiene signals and should not be
  treated as substitutes for the GitLost-specific findings.

## Safety

The script is intended to be read-only. It calls `gh api`, reads repository
metadata and file contents, prints a summary, and writes a local CSV.

The CSV can contain sensitive metadata, including private repository names,
secret names, workflow paths, and inferred exposure details. Prefer writing
reports outside the repository, for example `/private/tmp/gitlost-audit.csv`.
The repository `.gitignore` ignores common GitLost CSV report names as a safety
net.

## Developer Documentation

The README is for scanner operators. This design document is for maintainers,
including AI agents and human developers. Keep both files in sync, but put
implementation rationale, assumptions, and future-work notes here rather than in
the README.

Update this file and, when operator behavior changes, `README.md` whenever you
change:

- CLI flags or default behavior
- finding categories, severities, or evidence format
- CSV columns
- workflow parsing behavior
- GitLost correlation logic
- output sink or agent detection patterns
- known limitations or manual-check requirements

## TODO

- Move adjacent general hygiene checks, such as branch protection, secret
  scanning, Advanced Security, and broad Actions policy, behind an
  `--include-general-hygiene` flag.
- Improve agent detection by parsing workflow steps, `uses`, `run`, `env`,
  markdown agent workflows, Copilot setup files, MCP configs, and repository
  instructions more deliberately instead of relying mostly on keyword scanning.
- Make report handling safer by default: warn when `--out` points inside the
  repository, optionally redact organization secret names, and add a
  `--summary-only` mode.
- Add coverage/status output showing which API checks failed, which settings
  require manual review, and whether the GitHub token had enough permissions for
  meaningful results.
- Add synthetic tests for GitLost-like and non-GitLost-like workflows so the
  scanner stays focused on susceptibility rather than drifting into general
  security linting.
