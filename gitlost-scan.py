#!/usr/bin/env python3
"""
github-gitlost-audit.py

Read-only GitHub org audit for GitLost-style exposure risks.

Requires:
  - gh CLI installed
  - gh auth login
  - org owner/admin permissions for best coverage

Example:
  python3 github-gitlost-audit.py --org my-org --enterprise my-enterprise
  python3 github-gitlost-audit.py --org my-org --include-archived
  python3 github-gitlost-audit.py --org my-org --include-private
  python3 github-gitlost-audit.py --org my-org --out gitlost-audit.csv

Notes:
  - This does not modify GitHub settings.
  - It intentionally uses gh api rather than a Python GitHub library.
  - Prefers PyYAML for workflow parsing; falls back to regex when unavailable.
"""

import argparse
import base64
import csv
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml  # type: ignore
    HAVE_YAML = True
except ImportError:
    yaml = None  # type: ignore[assignment]
    HAVE_YAML = False


RISKY_TRIGGERS = {
    "pull_request_target",
    "issue_comment",
    "issues",
    "workflow_run",
    "discussion",
    "discussion_comment",
    "pull_request_review",
}

# GitLost is a chain, not a single bad setting: public attacker-controlled
# text has to reach an agent or workflow that can publish output somewhere.
UNTRUSTED_PUBLIC_TRIGGERS = {
    "issues",
    "issue_comment",
    "discussion",
    "discussion_comment",
    "pull_request",
    "pull_request_review",
    "pull_request_target",
}

PUBLIC_OUTPUT_PERMISSION_SCOPES = {
    "issues",
    "pull-requests",
    "discussions",
}

AGENTISH_PATTERNS = [
    r"\bcopilot\b",
    r"\bopenai\b",
    r"\banthropic\b",
    r"\bclaude\b",
    r"\bcodex\b",
    r"\bdevin\b",
    r"\bai[-_ ]?agent(s|ic)?\b",
    r"\bcoding[-_ ]?agent\b",
    r"\bmcp[-_ ]?server\b",
    r"\bactions/ai-inference\b",
    r"\bgh[-_]aw\b",
]

AGENT_CONFIG_PATHS = [
    "AGENTS.md",
    ".github/copilot-instructions.md",
    ".github/instructions",
    ".github/prompts",
    ".github/workflows/copilot-setup-steps.yml",
    ".github/workflows/copilot-setup-steps.yaml",
    ".devin",
    ".cursor",
    ".windsurf",
    ".mcp.json",
]

OUTPUT_SINK_PATTERNS = [
    (
        "GitHub issue/PR comment command",
        r"\bgh\s+(?:issue|pr)\s+comment\b",
    ),
    (
        "GitHub API comment write",
        r"\b(?:gh\s+api|curl)\b[^\n]*(?:/issues/[^\s\"']+/comments|/pulls/[^\s\"']+/comments)",
    ),
    (
        "github-script comment/review write",
        r"(?:actions/github-script@|github\.rest\.(?:issues|pulls)\.(?:createComment|createReview|createReviewComment)|github\.(?:issues|pulls)\.(?:createComment|createReview|createReviewComment))",
    ),
    (
        "third-party comment action",
        r"(?:peter-evans/create-or-update-comment|thollander/actions-comment-pull-request|marocchino/sticky-pull-request-comment|mshick/add-pr-comment|github-comment|comment-pull-request)",
    ),
    (
        "Actions artifact upload",
        r"\bactions/upload-artifact@",
    ),
    (
        "GitHub step summary or log output",
        r"\b(?:echo|printf|cat|tee)\b[^\n]*(?:GITHUB_STEP_SUMMARY|github\.event|issue\.body|comment\.body|steps\.)",
    ),
    (
        "webhook or HTTP egress",
        r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|httpie|xh)\b[^\n]*(?:https?://|\$[A-Z0-9_]*(?:WEBHOOK|URL))",
    ),
]


@dataclass
class Finding:
    """One CSV row describing a risk signal or coverage limitation."""

    repo: str
    visibility: str
    archived: bool
    category: str
    severity: str
    finding: str
    evidence: str
    suggested_action: str


@dataclass
class WorkflowSignals:
    """Normalized workflow traits used for individual and correlated findings."""

    triggers: List[str]
    risky_triggers: List[str]
    untrusted_public_triggers: List[str]
    agentish: bool
    has_explicit_permissions: bool
    dangerous_permissions: bool
    public_write_permissions: List[str]
    output_sinks: List[str]


def gh_api(endpoint: str, paginate: bool = False, tolerate_404: bool = True) -> Optional[Any]:
    """Call `gh api` and normalize common empty, denied, and paginated responses."""

    cmd = [
        "gh",
        "api",
        "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
    ]

    if paginate:
        cmd += ["--paginate", "--slurp"]

    cmd.append(endpoint)

    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if proc.returncode != 0:
        err = proc.stderr.strip()
        # Missing features, disabled products, or insufficient repository access
        # often show up as 404/403. Keep scanning and surface coverage gaps.
        if tolerate_404 and ("HTTP 404" in err or "Not Found" in err):
            return None
        if tolerate_404 and ("HTTP 403" in err or "Forbidden" in err):
            return {"__error__": err}
        print(f"[WARN] gh api failed for {endpoint}: {err}", file=sys.stderr)
        return None

    if not proc.stdout.strip():
        return None

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"[WARN] Could not parse JSON for {endpoint}", file=sys.stderr)
        return None

    if paginate:
        # gh api --paginate --slurp returns a list of page payloads.
        flattened = []
        if isinstance(data, list):
            for page in data:
                if isinstance(page, list):
                    flattened.extend(page)
                elif isinstance(page, dict) and "repositories" in page:
                    flattened.extend(page["repositories"])
                elif isinstance(page, dict) and "secrets" in page:
                    flattened.extend(page["secrets"])
                else:
                    flattened.append(page)
        return flattened

    return data


def get_org_repos(org: str) -> List[Dict[str, Any]]:
    """Return all visible repositories so public scan scope can still know private blast radius."""

    repos = gh_api(f"/orgs/{org}/repos?type=all&per_page=100", paginate=True)
    if not isinstance(repos, list):
        return []
    return repos


def get_org_actions_settings(org: str) -> Dict[str, Any]:
    """Read organization-level Actions policy and token defaults."""

    out = {}
    # These org settings can make otherwise safe-looking repo workflows risky:
    # broad action usage, write-default GITHUB_TOKENs, and allowed third-party actions.
    for name, endpoint in [
        ("actions_permissions", f"/orgs/{org}/actions/permissions"),
        ("workflow_permissions", f"/orgs/{org}/actions/permissions/workflow"),
        ("selected_actions", f"/orgs/{org}/actions/permissions/selected-actions"),
    ]:
        out[name] = gh_api(endpoint)
    return out


def get_org_actions_secrets(org: str) -> List[Dict[str, Any]]:
    """List organization Actions secrets and their repository visibility policy."""

    data = gh_api(f"/orgs/{org}/actions/secrets?per_page=100", paginate=True)
    if isinstance(data, list):
        return [s for s in data if isinstance(s, dict) and "name" in s]
    if isinstance(data, dict) and isinstance(data.get("secrets"), list):
        return data["secrets"]
    return []


def get_repo_full(owner: str, repo: str) -> Optional[Dict[str, Any]]:
    """Fetch detailed repository metadata that is absent from org repo listings."""

    return gh_api(f"/repos/{owner}/{repo}")


def get_repo_actions(owner: str, repo: str) -> Dict[str, Any]:
    """Read repository-level Actions policy, token defaults, and fork PR settings."""

    out = {}
    # Fork PR settings are mostly adjacent to GitLost, but they show whether
    # untrusted contributors can receive write tokens or secrets in Actions.
    for name, endpoint in [
        ("actions_permissions", f"/repos/{owner}/{repo}/actions/permissions"),
        ("workflow_permissions", f"/repos/{owner}/{repo}/actions/permissions/workflow"),
        ("selected_actions", f"/repos/{owner}/{repo}/actions/permissions/selected-actions"),
        ("fork_pr", f"/repos/{owner}/{repo}/actions/permissions/fork-pr"),
    ]:
        out[name] = gh_api(endpoint)
    return out


def get_branch_protection(owner: str, repo: str, branch: str) -> Optional[Dict[str, Any]]:
    """Fetch classic branch protection for the default branch when visible."""

    return gh_api(f"/repos/{owner}/{repo}/branches/{branch}/protection")


def get_repo_rulesets(owner: str, repo: str) -> Optional[List[Dict[str, Any]]]:
    """Fetch newer GitHub repository rulesets that may replace branch protection."""

    data = gh_api(f"/repos/{owner}/{repo}/rulesets?per_page=100", paginate=True)
    if isinstance(data, list):
        return data
    return None


def list_workflow_files(owner: str, repo: str, ref: str) -> List[Dict[str, Any]]:
    """List workflow-like files on the default branch without cloning the repo."""

    tree = get_repo_tree(owner, repo, ref)
    out: List[Dict[str, Any]] = []
    for path in sorted(tree):
        if not path.startswith(".github/workflows/"):
            continue
        if not path.lower().endswith((".yml", ".yaml", ".md")):
            continue
        out.append({"path": path, "name": path.rsplit("/", 1)[-1]})
    return out


def read_file_content(owner: str, repo: str, path: str, ref: str) -> Optional[str]:
    """Read and decode a repository file from the GitHub contents or blob API."""

    data = gh_api(f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
    if not isinstance(data, dict):
        return None
    content = data.get("content")
    encoding = data.get("encoding")
    if encoding == "base64" and content:
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return None
    # Files >1 MB: contents API returns no body. Fall back to git blobs.
    sha = data.get("sha")
    if sha:
        blob = gh_api(f"/repos/{owner}/{repo}/git/blobs/{sha}")
        if isinstance(blob, dict) and blob.get("encoding") == "base64" and blob.get("content"):
            try:
                return base64.b64decode(blob["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
    return None


_tree_cache: Dict[str, Set[str]] = {}


def get_repo_tree(owner: str, repo: str, ref: str) -> Set[str]:
    """Return a cached recursive file path set for one repo/ref."""

    key = f"{owner}/{repo}@{ref}"
    if key in _tree_cache:
        return _tree_cache[key]
    data = gh_api(f"/repos/{owner}/{repo}/git/trees/{ref}?recursive=1")
    paths: Set[str] = set()
    if isinstance(data, dict) and isinstance(data.get("tree"), list):
        for entry in data["tree"]:
            p = entry.get("path")
            if p:
                paths.add(p)
    _tree_cache[key] = paths
    return paths


def path_exists(owner: str, repo: str, path: str, ref: str) -> bool:
    """Check whether a file or directory exists in the cached repository tree."""

    tree = get_repo_tree(owner, repo, ref)
    if not tree:
        return False
    if path in tree:
        return True
    prefix = path.rstrip("/") + "/"
    return any(p.startswith(prefix) for p in tree)


def _extract_yaml_body(path: str, text: str) -> Optional[str]:
    """Return the YAML portion of a workflow file.

    For .yml/.yaml the whole file is YAML. For .md (gh-aw agentic workflows)
    the YAML lives in `---`-fenced frontmatter at the top.
    """
    if path.lower().endswith(".md"):
        m = re.match(r"\s*---\s*\n(.*?)\n---\s*(?:\n|$)", text, re.S)
        return m.group(1) if m else None
    return text


def _parse_yaml(text: str) -> Optional[Dict[str, Any]]:
    """Parse YAML into a dict, returning None when PyYAML is unavailable or fails."""

    if not HAVE_YAML or yaml is None:
        return None
    try:
        parsed = yaml.safe_load(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_triggers(parsed: Dict[str, Any]) -> List[str]:
    """Return workflow event names from the GitHub Actions `on` key."""

    # YAML 1.1 parses the bare key `on` as boolean True.
    if "on" in parsed:
        on = parsed["on"]
    elif True in parsed:  # type: ignore[operator]
        on = parsed[True]  # type: ignore[index]
    else:
        return []
    if on is None:
        return []
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(x) for x in on if isinstance(x, (str, int))]
    if isinstance(on, dict):
        return [str(k) for k in on.keys()]
    return []


def _collect_permissions(parsed: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Collect top-level and job-level GitHub Actions permission declarations."""

    out: List[Tuple[str, str]] = []

    def add(scope: str, value: Any) -> None:
        """Append either shorthand or per-scope permissions to the flat output."""

        if isinstance(value, str):
            out.append((scope, value))
        elif isinstance(value, dict):
            for k, v in value.items():
                out.append((f"{scope}.{k}", str(v)))

    if "permissions" in parsed:
        add("top", parsed.get("permissions"))
    jobs = parsed.get("jobs")
    if isinstance(jobs, dict):
        for jname, jdef in jobs.items():
            if isinstance(jdef, dict) and "permissions" in jdef:
                add(f"jobs.{jname}", jdef.get("permissions"))
    return out


def _permission_key(scope: str) -> str:
    """Extract the final permission name from a flattened permission scope."""

    if scope == "top":
        return "*"
    return scope.rsplit(".", 1)[-1]


def _is_write_like(value: str) -> bool:
    """Return True for permission values that can mutate GitHub or cloud state."""

    return value.lower() in ("write", "admin", "write-all")


def _collect_public_write_permissions(perms: List[Tuple[str, str]]) -> List[str]:
    """Find write permissions for GitHub surfaces that can expose public output."""

    out: List[str] = []
    for scope, value in perms:
        if not _is_write_like(value):
            continue
        key = _permission_key(scope)
        if key in PUBLIC_OUTPUT_PERMISSION_SCOPES or value.lower() == "write-all":
            out.append(f"{scope}={value}")
    return sorted(set(out))


def _fallback_triggers(yaml_body: str) -> List[str]:
    """Best-effort event extraction when PyYAML is missing or parsing fails."""

    # Keep fallback parsing deliberately simple: when YAML parsing fails, we only
    # need enough signal to avoid missing obvious event names.
    trigger_names = sorted(RISKY_TRIGGERS | UNTRUSTED_PUBLIC_TRIGGERS)
    found: Set[str] = set()
    lines = yaml_body.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)on\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if not m:
            continue
        indent = len(m.group(1))
        rest = m.group(2)
        if rest:
            for trigger in trigger_names:
                if re.search(rf"\b{re.escape(trigger)}\b", rest):
                    found.add(trigger)
            continue
        for nested in lines[i + 1:]:
            if not nested.strip() or nested.lstrip().startswith("#"):
                continue
            nested_indent = len(nested) - len(nested.lstrip())
            if nested_indent <= indent:
                break
            for trigger in trigger_names:
                if re.match(rf"^\s*(?:-\s*)?{re.escape(trigger)}\s*(?::|$)", nested):
                    found.add(trigger)
    return sorted(found)


def _fallback_permissions(yaml_body: str) -> List[Tuple[str, str]]:
    """Best-effort permission extraction scoped to actual `permissions` blocks."""

    perms: List[Tuple[str, str]] = []
    lines = yaml_body.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)permissions\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if not m:
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        if rest:
            perms.append(("permissions", rest))
            continue
        for nested in lines[i + 1:]:
            if not nested.strip() or nested.lstrip().startswith("#"):
                continue
            nested_indent = len(nested) - len(nested.lstrip())
            if nested_indent <= indent:
                break
            nested_match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*:\s*([A-Za-z-]+)\s*(?:#.*)?$", nested)
            if nested_match:
                perms.append((f"permissions.{nested_match.group(1)}", nested_match.group(2)))
    return perms


def _detect_output_sinks(text: str) -> List[str]:
    """Find commands or actions that may publish workflow or agent output."""

    sinks = [
        label for label, pattern in OUTPUT_SINK_PATTERNS
        if re.search(pattern, text, re.I)
    ]
    return sorted(set(sinks))


def scan_workflow_text(path: str, text: str) -> WorkflowSignals:
    """Extract GitLost-relevant signals from one workflow or agentic workflow file."""

    yaml_body = _extract_yaml_body(path, text) or ""
    parsed = _parse_yaml(yaml_body) if yaml_body else None

    if parsed is not None:
        triggers = _extract_triggers(parsed)
        risky = sorted({t for t in triggers if t in RISKY_TRIGGERS})
        untrusted_public = sorted({t for t in triggers if t in UNTRUSTED_PUBLIC_TRIGGERS})
        perms = _collect_permissions(parsed)
        has_explicit_permissions = bool(perms)
        dangerous_permissions = any(_is_write_like(value) for _, value in perms)
        public_write_permissions = _collect_public_write_permissions(perms)
    else:
        # Regex fallback when PyYAML is unavailable or YAML fails to parse.
        triggers = _fallback_triggers(yaml_body)
        risky = sorted({t for t in triggers if t in RISKY_TRIGGERS})
        untrusted_public = sorted({t for t in triggers if t in UNTRUSTED_PUBLIC_TRIGGERS})
        perms = _fallback_permissions(yaml_body)
        has_explicit_permissions = bool(perms) or bool(re.search(r"(?m)^\s*permissions\s*:", yaml_body))
        dangerous_permissions = any(_is_write_like(value) for _, value in perms)
        public_write_permissions = _collect_public_write_permissions(perms)

    # Agentish signals are searched across the whole file (markdown prose
    # in gh-aw workflows is where agent prompts live).
    agentish = any(re.search(p, text, re.I) for p in AGENTISH_PATTERNS)

    return WorkflowSignals(
        triggers=sorted(set(triggers)),
        risky_triggers=risky,
        untrusted_public_triggers=untrusted_public,
        agentish=agentish,
        has_explicit_permissions=has_explicit_permissions,
        dangerous_permissions=dangerous_permissions,
        public_write_permissions=public_write_permissions,
        output_sinks=_detect_output_sinks(text),
    )


def add_finding(findings: List[Finding], repo: Dict[str, Any], category: str, severity: str, finding: str, evidence: str, suggested_action: str) -> None:
    """Append a normalized finding row for a repository or organization."""

    findings.append(Finding(
        repo=repo.get("full_name", repo.get("name", "<org>")),
        visibility=repo.get("visibility", ""),
        archived=bool(repo.get("archived", False)),
        category=category,
        severity=severity,
        finding=finding,
        evidence=evidence,
        suggested_action=suggested_action,
    ))


def repo_is_public(repo: Dict[str, Any]) -> bool:
    """Return True when GitHub metadata says the repository is public."""

    return repo.get("visibility") == "public" or repo.get("private") is False


def _sample(values: List[str], limit: int = 5) -> str:
    """Format a bounded evidence list for compact CSV output."""

    if len(values) <= limit:
        return "; ".join(values)
    return "; ".join(values[:limit]) + f"; +{len(values) - limit} more"


def add_gitlost_correlation_finding(
    findings: List[Finding],
    repo: Dict[str, Any],
    org_private_repo_count: int,
    agent_config_paths: List[str],
    untrusted_input_workflows: List[str],
    agent_workflows: List[str],
    output_sink_workflows: List[str],
    public_write_workflows: List[str],
) -> None:
    """Add the repo-level GitLost chain finding when public-input and agent signals align."""

    if not repo_is_public(repo):
        return

    has_untrusted_input = bool(untrusted_input_workflows)
    has_agent_signal = bool(agent_config_paths or agent_workflows)
    has_output_path = bool(output_sink_workflows or public_write_workflows)
    if not (has_untrusted_input and has_agent_signal):
        return

    # Public REST data cannot prove Copilot/cloud-agent cross-repo reachability.
    # Visible private repo count is a blast-radius hint, so the CSV evidence
    # keeps the exact reachability question explicit for manual follow-up.
    evidence_parts = [
        "public_repo=true",
        f"org_private_repos_visible={org_private_repo_count}",
        f"untrusted_input={_sample(untrusted_input_workflows)}",
    ]
    if agent_workflows:
        evidence_parts.append(f"agent_workflows={_sample(agent_workflows)}")
    if agent_config_paths:
        evidence_parts.append(f"agent_config={_sample(agent_config_paths)}")
    if output_sink_workflows:
        evidence_parts.append(f"output_sinks={_sample(output_sink_workflows)}")
    if public_write_workflows:
        evidence_parts.append(f"public_write_permissions={_sample(public_write_workflows)}")
    evidence_parts.append("private_repo_reachability=manual_check_required")

    if has_output_path and org_private_repo_count > 0:
        severity = "critical"
        finding = "Likely GitLost-style susceptibility chain in public repository."
    elif has_output_path:
        severity = "high"
        finding = "Public prompt-to-output agent chain present; private repo reachability not confirmed."
    else:
        severity = "high"
        finding = "Partial GitLost-style chain: public untrusted input can reach agent-like behavior, but no output sink was detected."

    add_finding(
        findings, repo, "gitlost-susceptibility", severity,
        finding,
        " | ".join(evidence_parts),
        "Treat this as a priority manual review. Disable public issue/comment-driven agent entry points, remove public output sinks, restrict agent repository access, and confirm Copilot/agent firewall and allowlist settings."
    )


def audit_repo(org: str, repo_summary: Dict[str, Any], org_private_repo_count: int) -> List[Finding]:
    """Audit one repository for GitLost signals and adjacent Actions context."""

    findings: List[Finding] = []
    repo_name = repo_summary["name"]
    full = get_repo_full(org, repo_name) or repo_summary
    default_branch = full.get("default_branch") or repo_summary.get("default_branch") or "main"

    actions = get_repo_actions(org, repo_name)

    workflow_perm = actions.get("workflow_permissions")
    if isinstance(workflow_perm, dict) and "__error__" in workflow_perm:
        add_finding(
            findings, full, "coverage", "info",
            "Could not read repository workflow permissions.",
            workflow_perm["__error__"],
            "Confirm token has sufficient admin/read permissions."
        )
    elif isinstance(workflow_perm, dict):
        # `default_workflow_permissions` controls the default GITHUB_TOKEN given
        # to workflow jobs. Write defaults make accidental public output worse.
        default_perm = workflow_perm.get("default_workflow_permissions")
        can_approve = workflow_perm.get("can_approve_pull_request_reviews")
        if default_perm == "write":
            add_finding(
                findings, full, "actions-token", "high",
                "Repository default GITHUB_TOKEN permissions are read/write.",
                json.dumps(workflow_perm, sort_keys=True),
                "Set default workflow permissions to read-only unless this repo has an approved exception."
            )
        if can_approve:
            add_finding(
                findings, full, "actions-token", "high",
                "GitHub Actions can create or approve pull request reviews.",
                json.dumps(workflow_perm, sort_keys=True),
                "Disable Actions PR approval unless explicitly required and separately controlled."
            )

    fork_pr = actions.get("fork_pr")
    if isinstance(fork_pr, dict):
        # Fork PR settings are most important on public repos: they decide
        # whether outside contributors can trigger workflows with secrets/tokens.
        if fork_pr.get("send_write_tokens_to_workflows"):
            add_finding(
                findings, full, "fork-pr", "critical",
                "Fork pull request workflows may receive write tokens.",
                json.dumps(fork_pr, sort_keys=True),
                "Disable write tokens for fork pull request workflows."
            )
        if fork_pr.get("send_secrets_and_variables"):
            add_finding(
                findings, full, "fork-pr", "critical",
                "Fork pull request workflows may receive secrets or variables.",
                json.dumps(fork_pr, sort_keys=True),
                "Disable secrets and variables for fork pull request workflows."
            )
        approval = fork_pr.get("require_approval_for_fork_pr_workflows")
        if approval in (False, "false", "never", None):
            add_finding(
                findings, full, "fork-pr", "medium",
                "Fork pull request workflow approval setting is weak or unreadable.",
                json.dumps(fork_pr, sort_keys=True),
                "Require maintainer approval for fork pull request workflows."
            )

    actions_perm = actions.get("actions_permissions")
    if isinstance(actions_perm, dict):
        # Broad action allowance is a supply-chain signal, not the core GitLost
        # chain, but it can expand what a compromised workflow may run.
        allowed_actions = actions_perm.get("allowed_actions")
        enabled = actions_perm.get("enabled")
        if enabled is True and allowed_actions in ("all", None):
            add_finding(
                findings, full, "actions-policy", "medium",
                "Repository allows broad GitHub Actions usage.",
                json.dumps(actions_perm, sort_keys=True),
                "Prefer selected actions or inherited org restrictions for sensitive repos."
            )

    sec = full.get("security_and_analysis") or {}
    # GitHub reports these only when the caller has enough access and the
    # product/license exists for the repo, so missing values are treated gently.
    secret_scanning = (sec.get("secret_scanning") or {}).get("status")
    push_protection = (sec.get("secret_scanning_push_protection") or {}).get("status")
    advanced_security = (sec.get("advanced_security") or {}).get("status")

    if secret_scanning not in ("enabled", None):
        add_finding(
            findings, full, "secret-scanning", "high",
            "Secret scanning is not enabled.",
            f"secret_scanning={secret_scanning}",
            "Enable secret scanning where licensed/available."
        )
    if push_protection not in ("enabled", None):
        add_finding(
            findings, full, "secret-scanning", "high",
            "Secret scanning push protection is not enabled.",
            f"secret_scanning_push_protection={push_protection}",
            "Enable push protection where licensed/available."
        )
    if advanced_security not in ("enabled", None) and full.get("visibility") == "private":
        add_finding(
            findings, full, "code-security", "info",
            "GitHub Advanced Security is not enabled or not reported for this private repo.",
            f"advanced_security={advanced_security}",
            "Confirm expected licensing and policy for private repos."
        )

    protection = get_branch_protection(org, repo_name, default_branch)
    rulesets = get_repo_rulesets(org, repo_name)
    # Rulesets are GitHub's newer policy system and may protect branches even
    # when classic branch protection is absent.
    has_rulesets = bool(rulesets)
    if protection is None and not has_rulesets:
        add_finding(
            findings, full, "branch-protection", "high",
            "Default branch appears to have no branch protection and no repo rulesets visible.",
            f"default_branch={default_branch}",
            "Require PRs, reviews, status checks, and CODEOWNERS for default/release branches."
        )

    agent_config_paths: List[str] = []
    for cfg_path in AGENT_CONFIG_PATHS:
        # Agent instructions and MCP/Copilot config can influence how an agent
        # interprets issue text even when the workflow file itself looks generic.
        if path_exists(org, repo_name, cfg_path, default_branch):
            agent_config_paths.append(cfg_path)
            add_finding(
                findings, full, "agent-config", "medium",
                "Repository contains agent/coding-assistant configuration.",
                cfg_path,
                "Ensure this path is covered by CODEOWNERS and branch/ruleset review requirements."
            )

    untrusted_input_workflows: List[str] = []
    agent_workflows: List[str] = []
    output_sink_workflows: List[str] = []
    public_write_workflows: List[str] = []

    workflow_files = list_workflow_files(org, repo_name, default_branch)
    for wf in workflow_files:
        path = wf.get("path") or f".github/workflows/{wf.get('name')}"
        text = read_file_content(org, repo_name, path, default_branch)
        if not text:
            continue

        signals = scan_workflow_text(path, text)

        # Accumulate repo-level evidence so one workflow can provide the public
        # trigger while another file or config supplies the agent signal.
        if signals.untrusted_public_triggers:
            untrusted_input_workflows.append(f"{path}: {', '.join(signals.untrusted_public_triggers)}")

        if signals.agentish:
            agent_workflows.append(path)

        if signals.output_sinks:
            output_sink_workflows.append(f"{path}: {', '.join(signals.output_sinks)}")

        if signals.public_write_permissions:
            public_write_workflows.append(f"{path}: {', '.join(signals.public_write_permissions)}")

        if signals.risky_triggers:
            severity = "high" if signals.agentish or signals.dangerous_permissions else "medium"
            add_finding(
                findings, full, "workflow-trigger", severity,
                "Workflow uses triggers that are risky with untrusted user-controlled text.",
                f"{path}: {', '.join(signals.risky_triggers)}",
                "Review whether untrusted issues/comments/PR metadata can reach tools, secrets, tokens, shell, or AI agents."
            )

        if signals.agentish:
            add_finding(
                findings, full, "agent-workflow", "high" if signals.risky_triggers else "medium",
                "Workflow appears to invoke or configure an AI/agentic tool.",
                path,
                "Require security review. Scope token permissions, secrets, repo access, and outbound network behavior."
            )

        if signals.output_sinks:
            add_finding(
                findings, full, "workflow-output-sink", "high" if signals.risky_triggers or signals.agentish else "medium",
                "Workflow has a potential public or external output sink.",
                f"{path}: {', '.join(signals.output_sinks)}",
                "Confirm agent output and untrusted input cannot be written to public comments, logs, artifacts, summaries, or external endpoints."
            )

        if signals.public_write_permissions:
            add_finding(
                findings, full, "workflow-output-sink", "high" if signals.risky_triggers or signals.agentish else "medium",
                "Workflow token can write to public GitHub conversation surfaces.",
                f"{path}: {', '.join(signals.public_write_permissions)}",
                "Remove issue, pull request, or discussion write permissions unless a reviewed workflow requires them."
            )

        if not signals.has_explicit_permissions:
            add_finding(
                findings, full, "workflow-permissions", "medium",
                "Workflow does not declare an explicit permissions block.",
                path,
                "Add least-privilege permissions: at workflow or job level."
            )

        if signals.dangerous_permissions:
            add_finding(
                findings, full, "workflow-permissions", "high",
                "Workflow requests write/admin-like permissions.",
                path,
                "Confirm this is necessary. Split jobs or reduce permissions where possible."
            )

    add_gitlost_correlation_finding(
        findings=findings,
        repo=full,
        org_private_repo_count=org_private_repo_count,
        agent_config_paths=agent_config_paths,
        untrusted_input_workflows=untrusted_input_workflows,
        agent_workflows=agent_workflows,
        output_sink_workflows=output_sink_workflows,
        public_write_workflows=public_write_workflows,
    )

    return findings


def severity_rank(sev: str) -> int:
    """Map severity names to sort order, with unknown severities last."""

    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }.get(sev, 9)


def write_csv(path: str, findings: List[Finding]) -> None:
    """Write findings to CSV, preserving headers even when there are no findings."""

    fields = list(asdict(findings[0]).keys()) if findings else [
        "repo", "visibility", "archived", "category", "severity", "finding", "evidence", "suggested_action"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def main() -> int:
    """Parse CLI arguments, run the organization scan, and write the report."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True, help="GitHub org login")
    parser.add_argument("--enterprise", default=None, help="Enterprise slug for manual check text (optional)")
    parser.add_argument("--include-archived", action="store_true", help="Include archived repos")
    parser.add_argument("--include-private", action="store_true", help="Deep-scan private and internal repos; default is public repos only")
    parser.add_argument("--out", default="gitlost-audit.csv", help="CSV output path")
    args = parser.parse_args()

    print(f"Auditing org: {args.org}", file=sys.stderr)

    org_repo = {
        "name": f"org:{args.org}",
        "full_name": f"org:{args.org}",
        "visibility": "org",
        "archived": False,
    }

    findings: List[Finding] = []

    org_actions = get_org_actions_settings(args.org)

    org_workflow_perm = org_actions.get("workflow_permissions")
    if isinstance(org_workflow_perm, dict):
        # Org defaults can silently apply to many repos, so they are reported
        # before repo scanning and can explain repeated workflow-token findings.
        if org_workflow_perm.get("default_workflow_permissions") == "write":
            add_finding(
                findings, org_repo, "org-actions-token", "critical",
                "Organization default GITHUB_TOKEN permissions are read/write.",
                json.dumps(org_workflow_perm, sort_keys=True),
                "Set organization default workflow permissions to read-only."
            )
        if org_workflow_perm.get("can_approve_pull_request_reviews"):
            add_finding(
                findings, org_repo, "org-actions-token", "critical",
                "Organization allows GitHub Actions to approve pull request reviews.",
                json.dumps(org_workflow_perm, sort_keys=True),
                "Disable Actions PR approval at the org level."
            )

    org_actions_perm = org_actions.get("actions_permissions")
    if isinstance(org_actions_perm, dict):
        # This setting controls which marketplace/internal actions workflows may
        # run. Broad allowance is not GitLost by itself, but it increases drift.
        if org_actions_perm.get("enabled") is True and org_actions_perm.get("allowed_actions") in ("all", None):
            add_finding(
                findings, org_repo, "org-actions-policy", "high",
                "Organization allows broad GitHub Actions usage.",
                json.dumps(org_actions_perm, sort_keys=True),
                "Prefer selected actions, allowlists, or verified/internal action restrictions."
            )

    selected_actions = org_actions.get("selected_actions")
    if isinstance(selected_actions, dict):
        # Selected-action policy can still allow broad classes such as all
        # GitHub-owned or verified actions; record that as review context.
        allowed = selected_actions.get("github_owned_allowed")
        verified = selected_actions.get("verified_allowed")
        patterns = selected_actions.get("patterns_allowed") or []
        if allowed is True and verified is True and not patterns:
            add_finding(
                findings, org_repo, "org-actions-policy", "info",
                "Organization selected-action policy allows GitHub-owned and verified actions.",
                json.dumps(selected_actions, sort_keys=True),
                "Confirm this is acceptable for supply-chain risk. Consider pinning important third-party actions by SHA."
            )

    org_secrets = get_org_actions_secrets(args.org)
    for sec in org_secrets:
        # Only secret names and visibility policies are available here, never
        # values. Broad visibility matters when public repos exist in the org.
        visibility = sec.get("visibility")
        if visibility in ("all", "private"):
            add_finding(
                findings, org_repo, "org-secrets", "high",
                "Organization Actions secret is broadly visible to repositories.",
                f"name={sec.get('name')} visibility={visibility}",
                "Prefer selected-repository visibility for org secrets, especially when public repos exist in the org."
            )

    repos = get_org_repos(args.org)
    if not repos:
        print("No repos found or insufficient access.", file=sys.stderr)
        return 2

    org_private_repo_count = sum(
        1 for repo in repos
        if repo.get("visibility") == "private" or repo.get("private") is True
    )

    # Default deep-scan scope is public repos because GitLost starts from public
    # attacker-controlled text. Private repo inventory is still counted above so
    # public findings can show possible private-repo blast radius.
    scan_repos = []
    for repo in repos:
        if repo.get("archived") and not args.include_archived:
            continue
        if not args.include_private and not repo_is_public(repo):
            continue
        scan_repos.append(repo)

    scope = "all visible repos" if args.include_private else "public repos only"
    print(f"Deep-scanning {len(scan_repos)} of {len(repos)} repos ({scope}).", file=sys.stderr)

    for i, repo in enumerate(scan_repos, 1):
        print(f"[{i}/{len(scan_repos)}] {repo.get('full_name')}", file=sys.stderr)
        findings.extend(audit_repo(args.org, repo, org_private_repo_count))

    findings.sort(key=lambda f: (severity_rank(f.severity), f.repo, f.category, f.finding))

    write_csv(args.out, findings)

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("")
    print("Summary")
    print("-------")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            print(f"{sev}: {counts[sev]}")
    print(f"total findings: {len(findings)}")
    print(f"csv: {args.out}")

    print("")
    print("Manual checks not covered cleanly by public REST in this script")
    print("--------------------------------------------------------------")
    if args.enterprise:
        print(f"- Enterprise/org Copilot cloud agent access for enterprise '{args.enterprise}' and org '{args.org}'.")
    else:
        print(f"- Enterprise/org Copilot cloud agent access for org '{args.org}' (pass --enterprise to include enterprise scope).")
    print("- Copilot cloud agent firewall: force enabled at org level if available.")
    print("- Copilot cloud agent recommended allowlist: decide centrally; avoid repo drift.")
    print("- Copilot cloud agent custom allowlist: disable repo-admin custom entries unless reviewed.")
    print("- User-created Copilot automations/sessions: review logs/UI where available.")
    print("- CODEOWNERS coverage for .github/workflows/**, AGENTS.md, Copilot instructions, MCP configs, and agent setup files.")
    print("")
    print("Suggested triage order")
    print("----------------------")
    print("1. gitlost-susceptibility findings in public repos")
    print("2. public repos with both agent-workflow and workflow-output-sink findings")
    print("3. manual Copilot/cloud-agent access and firewall checks for those repos")
    print("4. workflows with public write permissions or comment/webhook/artifact sinks")
    print("5. adjacent high/critical Actions token or org-secret findings")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
