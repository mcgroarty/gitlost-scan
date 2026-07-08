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
  python3 github-gitlost-audit.py --org my-org --out gitlost-audit.csv

Notes:
  - This does not modify GitHub settings.
  - It intentionally uses gh api rather than a Python GitHub library.
  - It uses simple workflow-text scanning, not a full YAML parser.
"""

import argparse
import base64
import csv
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


RISKY_TRIGGERS = {
    "pull_request_target",
    "issue_comment",
    "issues",
    "workflow_run",
    "discussion",
    "discussion_comment",
    "pull_request_review",
}

AGENTISH_PATTERNS = [
    r"\bcopilot\b",
    r"\bopenai\b",
    r"\banthropic\b",
    r"\bclaude\b",
    r"\bcodex\b",
    r"\bdevin\b",
    r"\bagent\b",
    r"\bmcp\b",
    r"\bllm\b",
    r"\bai[-_ ]?agent\b",
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


@dataclass
class Finding:
    repo: str
    visibility: str
    archived: bool
    category: str
    severity: str
    finding: str
    evidence: str
    suggested_action: str


def gh_api(endpoint: str, paginate: bool = False, tolerate_404: bool = True) -> Optional[Any]:
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
    repos = gh_api(f"/orgs/{org}/repos?type=all&per_page=100", paginate=True)
    if not isinstance(repos, list):
        return []
    return repos


def get_org_actions_settings(org: str) -> Dict[str, Any]:
    out = {}
    for name, endpoint in [
        ("actions_permissions", f"/orgs/{org}/actions/permissions"),
        ("workflow_permissions", f"/orgs/{org}/actions/permissions/workflow"),
        ("selected_actions", f"/orgs/{org}/actions/permissions/selected-actions"),
    ]:
        out[name] = gh_api(endpoint)
    return out


def get_org_actions_secrets(org: str) -> List[Dict[str, Any]]:
    data = gh_api(f"/orgs/{org}/actions/secrets?per_page=100", paginate=False)
    if isinstance(data, dict) and isinstance(data.get("secrets"), list):
        return data["secrets"]
    return []


def get_repo_full(owner: str, repo: str) -> Optional[Dict[str, Any]]:
    return gh_api(f"/repos/{owner}/{repo}")


def get_repo_actions(owner: str, repo: str) -> Dict[str, Any]:
    out = {}
    for name, endpoint in [
        ("actions_permissions", f"/repos/{owner}/{repo}/actions/permissions"),
        ("workflow_permissions", f"/repos/{owner}/{repo}/actions/permissions/workflow"),
        ("selected_actions", f"/repos/{owner}/{repo}/actions/permissions/selected-actions"),
        ("fork_pr", f"/repos/{owner}/{repo}/actions/permissions/fork-pr"),
    ]:
        out[name] = gh_api(endpoint)
    return out


def get_branch_protection(owner: str, repo: str, branch: str) -> Optional[Dict[str, Any]]:
    return gh_api(f"/repos/{owner}/{repo}/branches/{branch}/protection")


def get_repo_rulesets(owner: str, repo: str) -> Optional[List[Dict[str, Any]]]:
    data = gh_api(f"/repos/{owner}/{repo}/rulesets?per_page=100", paginate=True)
    if isinstance(data, list):
        return data
    return None


def list_workflow_files(owner: str, repo: str, ref: str) -> List[Dict[str, Any]]:
    data = gh_api(f"/repos/{owner}/{repo}/contents/.github/workflows?ref={ref}")
    if isinstance(data, list):
        return [x for x in data if x.get("type") == "file" and x.get("name", "").lower().endswith((".yml", ".yaml"))]
    return []


def read_file_content(owner: str, repo: str, path: str, ref: str) -> Optional[str]:
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
    return None


def path_exists(owner: str, repo: str, path: str, ref: str) -> bool:
    data = gh_api(f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
    return isinstance(data, dict) or isinstance(data, list)


def scan_workflow_text(text: str) -> Tuple[List[str], bool, bool, bool]:
    lower = text.lower()

    risky = sorted([trigger for trigger in RISKY_TRIGGERS if re.search(rf"(^|\s|[\[\{{,]){re.escape(trigger)}(\s|:|,|\]|\}}|$)", lower, re.M)])

    agentish = any(re.search(p, lower, re.I) for p in AGENTISH_PATTERNS)

    has_explicit_permissions = bool(re.search(r"(?m)^\s*permissions\s*:", text))

    dangerous_permissions = bool(
        re.search(r"(?m)^\s*(contents|issues|pull-requests|actions|id-token|secrets|attestations)\s*:\s*(write|admin)\s*$", text)
        or re.search(r"(?m)^\s*permissions\s*:\s*write-all\s*$", text)
    )

    return risky, agentish, has_explicit_permissions, dangerous_permissions


def add_finding(findings: List[Finding], repo: Dict[str, Any], category: str, severity: str, finding: str, evidence: str, suggested_action: str) -> None:
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


def audit_repo(org: str, repo_summary: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    repo_name = repo_summary["name"]
    full = get_repo_full(org, repo_name) or repo_summary
    default_branch = full.get("default_branch") or repo_summary.get("default_branch") or "main"

    actions = get_repo_actions(org, repo_name)

    workflow_perm = actions.get("workflow_permissions")
    if isinstance(workflow_perm, dict):
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
    elif isinstance(workflow_perm, dict) and "__error__" in workflow_perm:
        add_finding(
            findings, full, "coverage", "info",
            "Could not read repository workflow permissions.",
            workflow_perm["__error__"],
            "Confirm token has sufficient admin/read permissions."
        )

    fork_pr = actions.get("fork_pr")
    if isinstance(fork_pr, dict):
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
    has_rulesets = bool(rulesets)
    if protection is None and not has_rulesets:
        add_finding(
            findings, full, "branch-protection", "high",
            "Default branch appears to have no branch protection and no repo rulesets visible.",
            f"default_branch={default_branch}",
            "Require PRs, reviews, status checks, and CODEOWNERS for default/release branches."
        )

    for cfg_path in AGENT_CONFIG_PATHS:
        if path_exists(org, repo_name, cfg_path, default_branch):
            add_finding(
                findings, full, "agent-config", "medium",
                "Repository contains agent/coding-assistant configuration.",
                cfg_path,
                "Ensure this path is covered by CODEOWNERS and branch/ruleset review requirements."
            )

    workflow_files = list_workflow_files(org, repo_name, default_branch)
    for wf in workflow_files:
        path = wf.get("path") or f".github/workflows/{wf.get('name')}"
        text = read_file_content(org, repo_name, path, default_branch)
        if not text:
            continue

        risky_triggers, agentish, has_explicit_permissions, dangerous_permissions = scan_workflow_text(text)

        if risky_triggers:
            severity = "high" if agentish or dangerous_permissions else "medium"
            add_finding(
                findings, full, "workflow-trigger", severity,
                "Workflow uses triggers that are risky with untrusted user-controlled text.",
                f"{path}: {', '.join(risky_triggers)}",
                "Review whether untrusted issues/comments/PR metadata can reach tools, secrets, tokens, shell, or AI agents."
            )

        if agentish:
            add_finding(
                findings, full, "agent-workflow", "high" if risky_triggers else "medium",
                "Workflow appears to invoke or configure an AI/agentic tool.",
                path,
                "Require security review. Scope token permissions, secrets, repo access, and outbound network behavior."
            )

        if not has_explicit_permissions:
            add_finding(
                findings, full, "workflow-permissions", "medium",
                "Workflow does not declare an explicit permissions block.",
                path,
                "Add least-privilege permissions: at workflow or job level."
            )

        if dangerous_permissions:
            add_finding(
                findings, full, "workflow-permissions", "high",
                "Workflow requests write/admin-like permissions.",
                path,
                "Confirm this is necessary. Split jobs or reduce permissions where possible."
            )

    return findings


def severity_rank(sev: str) -> int:
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }.get(sev, 9)


def write_csv(path: str, findings: List[Finding]) -> None:
    fields = list(asdict(findings[0]).keys()) if findings else [
        "repo", "visibility", "archived", "category", "severity", "finding", "evidence", "suggested_action"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True, help="GitHub org login")
    parser.add_argument("--enterprise", default=None, help="Enterprise slug for manual check text (optional)")
    parser.add_argument("--include-archived", action="store_true", help="Include archived repos")
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
        if org_actions_perm.get("enabled") is True and org_actions_perm.get("allowed_actions") in ("all", None):
            add_finding(
                findings, org_repo, "org-actions-policy", "high",
                "Organization allows broad GitHub Actions usage.",
                json.dumps(org_actions_perm, sort_keys=True),
                "Prefer selected actions, allowlists, or verified/internal action restrictions."
            )

    selected_actions = org_actions.get("selected_actions")
    if isinstance(selected_actions, dict):
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

    for i, repo in enumerate(repos, 1):
        if repo.get("archived") and not args.include_archived:
            continue
        print(f"[{i}/{len(repos)}] {repo.get('full_name')}", file=sys.stderr)
        findings.extend(audit_repo(args.org, repo))

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
    print("1. critical and high findings in public repos")
    print("2. public repos with agent workflows or issue/comment triggers")
    print("3. repos with org secrets visible broadly")
    print("4. private repos with read/write default workflow tokens")
    print("5. repos with missing branch protection/rulesets")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())