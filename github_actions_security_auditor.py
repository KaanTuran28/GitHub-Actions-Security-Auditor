#!/usr/bin/env python3
"""Static security auditor for GitHub Actions workflow files.

Flags the supply-chain and script-injection patterns documented by GitHub's
own security guidance and tools like `zizmor`/StepSecurity: `pull_request_target`
combined with checking out the PR head, self-hosted runners on fork-triggered
`pull_request` workflows, unpinned third-party actions, untrusted context
expressions interpolated directly into a shell script, secrets echoed to logs,
and `permissions: write-all`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*"
    r"(github\.event\.(issue|pull_request|comment|review|discussion)\.[\w.]*?(title|body)"
    r"|github\.head_ref"
    r"|github\.event\.head_commit\.message)"
    r"\s*\}\}"
)
PR_HEAD_REF_RE = re.compile(r"\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}")
SECRET_PRINT_RE = re.compile(
    r"\b(echo|print|write-host|console\.log)\b[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}", re.IGNORECASE
)
TRUSTED_ACTION_PREFIXES = ("actions/", "github/")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def get_triggers(workflow: dict) -> set:
    # PyYAML (YAML 1.1) parses a bare `on:` key as the boolean True, not the
    # string "on" — a well-known gotcha for anyone parsing GH Actions YAML.
    on = workflow.get("on")
    if on is None:
        on = workflow.get(True)
    if on is None:
        return set()
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def finding(severity: str, check: str, location: str, reason: str, recommendation: str) -> dict:
    return {"severity": severity, "check": check, "location": location, "reason": reason, "recommendation": recommendation}


def iter_jobs(workflow: dict):
    jobs = workflow.get("jobs") or {}
    for job_id, job in jobs.items():
        if isinstance(job, dict):
            yield job_id, job


def iter_steps(workflow: dict):
    for job_id, job in iter_jobs(workflow):
        for step in job.get("steps") or []:
            if isinstance(step, dict):
                yield job_id, job, step


def audit_workflow(workflow: dict, source: str) -> list:
    if not isinstance(workflow, dict):
        return []

    findings = []
    triggers = get_triggers(workflow)

    if "pull_request_target" in triggers:
        for job_id, _job, step in iter_steps(workflow):
            uses = str(step.get("uses", ""))
            if not uses.startswith("actions/checkout@"):
                continue
            ref = str((step.get("with") or {}).get("ref", ""))
            if PR_HEAD_REF_RE.search(ref):
                findings.append(finding(
                    "HIGH", "pull_request_target_checkout_pr_head", f"{source}:{job_id}",
                    "Workflow triggers on pull_request_target (runs with base-repo secrets/token) and "
                    "explicitly checks out the PR head — a fork's PR can run its own code with access "
                    "to your secrets.",
                    "Avoid checking out untrusted PR head code under pull_request_target; if unavoidable, "
                    "don't use secrets in the same job, or gate it behind manual approval.",
                ))

    if "pull_request" in triggers:
        for job_id, job in iter_jobs(workflow):
            runs_on = job.get("runs-on")
            runs_on_list = runs_on if isinstance(runs_on, list) else [runs_on]
            if any("self-hosted" in str(r) for r in runs_on_list):
                findings.append(finding(
                    "HIGH", "self_hosted_runner_on_fork_pr", f"{source}:{job_id}",
                    "Job uses a self-hosted runner on a workflow triggered by pull_request — a PR from a "
                    "fork can run arbitrary code on your self-hosted infrastructure.",
                    "Use GitHub-hosted runners for pull_request-triggered jobs, or require approval for "
                    "first-time/external contributors before running on self-hosted runners.",
                ))

    for job_id, job in iter_jobs(workflow):
        if job.get("permissions") == "write-all":
            findings.append(finding(
                "MEDIUM", "write_all_permissions", f"{source}:{job_id}",
                "permissions: write-all grants this job full write access to every GitHub API scope.",
                "Grant only the specific permission scopes this job actually needs.",
            ))

    for job_id, job, step in iter_steps(workflow):
        step_label = step.get("name") or step.get("id") or "?"
        location = f"{source}:{job_id}/{step_label}"

        uses = step.get("uses")
        if uses:
            action_ref, _, version = str(uses).rpartition("@")
            if action_ref and not action_ref.startswith(TRUSTED_ACTION_PREFIXES) and not FULL_SHA_RE.match(version):
                findings.append(finding(
                    "MEDIUM", "unpinned_third_party_action", location,
                    f'"{uses}" is not pinned to a full commit SHA — a compromised or re-tagged release '
                    "could silently change what this step runs.",
                    f"Pin to a full commit SHA instead of the {version!r} tag/branch.",
                ))

        run = step.get("run")
        if run:
            run_text = str(run)
            if UNTRUSTED_CONTEXT_RE.search(run_text):
                findings.append(finding(
                    "HIGH", "untrusted_input_script_injection", location,
                    "A run: step interpolates an untrusted, attacker-controlled context value (e.g. an "
                    "issue/PR title or body) directly into the shell command — a documented script-"
                    "injection vector (the value can contain shell metacharacters).",
                    'Pass the value through env: first (e.g. env: TITLE: "${{ github.event.issue.title '
                    '}}") and reference "$TITLE" in the script instead of interpolating the expression directly.',
                ))
            if SECRET_PRINT_RE.search(run_text):
                findings.append(finding(
                    "HIGH", "secret_printed_in_run", location,
                    "A run: step explicitly echoes/prints a secrets.* value — this writes the secret "
                    "into the (often public, or at least broadly-readable) build log.",
                    "Never echo/print a secret. If you need to debug, use a masked, minimal check "
                    "(e.g. verify it's non-empty) instead of printing the value.",
                ))

    if workflow.get("permissions") == "write-all":
        findings.append(finding(
            "MEDIUM", "write_all_permissions", f"{source}:(workflow)",
            "permissions: write-all at the workflow level grants every job full write access to every "
            "GitHub API scope.",
            "Grant only the specific permission scopes actually needed, ideally scoped per-job.",
        ))

    return findings


def audit_text(text: str, source: str) -> list:
    workflow = yaml.safe_load(text)
    return audit_workflow(workflow, source)


def build_report(results: list) -> str:
    all_findings = [(f, source) for source, findings in results for f in findings]
    high = [f for f, _ in all_findings if f["severity"] == "HIGH"]
    medium = [f for f, _ in all_findings if f["severity"] == "MEDIUM"]

    lines = [
        "# GitHub Actions Security Audit",
        "",
        f"- **Workflows scanned:** {len(results)}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM",
        "",
    ]
    if all_findings:
        lines += ["| Severity | Location | Check | Reason |", "|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1}
        for f, _source in sorted(all_findings, key=lambda pair: order[pair[0]["severity"]]):
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['location']} | {f['check']} | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(results: list) -> str:
    all_findings = [f for _, findings in results for f in findings]
    payload = {
        "workflows_scanned": len(results),
        "summary": {
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        },
        "results": [{"file": source, "findings": findings} for source, findings in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def collect_workflow_files(path: Path) -> list:
    if path.is_file():
        return [path]
    files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))
    return sorted(set(files))


def main():
    parser = argparse.ArgumentParser(description="Static security audit of GitHub Actions workflow files.")
    parser.add_argument(
        "--path", required=True,
        help="Path to a workflow YAML file, or a directory (e.g. .github/workflows) to scan recursively.",
    )
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    files = collect_workflow_files(target)
    results = [(str(f), audit_text(f.read_text(encoding="utf-8"), str(f))) for f in files]

    report = build_json_report(results) if args.format == "json" else build_report(results)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    all_findings = [f for _, findings in results for f in findings]
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"Scanned {len(files)} workflow(s): {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
