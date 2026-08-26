import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from github_actions_security_auditor import (
    audit_text,
    audit_workflow,
    build_json_report,
    build_report,
    collect_workflow_files,
    get_triggers,
    main,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_workflows"


def checks_in(findings):
    return [f["check"] for f in findings]


def audit_sample(name):
    return audit_text((SAMPLES / name).read_text(encoding="utf-8"), name)


def load(text):
    return yaml.safe_load(text)


def test_get_triggers_handles_pyyaml_bare_on_gotcha():
    # PyYAML parses a bare `on:` key as the boolean True (YAML 1.1) — make
    # sure we still recover the trigger list despite that.
    doc = load("on: push\njobs: {}\n")
    assert True in doc  # sanity-check the gotcha is real in this environment
    assert get_triggers(doc) == {"push"}


def test_get_triggers_handles_list_form():
    doc = load("on: [push, pull_request]\njobs: {}\n")
    assert get_triggers(doc) == {"push", "pull_request"}


def test_get_triggers_handles_dict_form():
    doc = load("on:\n  push:\n  pull_request:\n    types: [opened]\njobs: {}\n")
    assert get_triggers(doc) == {"push", "pull_request"}


def test_get_triggers_empty_when_missing():
    assert get_triggers({"jobs": {}}) == set()


def test_pull_request_target_with_pr_head_checkout_flagged_high():
    doc = load(
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "pull_request_target_checkout_pr_head" and f["severity"] == "HIGH" for f in findings)


def test_pull_request_target_without_pr_head_checkout_not_flagged():
    doc = load(
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "pull_request_target_checkout_pr_head" for f in findings)


def test_self_hosted_runner_on_pull_request_flagged_high():
    doc = load("on: pull_request\njobs:\n  build:\n    runs-on: self-hosted\n    steps: []\n")
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "self_hosted_runner_on_fork_pr" and f["severity"] == "HIGH" for f in findings)


def test_self_hosted_runner_on_push_not_flagged():
    doc = load("on: push\njobs:\n  build:\n    runs-on: self-hosted\n    steps: []\n")
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "self_hosted_runner_on_fork_pr" for f in findings)


def test_unpinned_third_party_action_flagged_medium():
    doc = load(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: some-org/some-action@v1\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "unpinned_third_party_action" and f["severity"] == "MEDIUM" for f in findings)


def test_pinned_third_party_action_not_flagged():
    doc = load(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: some-org/some-action@" + "a" * 40 + "\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "unpinned_third_party_action" for f in findings)


def test_unpinned_first_party_action_not_flagged():
    doc = load("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "unpinned_third_party_action" for f in findings)


def test_untrusted_input_in_run_flagged_high():
    doc = load(
        "on: issues\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "untrusted_input_script_injection" and f["severity"] == "HIGH" for f in findings)


def test_untrusted_input_via_env_indirection_not_flagged():
    doc = load(
        "on: issues\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - env:\n"
        "          TITLE: ${{ github.event.issue.title }}\n"
        '        run: echo "$TITLE"\n'
    )
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "untrusted_input_script_injection" for f in findings)


def test_secret_echoed_flagged_high():
    doc = load(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "token is ${{ secrets.TOKEN }}"\n'
    )
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "secret_printed_in_run" and f["severity"] == "HIGH" for f in findings)


def test_secret_used_without_echo_not_flagged():
    doc = load(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - env:\n"
        "          TOKEN: ${{ secrets.TOKEN }}\n"
        "        run: ./deploy.sh\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "secret_printed_in_run" for f in findings)


def test_write_all_permissions_workflow_level_flagged_medium():
    doc = load("on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n")
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "write_all_permissions" and "(workflow)" in f["location"] for f in findings)


def test_write_all_permissions_job_level_flagged_medium():
    doc = load(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: write-all\n    steps: []\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert any(f["check"] == "write_all_permissions" and "build" in f["location"] for f in findings)


def test_scoped_permissions_not_flagged():
    doc = load(
        "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )
    findings = audit_workflow(doc, "test.yml")
    assert not any(f["check"] == "write_all_permissions" for f in findings)


def test_non_dict_workflow_returns_no_findings():
    assert audit_workflow(None, "test.yml") == []
    assert audit_workflow([], "test.yml") == []


def test_insecure_example_flags_expected_checks_and_counts():
    findings = audit_sample("insecure_example.yml")
    checks = set(checks_in(findings))
    assert checks == {
        "pull_request_target_checkout_pr_head",
        "self_hosted_runner_on_fork_pr",
        "unpinned_third_party_action",
        "untrusted_input_script_injection",
        "secret_printed_in_run",
        "write_all_permissions",
    }
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    assert (high, medium) == (4, 2)


def test_hardened_example_has_no_findings():
    assert audit_sample("hardened_example.yml") == []


def test_collect_workflow_files_on_directory():
    files = collect_workflow_files(SAMPLES)
    names = {f.name for f in files}
    assert names == {"insecure_example.yml", "hardened_example.yml"}


def test_collect_workflow_files_on_single_file():
    assert len(collect_workflow_files(SAMPLES / "hardened_example.yml")) == 1


def test_build_report_lists_findings_in_markdown_table():
    results = [("insecure_example.yml", audit_sample("insecure_example.yml"))]
    report = build_report(results)
    assert "HIGH" in report
    assert "secret_printed_in_run" in report


def test_build_report_clean_says_no_issues():
    results = [("hardened_example.yml", audit_sample("hardened_example.yml"))]
    report = build_report(results)
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    results = [("insecure_example.yml", audit_sample("insecure_example.yml"))]
    payload = json.loads(build_json_report(results))
    assert payload["workflows_scanned"] == 1
    assert payload["summary"]["high"] == 4


def run_main(monkeypatch, tmp_path, target_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["github_actions_security_auditor.py", "--path", str(target_path), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_insecure_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.yml", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_hardened_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "hardened_example.yml", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.yml", []) == 0
