# GitHub Actions Security Audit

- **Workflows scanned:** 1
- **Findings:** 4 HIGH, 2 MEDIUM

| Severity | Location | Check | Reason |
|---|---|---|---|
| HIGH | sample_workflows\insecure_example.yml:build | pull_request_target_checkout_pr_head | Workflow triggers on pull_request_target (runs with base-repo secrets/token) and explicitly checks out the PR head — a fork's PR can run its own code with access to your secrets. |
| HIGH | sample_workflows\insecure_example.yml:build | self_hosted_runner_on_fork_pr | Job uses a self-hosted runner on a workflow triggered by pull_request — a PR from a fork can run arbitrary code on your self-hosted infrastructure. |
| HIGH | sample_workflows\insecure_example.yml:build/Print issue title | untrusted_input_script_injection | A run: step interpolates an untrusted, attacker-controlled context value (e.g. an issue/PR title or body) directly into the shell command — a documented script-injection vector (the value can contain shell metacharacters). |
| HIGH | sample_workflows\insecure_example.yml:build/Debug secret | secret_printed_in_run | A run: step explicitly echoes/prints a secrets.* value — this writes the secret into the (often public, or at least broadly-readable) build log. |
| MEDIUM | sample_workflows\insecure_example.yml:build/Build with third-party action | unpinned_third_party_action | "some-org/some-build-action@v1" is not pinned to a full commit SHA — a compromised or re-tagged release could silently change what this step runs. |
| MEDIUM | sample_workflows\insecure_example.yml:(workflow) | write_all_permissions | permissions: write-all at the workflow level grants every job full write access to every GitHub API scope. |
