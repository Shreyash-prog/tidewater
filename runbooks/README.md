# Runbooks

SSM Automation document YAMLs — one per remediation. Every destructive action in
Tidewater goes through one of these (never a direct `boto3 delete_*` call), and
each must support a `--check` / dry-run mode (see CLAUDE.md safety rules).

Populated from Phase 4 onward. Planned documents (docs/scope-poc.md §4):

- `delete_iam_role.yml`
- `delete_iam_access_key.yml`
- `detach_unused_policy.yml`
- `delete_lambda_version.yml`
- `delete_orphan_log_group.yml`

`iam.wildcard_policy` is flag-only and has no remediation runbook.
