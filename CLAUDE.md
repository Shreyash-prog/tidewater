# Tidewater — Repo Context for Claude Code

This is a POC of a platform hygiene framework for AWS. You are helping build it. Always consult these documents before generating code or making design decisions:

1. **`docs/scope-poc.md`** — what's in the POC and what's deliberately out.
2. **`docs/architecture.md`** — technical decisions, stack, repo layout, data model.
3. **`docs/build-plan.md`** — the phase-by-phase build sequence (will be added).

## Locked technical choices (do not re-litigate)

- **Language (backend)**: Python 3.12 + Pydantic v2 + AWS Lambda Powertools
- **Language (frontend)**: TypeScript + React + Vite
- **Styling**: Tailwind + shadcn/ui
- **Charts**: Recharts
- **IaC**: AWS CDK in Python, two stacks (`CoreStack` + `FixturesStack`)
- **API**: API Gateway HTTP API, contract in `openapi/api.yaml`, TS client generated
- **Auth (POC only)**: pre-shared bearer token in `localStorage`, Lambda authorizer validates against SSM Parameter Store
- **Data store**: DynamoDB on-demand
- **Lint**: Ruff. **Type check**: mypy default mode with `disallow_untyped_defs = True`
- **Dep mgmt**: pip + `requirements.txt` per Lambda (uv for local dev speed)
- **Region**: `us-east-1` only
- **Budget**: hard cap of $20/month via AWS Budgets stop-action on EventBridge Schedules

## Coding conventions

- Type-annotate every function. mypy will fail PRs that don't.
- Use Pydantic models for all data crossing boundaries (Lambda inputs, DynamoDB items, API payloads).
- Use Powertools `Logger`, `Tracer`, `Metrics` in every Lambda.
- Never use `boto3.client(...).delete_*` directly in detector or policy-engine code. All destructive actions go through SSM Automation documents in `runbooks/`.
- Detectors snapshot any deletable resource to `s3://<audit-bucket>/snapshots/...` before deletion.
- Audit log writes are JSON Lines to S3, never just CloudWatch logs.
- Log retention is 1 day on every Lambda log group (Free Tier guardrail).
- No NAT Gateways anywhere — Lambdas run outside VPC.

## Safety rules

- Anything that deletes an AWS resource must have a corresponding SSM Automation doc with a `--check` / dry-run mode.
- Every rule has a 14-day grace period between first detection and any auto-remediation (configurable but defaulted on).
- The `iam.wildcard_policy` detector is **flag-only** — it never auto-remediates. Wildcard policies often exist for legitimate reasons that aren't visible to the framework.

## Detector authoring conventions (Phase 3+)

- A detector subclasses `shared.detector_base.Detector`, sets `rule_id`/`service`/`severity`, and implements `scan() -> Iterator[Finding]`. `run()` (provided) wraps `scan()` with Powertools metrics + structured logging. Detectors are **read-only** — never call a destructive API; deletion happens via SSM Automation in the remediator (Phase 4).
- Skip AWS-managed roles/resources (e.g. `^aws-service-role/` path, `AWSReservedSSO_`, `cdk-hnb659fds-`, `StackSet-`, `OrganizationAccountAccessRole`, `aws-controltower-`). Never put a trust policy (or other large/noisy blobs) in `Finding.details`.
- Rules are YAML in the `rules-yaml` S3 bucket at `rules/{rule_id}.yaml`, loaded via `shared.rule_loader.load_enabled_rules_for_service(service, prefix="rules/")`. Loading **fails closed**: on a persistent S3 error the loader raises and the handler emits zero findings rather than acting on stale/absent config. The 5-minute cache (keyed per `(service, prefix)`) is for performance only.
- **Detector Lambda event schema:** `{account, region, rules_prefix_override?: string}`. `rules_prefix_override` (default `"rules/"`) scopes which S3 prefix rules are read from. It is a legitimate, read-only configuration knob — used by the smoke test to point at a temporary scoped rule set, and forward-compatible with per-account/per-tenant rule prefixes. It is **not** a per-rule threshold knob: detectors must not gain test-only overrides on their evaluation logic; exercise behaviour by supplying real rule YAML instead.
- Findings are written via `shared.findings_writer.FindingsTableWriter`, which does an **idempotent conditional upsert** keyed on PK=`account#region#service`, SK=`resource_arn#rule_id` (preserves `detected_at`, refreshes `last_seen_at`). Re-running a detector must never duplicate rows — cover this with a "run twice, same row count" test.
- A service handler keeps a `REGISTRY` mapping `rule_id -> Detector` class; unknown rule_ids are logged and skipped. Emit one EventBridge event per created/updated finding via `shared.event_emitter`.
- Detector code that imports `shared` must be packaged with `include_shared=True` on `PythonLambda` and referenced by its full dotted handler path (e.g. `detectors.iam.handler.handler`) so repo and bundle imports match.
- Phase 3 is **on-demand only** (no EventBridge Schedule) and hard-codes `policy_decision = dry_run`; the policy engine arrives in Phase 4.
- ⚠️ **The shipped POC rule values are demo-only and unsafe in production.** `infra/initial_rules/iam.unused_role.yaml` uses `idle_days: -1` (flags any role idle ≥ 0 days, so the demo runs in seconds), `grace_period_days: 0` (no window before auto-remediation), and an `Environment=nonprod → auto` override. Production rules use `idle_days` of 7–90, `grace_period_days` ≥ 14, and `prompt` (human review) rather than `auto`. See README "POC vs Production".

### Approval idempotency

- **One approval per finding, ever.** Approval rows are keyed by a deterministic id — `appr_` + the first 24 hex chars of `sha256("{finding_pk}|{finding_sk}")` (`policy_engine.handler.approval_id_for`) — so the idempotency check is a single `GetItem`, with no GSI. The policy engine re-dispatches `prompt` whenever a finding's stored `policy_decision` differs from the computed one (the detector resets it to `dry_run` on each run), so approval creation **must** be idempotent: if a pending approval already exists, log and skip — never create a second.
- Approvals already in `approved`/`rejected`/`expired` are **preserved**. If a finding returns to `prompt`, the policy engine logs a warning and does **not** create a new approval or re-open the old one. Re-opening previously-decided findings is **future dashboard work** (Phase 9+).

## Workflow

- All work happens on feature branches; PRs go to `main` (branch protection enforced).
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- Before opening a PR: `make lint && make test && make synth` must pass.
- `pre-commit` runs `gitleaks` on staged changes — do not bypass it.

## When unsure

If you're about to make a decision not covered by the locked choices above, ask the developer before coding. POC scope is tight; speculative additions blow the timeline.
