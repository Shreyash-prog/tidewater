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
- **Tags aren't always in the list call.** IAM `ListRoles` returns tags inline, but Lambda `ListFunctions` does **not** — `lambda.unused_function` fetches them with a per-function `lambda:ListTags` call. Always confirm where a service surfaces tags; the policy engine needs `details["tags"]` for nonprod/skip overrides.
- **Rule-YAML thresholds are required, never silently defaulted.** A detector that needs `threshold.idle_days` must fail loudly when it's absent (`lambda.unused_function` raises `ValueError`; `iam.unused_role` logs and emits zero findings) rather than picking an implicit window — a wrong default could auto-remediate far more aggressively than intended.
- **Quota-shaped detectors accumulate history + forecast.** Write each data point every scan via `shared.metrics.write_metric_history` (best-effort — log + continue on failure, never block detection) and project breaches via `shared.forecasting.compute_forecast`. The IAM detector handler surfaces the rule's `forecast.{enabled,alert_at_days_remaining}` into the detector's `threshold` dict; the detector reads `METRIC_HISTORY_TABLE` from its environment. See "Forecasting".
- **Notification routing is automatic — detectors don't think about it.** Emit a finding normally; if it's HIGH severity and the policy engine decides `prompt` (or it's a `*.forecast_alert`), the operator gets an email. See "Notifications".
- Phase 3 is **on-demand only** (no EventBridge Schedule) and hard-codes `policy_decision = dry_run`; the policy engine arrives in Phase 4.
- `iam.orphaned_trust` recognizes **two** orphan forms in a trust policy: same-account ARN-format principals verified absent via `GetRole`/`GetUser` (MEDIUM — AWS sometimes retains these briefly after deletion), and **bare AWS unique IDs** (`AIDA*` user, `AROA*` role, `AIPA*` group) which AWS substitutes for a deleted entity's ARN (HIGH — AWS rejects bare unique IDs on trust-policy *create*, so any present is a confirmed orphan). Bare IDs are matched by **prefix, not length**. `details["orphan_principals"]` is a list of `{"type": "arn"|"unique_id", "principal": ...}`; the remediator strips both forms.
- ⚠️ **The shipped POC rule values are demo-only and unsafe in production.** `infra/initial_rules/iam.unused_role.yaml` uses `idle_days: -1` (flags any role idle ≥ 0 days, so the demo runs in seconds), `grace_period_days: 0` (no window before auto-remediation), and an `Environment=nonprod → auto` override. Production rules use `idle_days` of 7–90, `grace_period_days` ≥ 14, and `prompt` (human review) rather than `auto`. See README "POC vs Production".

### IAM grants ↔ boto3 calls (Phase 5)

- Detector execution-role permissions are **hand-curated** in `core_stack.py` (`_iam_detector`), not derived from a CDK `grant_*` helper. They can drift out of sync with detector code. `tests/test_iam_grants_match_boto3_calls.py` is a meta-test that statically scans detector source for boto3 IAM calls (direct, callable-reference, and `get_paginator("...")` forms) and asserts the synthesized role grants the matching action.
- **Adding a new IAM API call to a detector requires two edits:** (1) grant the `iam:` action in `core_stack.py`, and (2) add the `boto3_method -> iam:Action` pair to `BOTO3_METHOD_TO_IAM_ACTION` in that test. The test fails loudly until both are present.
- `iam.wildcard_policy` is **read-only by design and flag-only**: it has no SSM runbook, no `REGISTRY` entry in the remediator, and must never be auto-remediated under any circumstances. Wildcard policies frequently exist for legitimate reasons the framework can't see.

### Remediation runbook authoring (Phase 5)

- Each destructive rule maps to one SSM Automation document in `runbooks/` and one `REGISTRY` entry + parameter builder in `lambdas/remediator/handler.py`. The remediator only dispatches + audits; the runbook does the snapshot-then-mutate. `runbooks/_shared/snapshot_and_audit.py` is the unit-tested canonical reference for the snapshot/audit/finding-update/event helpers; the runbooks inline equivalent self-contained Python (SSM `aws:executeScript`) so they need no attachments.
- **Every runbook snapshots before it mutates** (the `writeSnapshotToS3` gate) and re-asserts its guardrail (protected-role / AWS-managed-policy / no-attachments) at execution time. `tests/runbook/test_new_runbooks.py` enforces this ordering structurally.
- `delete_iam_access_key.yml` **deactivates only** (`UpdateAccessKey Status=Inactive`) — it never calls `DeleteAccessKey`. Key deletion is irreversible and the secret can't be snapshotted, so full deletion is an operator-driven action, never automatic.
- SSM-runbook IAM permissions live on `TidewaterSsmExecutionRole`, scoped by resource type (role/ vs user/ vs policy/); service-last-accessed APIs key off a JobId and can't be resource-scoped, so they're granted on `*`.

### SSM Document maintenance

- **CloudFormation cannot update a custom-named `AWS::SSM::Document` whose body changes.** Changing the runbook YAML makes CFN see a replacement of a named resource, which it refuses: *"CloudFormation cannot update a stack when a custom-named resource requires replacing."* The fix is to **rename** the document — bump a version suffix (`V2 → V3 → …`) so CFN treats it as a new resource (old one deleted, new one created from the updated body).
- **When you change a runbook's logic, bump its version suffix in the same PR** in two places: the document name in `PHASE5_DOCUMENTS` (`infra/stacks/core_stack.py`) — which flows automatically to the `CfnDocument` name and the remediator's `ssm:StartAutomationExecution` grant ARNs via `ALL_DOCUMENT_NAMES` — and the matching `REGISTRY` value in `lambdas/remediator/handler.py`. Keep the document name and the REGISTRY value identical or dispatch breaks.

### Service detector authoring

- New service domains live in **parallel directories** under `lambdas/detectors/<service>/`, each mirroring `iam/`: `handler.py` (entry, with its own `REGISTRY`), `detectors/<rule>.py`, `requirements.txt`, and a sibling test tree under `lambdas/tests/detectors/<service>/`. Each service gets its **own** detector Lambda (`_iam_detector`, `_lambda_detector`, …) so a slow/broken service can't stall the others.
- **Python reserved-word collisions:** name the package `lambda_` (trailing underscore) because `lambda` is a keyword. The bundle mirrors the repo tree, so the handler path is `detectors.lambda_.handler.handler` and imports use `detectors.lambda_.detectors.<rule>`.
- **CloudWatch-metric-driven detectors:** when the signal is a metric, not a service API, query `cloudwatch:GetMetricStatistics` with `Period=86400`, `Statistics=["Sum"]`, over a window of `now - idle_days .. now` (the window comes from the rule threshold). "Unused" = `Sum == 0` over the window (no datapoints also sums to 0 → never invoked). Keep `details` values JSON/DynamoDB-safe — store integer `0`, never a float.
- **"Detector flags, runbook protects."** Detectors emit findings on the **primary signal** only (zero invocations); they never reason about downstream impact. The runbook adds **downstream-impact gates** that abort with a clear message before snapshot/delete — for `delete_unused_function.yml`: active event source mappings, a public function URL, or a resource policy granting invoke to external/cross-account sources. Each gate's `executeScript` exposes a pure helper (`_assert_no_mappings`, `_assert_no_url`, `_assert_internal_only`) so the gate logic is unit-tested in-process without boto3.
- A Lambda finding's snapshot is **two** S3 objects (the code `.zip` plus a `config.json` consolidating configuration, event-source mappings, function-URL config, and resource policy — enough to recreate via `lambda:CreateFunction`), both written **before** `deleteFunction`.

### Forecasting

- The framework supports **predictive findings** for quota-shaped rules. Today only `iam.policy_quota` is forecast-eligible (the only quota-shaped rule); the infrastructure generalizes to any future one.
- A forecast is emitted as a **separate finding** — `rule_id` ending in `.forecast_alert` (e.g. `iam.policy_quota.forecast_alert`) — never as an attribute on the current-state finding. The two have independent lifecycles, decisions, approvals, and audit trails. The current-state finding (`iam.policy_quota`) still fires only on an actual breach; the forecast finding fires when a breach is *projected* within `forecast.alert_at_days_remaining` days. Both can exist at once.
- **Model:** slope of the last 7 days (`shared.forecasting.compute_forecast`, stdlib-only linear regression), wrapped in four guards — `insufficient_data` (< 7 points in the 14-day window), `stable` (low value variance, or flat/decreasing slope), `no_clear_trend` (R² < 0.5), and `numeric`. **Only `numeric` produces an alert.** Confidence is from R²: >0.9 high, 0.7–0.9 medium, 0.5–0.7 low. Forecast computation lives **inside** the detector that produced the metric — no separate forecaster Lambda.
- **Forecast findings default to `prompt` with NO auto overrides** (`rules/iam.policy_quota.forecast_alert.yaml` — note the absence of any `Environment=nonprod → auto`). We will not delete a resource based on a *projection*: real breaches can auto-remediate, predicted ones get human review.
- Detectors write to `metric_history` on **every** scan (not just on breach) so history is complete. Points expire via DynamoDB TTL (30 days, attribute `ttl`); the table key is `pk=account#region#service#resource_arn`, `sk=ISO timestamp`. Use `tools/seed_metric_history.py` (a CLI helper, never deployed) to backfill synthetic points for demos.

### Notifications

- The **NotifierFunction** Lambda subscribes (via the `tidewater-notifier-rule` EventBridge rule on the `tidewater-events` bus) to `Finding.created` / `Finding.updated` / `remediation.failed` events, filters to the notification-worthy ones, dedupes per finding, formats a plain-text message, and publishes it to the `tidewater-notifications` SNS topic. It is the **sole** publisher to that topic (Phase 8 removed the Phase 2 raw fan-out rule), so subscribers get clean emails, not raw event JSON.
- **Only three categories notify:** HIGH-severity findings with `policy_decision == prompt` (security/compliance needing review), any `*.forecast_alert` finding (projection-based — always needs eyes), and `remediation.failed` events. Deliberately silent: MEDIUM/LOW severity, `auto`/`skip` paths, happy-path `remediation_started`/`remediation_completed`, `dispatch_deferred`, and `policy_decided` (audit-only). The EventBridge rule is broader than this (it can't express severity/decision logic); the filter lives in the Lambda.
- Because the detector emits a finding with `policy_decision=dry_run`, the **policy engine re-emits `Finding.updated`** with the decided value once it evaluates — that's the event the HIGH+prompt path actually fires on. The remediator emits `remediation.failed` on its failure path.
- **Dedupe** is by `finding_pk+sk` via the findings table's sparse `notified_at` attribute: a conditional `UpdateItem` claims a slot only if `notified_at` is unset or older than a 7-day staleness window (`STALENESS_DAYS`). This prevents re-emailing on every scan of the same unresolved finding. `notified_at` is owned **only** by the notifier — detectors and remediators never touch it.
- **Email subscribers are added manually post-deploy** (the topic is SNS; we don't hardcode addresses). Per address:
  1. AWS Console → SNS → Topics → `tidewater-notifications` → **Create subscription**.
  2. Protocol **Email**, Endpoint the recipient address → **Create subscription**.
  3. The recipient clicks **Confirm subscription** in the email AWS sends.
  Or via CLI: `aws sns subscribe --topic-arn <NotificationsTopicArn output> --protocol email --notification-endpoint you@example.com` (then confirm via email).
- This is the first step toward **multi-channel** notifications: Slack / PagerDuty / etc. are future subscribers on the same SNS topic (or future EventBridge targets), no notifier changes required for additional email recipients.

### Multi-rule remediation

- Multiple rules can flag the **same** resource (e.g. a nonprod role that is both unused and has an orphan trust principal). Each finding is decisioned independently, so two `auto` findings could otherwise dispatch remediations against one resource at once — and the faster runbook (e.g. `iam.unused_role` deleting the whole role) would yank the resource out from under the slower one (`iam.orphaned_trust`), risking a half-mutated state and confusing `remediation_failed` audit noise.
- The policy engine **serializes dispatches per-resource**. Before invoking the remediator for an `auto` finding it queries the findings table's `ResourceArnStatusIndex` GSI (`resource_arn` HASH, `status` RANGE) for any *other* finding on the same `resource_arn` already in `in_remediation`. If one exists, it **defers**: writes a `dispatch_deferred` audit event and returns without invoking the remediator. The finding stays `open` with its `auto` decision — there is **no** new status value; the only durable evidence of a deferral is the audit event.
- **POC reconvergence is eventual, not immediate.** The remediator does *not* poll for SSM completion or re-enqueue siblings (deliberately, to keep the Lambda cheap and the blast radius small). A deferred finding re-dispatches on its **next stream event**, which in the on-demand POC is the **next detector run** (the idempotent upsert refreshes `last_seen_at`, firing a MODIFY event); the engine re-checks for conflicts and, finding none, dispatches. Production may later add immediate reconvergence (runbook-emitted `finding.remediated` → re-bump siblings) — that's a future refactor.
- If the in-flight remediation **deleted** the resource, the deferred dispatch's runbook hits its own state guards (`assertRoleNotProtected`, `getRoleDetails` raising `NoSuchEntity`, etc.) and exits cleanly; the deferred finding remains open for a human to resolve.
- The policy engine needs `dynamodb:Query` on the findings table (covers `/index/*`) for this check — granted in `core_stack.py` and asserted by `test_synth_constraints.py`.

### Dashboard

- **Architecture:** a React+Vite+Tailwind SPA in `dashboard/`, served from the existing `DashboardSpaBucket` (S3) via the `DashboardDistribution` (CloudFront). API calls go to the existing HTTP API (`tidewater-api`) → **`DashboardApiFunction`** (one fat Lambda, internal route dispatch in `lambdas/dashboard_api/handler.py`) → DynamoDB/S3. Read-only: 6 GET routes (`/findings`, `/findings/{pk}/{sk}`, `/findings/{pk}/{sk}/audit`, `/findings/{pk}/{sk}/snapshot`, `/rules`, `/rules/{rule_id}`). **Approvals (`POST /approvals`) arrive in Phase 9b** — nothing here mutates state.
- **Auth:** the existing HTTP API Lambda authorizer (`lambdas/authorizer`, upgraded from its Phase 2 stub) validates `Authorization: Bearer <token>` against the SSM SecureString at `/platform-hygiene/poc/bearer-token` (`BEARER_TOKEN_PARAM`), generated once by the `BearerToken` custom resource and cached per warm container. The 6 dashboard routes inherit this as the API's default authorizer; `/health` stays public. The SPA prompts for the token on first load and stores it in `localStorage`; a 401/403 clears it and re-prompts.
- **First-deploy setup:** (1) `make deploy` (builds the SPA, syncs `dashboard/dist` → SPA bucket, invalidates CloudFront, and the bearer token is generated on first deploy); (2) `aws ssm get-parameter --name /platform-hygiene/poc/bearer-token --with-decryption --query Parameter.Value --output text` → copy it; (3) open the `DashboardUrl` output in a browser; (4) paste the token when prompted.
- **Token rotation:** `aws ssm put-parameter --name /platform-hygiene/poc/bearer-token --type SecureString --value $(openssl rand -base64 32) --overwrite` — all users must re-enter the new token.
- **Build pipeline:** the SPA BucketDeployment is gated on `dashboard/dist` existing, so `make synth`/CI (which don't build the frontend) keep the placeholder page; `make deploy` runs `make build-frontend` first so the real SPA ships. `dashboard/dist` is git-ignored — never commit the build output.
- **Adding a new route:** add a handler in `lambdas/dashboard_api/routes/` and register it in the `ROUTES` dict in `handler.py`; add the route to the HTTP API in `core_stack._api` (it inherits the bearer authorizer automatically). On the frontend, add a `src/pages/` view and wire its URL into the `react-router-dom` `Routes` in `App.tsx`.

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
