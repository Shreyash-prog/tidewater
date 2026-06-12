# Tidewater

**Platform hygiene framework for AWS** — continuously detect, forecast, and (optionally) clean up operational cruft inside managed services.

> 🚧 **Status: pre-alpha POC under active construction.** Nothing here is production-ready. The auth model is intentionally insecure for demo purposes. Do not deploy publicly.

## Live Demo

A live deployment of Tidewater is running in my AWS account. You can browse the dashboard read-only to see findings, rules, and the framework's accumulated state.

**URL:** https://d2o52kqdxzqimw.cloudfront.net

**Bearer token:** `HwdbqPW9T8HFIn1j6e0xr3H_wlmCOyu74PjhSEAEImw`

### How to access

1. Open the URL above in your browser
2. When prompted, paste the bearer token shown above
3. The dashboard loads with the Findings view by default

### What you'll see

**Findings view** (default): a table of every detection the framework has made, with columns for severity, service, rule, resource, status, decision, and timestamp. The data is live — these are real findings from real AWS resources in my account.

You'll see a mix of:

- `lambda.unused_function` findings — the framework detecting its own AWS Lambda functions as idle (it correctly observes its own infrastructure; the meta-detection is intentional)
- `iam.unused_role` findings — IAM roles that haven't been used recently
- `iam.unused_policy` findings — managed policies attached to nothing
- `iam.policy_quota.forecast_alert` findings — predictive alerts where a role's attached-policy count is trending toward the IAM hard limit of 10

Findings carry one of three decisions:

- `auto` — the framework will auto-remediate (e.g., `iam.unused_role` for `Environment: nonprod` resources)
- `prompt` — waiting for human review (most findings)
- `skip` — explicitly excluded via tags

And one of four statuses: `open`, `in_remediation`, `resolved`, `skipped`.

**Filter sidebar**: filter findings by severity (high / medium / low), service (iam / lambda), status, or rule_id text.

**Click any finding** to see its full detail page — the metadata, the JSON details from the detector, the audit log trail showing every state transition, and (for findings that triggered auto-remediation) a button to download the resource snapshot that was captured before deletion.

**Rules view** (sidebar nav): cards for each of the 8 currently-loaded rules. Click any rule to see its YAML — threshold, forecast config, policy decision logic, and tag-based overrides.

### What's NOT available in the demo

This deployment is at Phase 9a — the read-only dashboard. Phase 9b (approve/reject buttons for `prompt` findings) is the next phase but not yet deployed; the dashboard is currently view-only.

### What was built

Across the framework's phases:

- **7 detectors** across 2 AWS services (IAM and Lambda)
- **5 destructive remediation runbooks** via SSM Automation, all snapshot-protected (the resource configuration is saved to S3 before deletion)
- **Multi-rule race serialization** so a resource flagged by two rules doesn't get conflicting decisions
- **Quota forecasting** with last-7-days linear regression and four abstention guards (insufficient_data / stable / no_clear_trend / numeric)
- **Email notifications** for high-severity findings, forecast alerts, and remediation failures, with finding-level deduplication
- **This dashboard** — the operator-visible surface

### Notes

- The bearer token authenticates browser access to the API. It's POC-grade auth; production would use Cognito or org SSO.
- The token may be rotated periodically. If it stops working, check this README for the latest value.
- The demo deployment may be taken down at any time.
- For questions or to discuss the architecture, please reach out via [your contact link — replace with your actual contact info].

## What this is

Tidewater watches for "soft" operational limits and accumulated cruft that AWS-native tools (Service Quotas, Trusted Advisor, Compute Optimizer) don't cover:

- Unused IAM roles, stale access keys, policy bloat
- Idle Lambda functions, orphaned versions, dead DLQ destinations
- (Roadmap) Inactive MWAA DAGs, dead SNS subscriptions, orphaned EventBridge rules, and more

Findings flow through a configurable policy engine that either auto-remediates (by tag/policy) or prompts the platform engineer for approval.

## POC scope

- **Services**: IAM + Lambda only (MWAA and 6 others are on the roadmap)
- **Deployment**: single AWS account, single region, self-hosted
- **Budget guardrail**: hard ceiling of $20/month via AWS Budgets
- **Auth**: pre-shared bearer token (POC-grade, see security note)

## Repo layout

```
infra/      AWS CDK in Python — OidcStack + CoreStack + FixturesStack
lambdas/    Python 3.12 Lambdas — detectors, policy engine, remediator, forecaster, API
runbooks/   SSM Automation documents for each remediation
dashboard/  React + TypeScript + Vite + Tailwind + shadcn/ui
openapi/    Hand-edited API spec, generated TS client
docs/       Scope, architecture, build plan, demo script
```

## Quick start (local development)

Prerequisites: **Python 3.12**, **Node 20**, and the **AWS CDK CLI** (`npm i -g aws-cdk`)
on your `PATH`. No AWS account or credentials are needed for Phase 1 — nothing
deploys yet.

```bash
make install   # create .venv, install Python + dashboard deps
make lint      # Ruff check + format check (Python), Prettier check (dashboard)
make test      # pytest + dashboard typecheck
make synth     # cdk synth — sanity-check the (empty) CDK app
```

`make help` lists every target. `make seed-history` is an intentional no-op
until Phase 11. Deploy targets (`make deploy`, `make deploy-oidc`, `make destroy`)
are live as of Phase 2 — see **Deploying** below.

## Deploying

Phase 2 creates real AWS resources (all pay-per-use; ~$0/month idle). Region is
`us-east-1` only. A $20 AWS Budget with a 100% stop-action is the cost backstop.

Budget alerts and SNS notifications are sent to the `notification_email` CDK
context value (defaults to the AWS account owner, `shreyashkalalwork@gmail.com`,
and is committed in `cdk.context.json`). Override per deploy with
`cdk deploy -c notification_email=you@example.com`.

### Deploying for the first time

1. **Bootstrap CDK** (once per account/region): `cdk bootstrap aws://<account>/us-east-1`
2. **Deploy the OIDC stack from your laptop** (CI can't — the deploy role doesn't
   exist yet):
   ```bash
   make deploy-oidc        # cdk deploy PlatformHygiene-Oidc
   ```
3. **Wire CI to the deploy role.** Copy the `DeployRoleArn` output and set it as a
   GitHub Actions repository **variable** (not a secret — an ARN isn't sensitive):
   ```bash
   gh variable set AWS_DEPLOY_ROLE_ARN --body "<DeployRoleArn from step 2>"
   ```
4. **Deploy CoreStack** — locally or from CI:
   ```bash
   make deploy             # or: trigger the "Deploy CoreStack" GitHub Actions workflow
   ```

### Deploying changes

Run `make deploy` locally, or trigger the **Deploy CoreStack** workflow
(`workflow_dispatch`). Both deploy `PlatformHygiene-Core` via the OIDC role.

> **POC security note:** the deploy role uses `AdministratorAccess`. Production
> must scope this to least privilege.

### After deploy

```bash
# Bearer token (copy into the dashboard on first load)
aws ssm get-parameter --name /platform-hygiene/poc/bearer-token \
  --with-decryption --query Parameter.Value --output text

# Dashboard URL
aws cloudformation describe-stacks --stack-name PlatformHygiene-Core \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue" --output text

# Health endpoint
curl -s "$(aws cloudformation describe-stacks --stack-name PlatformHygiene-Core \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text)/health"
```

### Teardown

```bash
make destroy            # cdk destroy --all
```

The `audit-log` and `snapshots` buckets have a **RETAIN** removal policy and
**survive teardown** (they hold the audit trail and pre-deletion snapshots);
delete them by hand if you really want them gone. Everything else is removed.

## Maintenance

### Powertools layer version

The AWS Lambda Powertools layer ARN is resolved at synth time from the public SSM
parameter `/aws/service/powertools/python/arm64/python3.12/latest` (via CDK
`value_from_lookup`) and cached in the committed `cdk.context.json`. CI synth
reads the cached value, so it needs no AWS credentials. To pick up a newer
Powertools release:

```bash
make refresh-powertools   # needs AWS creds; rewrites cdk.context.json
```

Commit the updated `cdk.context.json`. `cdk diff` will then show the layer
version change clearly.

### Repo conventions

- **Branches & commits:** feature branch per phase, [Conventional Commits](https://www.conventionalcommits.org/),
  PRs into `main`.
- **Pre-commit:** run `make install` once, then commits automatically run
  gitleaks (secret scan) plus Ruff, mypy, and Prettier. The repo uses
  `core.hooksPath=.githooks`; the gitleaks hook delegates to `pre-commit run`,
  so there's no separate `pre-commit install` step. Do not bypass these hooks.
- **Toolchain:** Ruff (lint + format), mypy (`disallow_untyped_defs`), pytest,
  CDK in Python. Config lives in `pyproject.toml` (Python) and `dashboard/`
  (TypeScript). Dependency versions are pinned.

### Layout notes

- Python import roots are `lambdas/` and `infra/` (e.g. `from shared.models import …`).
- Per-Lambda runtime deps live in each Lambda's `requirements.txt`; the dev
  toolchain lives in `requirements-dev.txt`.

## Documentation

See `docs/`:

- `scope-v1.md` — the eventual v1 product scope
- `scope-poc.md` — what this POC actually delivers
- `architecture.md` — technical decisions and design
- `build-plan.md` — phase-by-phase build sequence

## Security note

This POC uses a pre-shared bearer token stored in browser localStorage for dashboard auth. This is deliberately simple for demo purposes and **must not** be exposed to the public internet. The roadmap moves auth to AWS Cognito.

## POC vs Production

Several settings are tuned for a fast, self-contained demo and are **intentionally
unsafe for real accounts**. They're consistent with the "do not deploy publicly"
guidance above — flip them before any production use:

| Setting | POC (demo) | Production |
|---|---|---|
| `iam.unused_role` `threshold.idle_days` | **-1** (flags any role idle ≥ 0 days, so create→detect→remediate runs in seconds) | 7–90 days |
| `iam.unused_role` `grace_period_days` | **0** (auto-remediates immediately) | ≥ 14 days |
| Policy override `Environment=nonprod` | **auto** (auto-remediates nonprod roles) | `prompt` (human review/approval) |
| Dashboard auth | Pre-shared bearer token in `localStorage` | AWS Cognito |

The rule values live in `infra/initial_rules/iam.unused_role.yaml`; the demo-only
defaults are pinned by `infra/tests/test_initial_rules.py` so changing them is a
deliberate, reviewed act.

## License

MIT — see `LICENSE`.
