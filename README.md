# Tidewater

**Platform hygiene framework for AWS** — continuously detect, forecast, and (optionally) clean up operational cruft inside managed services.

> 🚧 **Status: pre-alpha POC under active construction.** Nothing here is production-ready. The auth model is intentionally insecure for demo purposes. Do not deploy publicly.

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

## License

MIT — see `LICENSE`.
