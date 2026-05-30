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

## Workflow

- All work happens on feature branches; PRs go to `main` (branch protection enforced).
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- Before opening a PR: `make lint && make test && make synth` must pass.
- `pre-commit` runs `gitleaks` on staged changes — do not bypass it.

## When unsure

If you're about to make a decision not covered by the locked choices above, ask the developer before coding. POC scope is tight; speculative additions blow the timeline.
