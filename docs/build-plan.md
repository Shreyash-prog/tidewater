# Tidewater — Build Plan

**Status:** Active
**Cadence:** Weekends-only, longer sessions (~4–6h per session)
**Review model:** Claude Code commits autonomously on phase branches; you review at the PR boundary
**Expected duration:** 6–8 weekends to a working demo

---

## How this plan works

The POC is broken into **11 phases**. Each phase is a self-contained branch + PR, designed to leave the repo in a deployable state at the end. You should be able to stop after any phase, come back next weekend, and pick up cleanly.

### Per-phase loop

1. You read the phase's "Goal" section and the prompt below it
2. You open Claude Code in the repo (`cd ~/code/tidewater && claude`)
3. You paste the prompt
4. Claude Code creates the branch, does the work, makes small focused commits, pushes the branch, opens a PR, and **stops**
5. You review the PR on GitHub (CI must be green; if not, ask Claude Code to fix)
6. You merge the PR, switch back to `main`, pull, and you're ready for the next phase

### Guardrails baked into every phase prompt

- One branch per phase, conventional commit messages, no force-pushing
- CI (lint + type-check + tests + `cdk synth`) must be green before opening the PR
- No new `pip install` or `npm install` of packages outside the locked stack
- No design decisions outside `architecture.md` — if Claude Code thinks it needs to deviate, it asks instead of guessing
- `cdk deploy` is **only** run when the phase says to deploy; otherwise everything stays local

### Pause and resume

If you stall for 6+ weeks, costs are still ~$0 but the credits clock keeps ticking. If life happens, run:

```bash
cd ~/code/tidewater && cdk destroy --all
```

When you resume:

```bash
cdk deploy PlatformHygiene-Core
cdk deploy PlatformHygiene-Fixtures
```

---

## Phases at a glance

| # | Phase | Estimated session | Output |
|---|---|---|---|
| 1 | Repo skeleton, Makefile, CI | 1 session | Empty repo structure, lint/test/CI all green |
| 2 | CDK CoreStack (empty resources) | 1 session | Deployable empty infra, $20 budget enforced |
| 3 | First end-to-end slice (one detector) | 1–2 sessions | One IAM rule finds & writes findings to DynamoDB |
| 4 | Policy engine + remediator + SSM runbook | 1–2 sessions | Auto/prompt/dry-run decisioning, real deletion via SSM |
| 5 | Remaining IAM detectors (5 more) | 1 session | Full IAM rule catalog |
| 6 | Lambda detectors (6 rules) | 1 session | Full Lambda rule catalog |
| 7 | FixturesStack (demo resources) | 1 session | 100 fake Lambdas, 30 IAM roles, deployed |
| 8 | OpenAPI spec + API Lambda | 1 session | Dashboard backend, generated TS client |
| 9 | Dashboard scaffold (Vite + Tailwind + shadcn + auth) | 1 session | Empty SPA deploys to CloudFront, auth works |
| 10 | Dashboard pages (Findings, Approvals, Rules) | 1–2 sessions | Functional UI, end-to-end approve flow |
| 11 | Forecaster + synthetic data + Forecasts page + demo polish | 1–2 sessions | Forecast charts, demo script, smoke test |

Total: **8–13 sessions**. You should plan for the high end — surprises happen.

---

## Phase 1 — Repo skeleton, Makefile, CI

### Goal

Establish the repo structure, dependency management, linting/typing/test toolchain, and GitHub Actions CI. **Zero AWS resources are created in this phase.** When this phase merges, anyone can clone the repo, run `make install && make lint && make test`, and get green.

### What "done" looks like

- `infra/`, `lambdas/`, `dashboard/`, `runbooks/`, `openapi/`, `docs/` directories exist with appropriate skeletons
- `pyproject.toml` at root with shared Ruff + mypy config
- A working `Makefile` with `install`, `lint`, `test`, `synth`, `deploy`, `destroy`, and `seed-history` targets (the AWS-touching ones can be no-ops until later phases fill them in)
- `infra/` is a valid CDK Python app that synthesizes (even if both stacks are empty)
- `lambdas/shared/models.py` exists with the Pydantic models from `architecture.md` §5
- `dashboard/` is a fresh Vite + React + TypeScript + Tailwind + shadcn project that builds (`npm run build` succeeds)
- `.github/workflows/ci.yml` runs lint + type-check + unit tests + `cdk synth` + dashboard build on every PR
- A pre-commit hook config (`.pre-commit-config.yaml`) wires Ruff + mypy + prettier
- The PR for this phase has CI green

### What's deliberately out of this phase

- Any actual CDK resources (Lambdas, tables, etc.) — those come in Phase 2
- Any actual detector logic — Phase 3
- The dashboard's pages — Phase 9–10
- The deploy GitHub Actions workflow — Phase 2 (since there's nothing to deploy yet)

### Prompt to paste into Claude Code

```
Read CLAUDE.md, docs/scope-poc.md, and docs/architecture.md in full before starting.

You are starting Phase 1 of the build plan in docs/build-plan.md: Repo skeleton, Makefile, CI.

Create a feature branch `phase/1-repo-skeleton`. Do all work on that branch with small, focused, conventional-commit messages (chore:, feat:, docs:, ci:, test: as appropriate). When the phase's "What done looks like" criteria are all met and CI is green, push the branch, open a PR with title "Phase 1: Repo skeleton, Makefile, CI", and stop. Do not start Phase 2.

Scope strictly to what Phase 1 in docs/build-plan.md describes. Do not create any AWS resources, do not add any business logic, do not write the API spec yet. The goal is a clean, well-typed, lintable scaffold.

Key requirements:
- Python 3.12, pip + requirements.txt per Lambda (no Poetry, no uv in production paths)
- The CDK app uses two stacks (CoreStack + FixturesStack); both can be empty class bodies for now, but cdk synth must succeed
- Ruff for lint + format; mypy in default mode with `disallow_untyped_defs = True`; type-stubs for boto3 services we'll use (iam, lambda, dynamodb, s3, events, sns, ssm, scheduler, cognito-idp, apigatewayv2)
- AWS Lambda Powertools is a dependency, even though no Lambdas use it yet
- Dashboard: Vite + React 18 + TypeScript + Tailwind + shadcn/ui initialized but no pages yet — just App.tsx renders "Tidewater" centered with shadcn-styled text
- Recharts and TanStack Query installed but unused so the Phase 9 install is just configuration
- pytest configured with a `tests/` directory at the root for cross-cutting tests, plus `lambdas/tests/` for Lambda-specific tests (one placeholder test in each so pytest doesn't error)
- GitHub Actions CI on PRs: jobs for `lint`, `typecheck`, `pytest`, `cdk-synth`, `dashboard-build`. All five must pass.
- Pre-commit config that runs Ruff + mypy + prettier locally (separate from CI)
- A `.env.example` file documenting any env vars the project will eventually need (none yet — file can just have a comment header)
- Updated README with quick-start instructions

Edge cases and decisions:
- If a tool requires a config file (Ruff, mypy, pytest, prettier, eslint), put it in pyproject.toml or the closest sensible location, not scattered
- If shadcn/ui init asks questions interactively, use sensible defaults (Default style, Slate, CSS variables enabled)
- If you discover a conflict with the locked stack in architecture.md, STOP and ask before deviating
- Lock dependency versions (use --upgrade-strategy=eager once, then commit the resolved versions)

When done, the PR description should list:
1. What this phase created (high-level)
2. Any decisions you made within the locked scope
3. How to verify locally: `make install && make lint && make test && make synth`

Do not deploy anything to AWS in this phase.
```

### After the PR merges

```bash
git checkout main && git pull
```

Run a quick local sanity check:
```bash
make install
make lint
make test
make synth
```

If all four succeed, Phase 1 is truly done. Move to Phase 2.

---

## Phase 2 — CDK CoreStack (empty resources)

### Goal

Stand up all the AWS infrastructure for the POC, with empty implementations. After this phase merges and `cdk deploy` runs, the account will contain: DynamoDB tables, S3 buckets, an EventBridge bus + scheduler, SNS topic, Cognito user pool placeholder, CloudFront + S3 for the dashboard (serving an empty page), API Gateway HTTP API (returning 200 from one health endpoint), and AWS Budgets with the $20 stop-action.

**This is the phase that first costs AWS money.** It should still be ~$0/month — all resources are pay-per-use and idle — but verify with `aws ce get-cost-and-usage` after 24 hours.

### What "done" looks like

- `cdk deploy PlatformHygiene-Core` succeeds from a clean clone
- All resources from `architecture.md` §3 exist as empty/stub forms
- AWS Budget `tidewater-poc-budget` is created with the stop-action on EventBridge Schedules (which don't exist yet, so the action is benign — but the wiring is testable)
- The deploy GitHub Actions workflow exists (manual trigger, OIDC-authenticated to AWS — no long-lived keys)
- A `/health` endpoint on the API returns 200 from a stub Lambda
- The CloudFront URL serves the Phase 1 "Tidewater" placeholder page
- The PR includes deploy instructions and a teardown command in the description

### Prompt to paste into Claude Code

```
Read CLAUDE.md, docs/architecture.md (especially §3 and §9), and the merged Phase 1 code before starting.

You are starting Phase 2 of docs/build-plan.md: CDK CoreStack — empty resources.

Create branch `phase/2-corestack-skeleton`. Build out the CoreStack with all resources from architecture.md §3, but with empty/stub implementations:
- DynamoDB tables (findings, approvals, metric_history, forecasts, rules_meta) with correct PK/SK design from §4
- S3 buckets: audit-log, snapshots, rules-yaml, dashboard-spa (with bucket policies for CloudFront OAC)
- EventBridge custom bus + EventBridge Scheduler (no schedules yet)
- SNS topic for downstream notifications
- API Gateway HTTP API with a single `/health` route returning 200
- One stub Lambda (the api/handler.py) handling /health with Powertools resolver, JSON-structured logging, 1-day log retention
- CloudFront distribution with the dashboard-spa S3 bucket as origin
- Lambda authorizer Lambda (stub — returns ALLOW for now; real validation in Phase 8)
- SSM Parameter Store entry `/platform-hygiene/poc/bearer-token` with a CDK-generated 32-byte random value (use cdk.SecretValue, not a hardcoded value; ensure it's marked as SecureString)
- AWS Budgets with $10 alert and $20 stop-action targeting EventBridge Scheduler

Also add:
- A new GitHub Actions workflow `.github/workflows/deploy.yml` triggered manually (workflow_dispatch), OIDC-authenticated to AWS, deploys CoreStack only
- The OIDC trust setup needs a one-time IAM role created via CDK (a separate "bootstrap" path or a clear README instruction — your choice, document it)
- README updates: how to deploy, how to find the bearer token after deploy (`aws ssm get-parameter --name /platform-hygiene/poc/bearer-token --with-decryption`), how to find the dashboard URL (`aws cloudformation describe-stacks ...`)
- Print the bearer token AND the dashboard URL at the end of `cdk deploy` via CfnOutput

Critical safety:
- All resources tagged with `Project=Tidewater` and `Environment=POC`
- All Lambdas have 1-day log retention (CloudWatch budget killer otherwise)
- No NAT Gateways anywhere
- DynamoDB tables on-demand billing
- Removal policy DESTROY on all stateful resources except snapshots-bucket (RETAIN — protects audit trail even on accidental teardown)

When CI is green, push and open the PR. Do NOT run `cdk deploy` yourself — that's the developer's job after PR review. Mention this clearly in the PR description.

The PR description should include:
1. Resources created (with rough CloudFormation count)
2. Estimated monthly cost at idle
3. Step-by-step deploy instructions for the developer
4. How to teardown: `cdk destroy --all` (and what won't be destroyed: snapshots-bucket)
```

### After the PR merges and you deploy

```bash
git checkout main && git pull
cdk deploy PlatformHygiene-Core
```

Wait for it to finish (~5–10 min first time). Then verify:

```bash
# Dashboard URL should render
curl -sI $(aws cloudformation describe-stacks --stack-name PlatformHygiene-Core \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue" --output text)

# Health endpoint should return 200
curl -s $(aws cloudformation describe-stacks --stack-name PlatformHygiene-Core \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text)/health

# Bearer token should be retrievable
aws ssm get-parameter --name /platform-hygiene/poc/bearer-token --with-decryption --query 'Parameter.Value'

# Budget should exist
aws budgets describe-budgets --account-id $(aws sts get-caller-identity --query Account --output text)
```

If all four work, Phase 2 is done. Wait 24 hours and check `aws ce get-cost-and-usage` to confirm idle cost is ~$0.

---

## Phase 3 — First end-to-end slice (one detector)

### Goal

Build the *full vertical slice* of the framework, end to end, for exactly one rule: `iam.unused_role`. Detector Lambda fires on schedule → finds unused roles → writes findings to DynamoDB → emits EventBridge event → SNS publishes. **No policy engine, no remediator yet.** This phase proves the bones.

### What "done" looks like

- `lambdas/shared/detector_base.py` implements the `Detector` ABC from `architecture.md` §6
- `lambdas/shared/rule_loader.py` reads rule YAML from the rules-yaml S3 bucket
- `lambdas/detectors/iam/` is implemented with `unused_role.py`
- An EventBridge Schedule triggers it hourly
- Findings land in the `findings` DynamoDB table with correct PK/SK
- An EventBridge event is published to the custom bus on every finding
- SNS topic receives the events (subscribed via EventBridge rule)
- pytest unit tests cover the detector with moto mocks
- One sample rule YAML in S3: `rules/iam.unused_role.yaml`
- An integration smoke test (`make smoke`) creates a known-unused role, triggers the detector manually, asserts a finding appeared

### Prompt to paste into Claude Code

(I'll write this prompt when Phase 2 merges. The Phase 3 prompt depends on choices Claude Code makes in Phase 2 that I want to see before specifying.)

---

## Phases 4 through 11

Phases 4–11 will be written one at a time, after the previous phase merges. This is deliberate: each phase's prompt depends on what got built in the previous phase, and writing all of them now would lock in assumptions that may not hold.

When you merge Phase 1, come back to this conversation with **"Phase 1 merged"** and I'll write the Phase 2 prompt. Then Phase 3 after Phase 2 merges. And so on.

---

## When to come back to this conversation

- After Phase 1 merges → "Phase 1 merged"
- If Claude Code asks a question you don't want to answer alone → paste it here
- If CI keeps failing in a way you can't diagnose → paste the failure here
- If you want to change scope mid-build → ask before letting Claude Code do it
- If costs spike unexpectedly → immediately, before anything else
