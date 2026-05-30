# Platform Hygiene Framework — POC Scope

**Status:** Locked
**Date:** 2026-05-29
**Parent doc:** `scope-v1.md`

This document captures the POC (proof-of-concept) scope, which is a deliberately narrowed subset of the v1 scope. Cuts are listed explicitly so they can be reversed for v1.

---

## 1. POC goal

Prove the **framework pattern** end-to-end on a small budget, in a fresh AWS Free Tier account, in a form that can be demonstrated via screen-share to one or two people.

The POC must show:

1. Detectors finding real issues in real (synthetic) AWS resources
2. The YAML-driven rule + policy engine deciding auto-remediate vs. prompt
3. A working dashboard with findings, forecast charts, an approval queue, and an audit log
4. A real (auto or approved) remediation actually deleting/modifying a resource
5. Events flowing out via EventBridge + SNS

The POC does **not** need to prove enterprise readiness, multi-account scale, or forecast accuracy on real data.

---

## 2. Hard constraints

| Constraint | Value |
|---|---|
| Monthly AWS cost ceiling | **$20** (hard limit via AWS Budgets action) |
| Budget alarm threshold | **$10** (email + Slack via SNS) |
| Environment | Fresh AWS Free Tier account |
| Regions | `us-east-1` only (cheapest, all services available) |
| Audience | Screen-share demo to 1–2 people |

---

## 3. POC scope vs. v1 scope

| Area | v1 scope | POC scope | Reversed for v1? |
|---|---|---|---|
| Launch services | IAM, Lambda, MWAA | **IAM + Lambda only** | Yes — MWAA in v1 |
| Deployment | Self-hosted, customer's account | Single account, single region | Yes |
| Multi-account | Hub-and-spoke org-wide | Single account only | Yes |
| Remediation default | Auto-with-prompt-fallback (Trusted Remediator–style) | **Same**, but no Step Functions | Yes (SF added in v1) |
| Approval workflows | Step Functions state machine, reviewer assignment, escalation, timeouts | **DynamoDB row + dashboard Approve/Reject buttons** | Yes |
| Forecasting | Linear + seasonality (Prophet) | **Linear + seasonality** *(with synthetic backfill — see §7)* | N/A — kept |
| Rule extensibility | Built-in catalog + custom YAML | **Same** | N/A |
| Notifications | EventBridge + SNS | **Same** | N/A |
| Approval UI | Dashboard | **Same** | N/A |
| Safety guardrails | Dry-run default, 14d grace, rate limits, audit log, snapshot before delete | **Same** (these are cheap to implement and critical for demo credibility) | N/A |

### Why MWAA was dropped from the POC

MWAA's smallest production environment is **~$355/month**; `mw1.micro` is **~$80–120/month**; even MWAA Serverless has minimum charges. Any MWAA usage immediately breaks the $20 ceiling. MWAA is shown in the demo as "here's where the next adapter plugs in" — the architecture has a service-adapter interface; one is implemented (Lambda+IAM), MWAA is a stub.

---

## 4. POC service catalog

Aim for **~12 working detectors total** — enough to make the dashboard feel real.

### IAM (6 detectors)
1. Roles with `iam:LastUsed` older than threshold (default 90d → POC default 7d to make findings appear quickly)
2. Access keys older than threshold AND with `LastUsedDate` > N days ago
3. Roles with no trust relationship principals that exist
4. Unused customer-managed policies (no attachments)
5. Inline policies with `*:*` action (flag-only, never auto-remediate — too dangerous)
6. Roles approaching attached-policy quota (10 managed policies)

### Lambda (6 detectors)
1. Functions with zero invocations in N days (CloudWatch `Invocations` metric)
2. Function versions with no alias, older than N days
3. Per-region deployment-package storage approaching 75 GB quota *(this is where the forecasting demo shines)*
4. Functions with `ReservedConcurrentExecutions` set but zero invocations
5. Functions with a DLQ ARN that no longer exists
6. Log groups for deleted functions

### Remediation runbooks (SSM Automation documents)
- `delete-iam-role` (with snapshot to S3 first)
- `delete-iam-access-key` (with 7-day "deactivate first, delete later" mode)
- `detach-unused-policy`
- `delete-lambda-version`
- `delete-orphaned-log-group`
- IAM-roles-with-wildcards is **flag-only** — no auto-remediation runbook

---

## 5. Architecture (POC)

Simpler than v1. No Step Functions, no StackSets, single account.

```
┌──────────────────────────────────────────────────────────────────┐
│  Single AWS account (us-east-1)                                  │
│                                                                  │
│  ┌─────────────────────┐                                         │
│  │  EventBridge        │  triggers detectors on schedule         │
│  │  Scheduler          │  (every 1h for POC, configurable)       │
│  └──────────┬──────────┘                                         │
│             ▼                                                    │
│  ┌─────────────────────┐    ┌───────────────────────────────┐    │
│  │  Detector Lambdas   │───▶│  Findings table (DynamoDB)    │    │
│  │  (one per service,  │    │  PK: account#region#service   │    │
│  │   sub-handler per   │    │  SK: resource#rule_id         │    │
│  │   rule)             │    │  TTL on resolved              │    │
│  └─────────────────────┘    └──────────────┬────────────────┘    │
│                                            ▼                     │
│  ┌────────────────────────────────────────────────────────┐      │
│  │  Policy Engine Lambda                                  │      │
│  │  - reads rule YAML (S3) + finding                      │      │
│  │  - evaluates tag overrides                             │      │
│  │  - decides: auto | prompt | dry_run | skip             │      │
│  └─────────┬─────────────────────────────┬────────────────┘      │
│            │ auto                        │ prompt                │
│            ▼                             ▼                       │
│  ┌─────────────────────┐    ┌─────────────────────────────┐      │
│  │  Remediator Lambda  │    │  Approval table (DynamoDB)  │      │
│  │  - invokes SSM doc  │    │  - shown in dashboard       │      │
│  │  - snapshots first  │    │  - Approve → Remediator     │      │
│  └─────────┬───────────┘    └─────────────────────────────┘      │
│            │                                                     │
│            ▼                                                     │
│  ┌─────────────────────┐                                         │
│  │  Audit log (S3)     │  every action, JSON Lines               │
│  └─────────────────────┘                                         │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  Forecaster Lambda                                      │     │
│  │  - daily run                                            │     │
│  │  - linear extrapolation from real DynamoDB time-series  │     │
│  │  - seasonality model fed by SYNTHETIC 90d backfill      │     │
│  │  - writes forecasts to DynamoDB                         │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  Dashboard                                              │     │
│  │  - S3 + CloudFront (React SPA)                          │     │
│  │  - API Gateway HTTP API + Lambda backend                │     │
│  │  - Cognito user pool (1 user, you)                      │     │
│  │  - Pages: Findings, Approvals, Rules, Forecasts, Audit  │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  EventBridge bus + SNS topic                            │     │
│  │  - publishes finding.created, finding.remediated,       │     │
│  │    approval.requested, approval.approved/rejected       │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  AWS Budgets                                            │     │
│  │  - $10 alarm via SNS (email)                            │     │
│  │  - $20 ceiling with budget action: stop EventBridge     │     │
│  │    Scheduler so detectors stop firing                   │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  Demo fixtures (deployed on POC install)                │     │
│  │  - 100 idle Lambda functions (no code, no invocations)  │     │
│  │  - 30 IAM roles with various violations                 │     │
│  │  - 5 unused access keys                                 │     │
│  │  - synthetic 90d history in DynamoDB for forecaster     │     │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 6. Cost model

Estimated monthly AWS spend, sized for the POC:

| Component | Service | Est. cost | Notes |
|---|---|---|---|
| Detector triggers | EventBridge Scheduler | $0 | Free tier 14M invocations |
| Detector + policy + remediator | Lambda | $0 | Tiny fn count × hourly schedule, free tier easily |
| Findings + approvals | DynamoDB on-demand | <$1 | Few MB, on-demand pricing |
| Forecaster | Lambda | $0 | Daily run, low memory |
| API + dashboard backend | API Gateway HTTP + Lambda | <$1 | Free tier covers POC traffic |
| Frontend hosting | S3 + CloudFront | <$1 | Static SPA, near-zero traffic |
| Auth | Cognito | $0 | Free tier 50k MAU |
| Audit log | S3 | <$0.50 | JSON Lines, KB/day |
| Notifications | SNS + EventBridge bus | $0 | Free tier |
| CloudWatch logs | CloudWatch | $1–3 | **Risk variable — see §8** |
| Fake Lambdas | Lambda | $0 | Zero invocations |
| Fake IAM roles | IAM | $0 | IAM is free |
| **Estimated total** | | **$3–7/mo** | |

The $20 budget gives a 3×–6× safety margin over the realistic estimate.

---

## 7. Synthetic data plan (for seasonality demo)

To demo the seasonality forecaster without 90 days of real history:

- On POC install, a one-time bootstrap Lambda writes 90 days of synthetic time-series data into a `metric_history` DynamoDB table.
- Data has a clear weekly seasonality (e.g., Lambda function count grows fast on weekdays, flat on weekends) and a small upward trend.
- The forecaster runs on this synthetic data and produces a 30-day forward forecast with weekly seasonality visible.
- Real, live detector findings stream into the same table going forward — so the demo shows synthetic-past blending into real-present.

**Acknowledged demo risk:** A technical viewer asking "is that real data?" gets the honest answer: "The 90-day history is synthetic to demo the capability; in production this is fed by real telemetry." Slide-deck framing matters here.

---

## 8. Cost guardrails (concrete)

Beyond the AWS Budgets alarm and ceiling, four operational rules:

1. **Log retention = 1 day** on every Lambda log group. CloudWatch ingestion is the only realistic budget killer.
2. **Detector schedule = `rate(1 hour)`** by default; reducible to `rate(15 minutes)` only for demo purposes, never left there.
3. **No provisioned concurrency** on any Lambda.
4. **No NAT Gateways.** All Lambdas run outside a VPC. (A NAT Gateway alone is ~$32/month and would blow the budget by itself.)

AWS Budgets action at $20 stops EventBridge Scheduler rules — detectors halt, no further cost accrues, dashboard still works for review.

---

## 9. Build plan (rough)

Sized for one developer, evenings/weekends. Adjust to your actual availability.

| Phase | Duration | Output |
|---|---|---|
| **1. Infra skeleton** | 3–4 days | CDK app deploys: empty Lambdas, DynamoDB tables, S3 buckets, API Gateway, Cognito, EventBridge bus, AWS Budgets |
| **2. First detector + finding** | 2–3 days | One Lambda detector working end-to-end (IAM unused-role), writing to findings table |
| **3. Policy engine + remediator** | 3–4 days | YAML rule loading, tag-based policy decision, SSM Automation doc invocation, audit log to S3 |
| **4. Dashboard MVP** | 4–5 days | React SPA: findings list, approval queue with Approve/Reject, audit log view |
| **5. Remaining 11 detectors** | 4–6 days | Build out IAM + Lambda detector catalog |
| **6. Forecaster + synthetic data** | 3–4 days | Linear + Prophet, synthetic backfill bootstrap, dashboard forecast charts |
| **7. Demo fixtures + polish** | 2–3 days | Fixture stack (100 fake Lambdas, 30 IAM roles), README, demo script, screen-share dry-run |
| **Total** | **~3–5 weeks** of evenings, or ~2 weeks full-time | |

---

## 10. Demo script (what gets screen-shared)

A working demo flow that hits every framework feature:

1. **Open dashboard** → show 47 findings across 12 rule types. (We pre-seeded these via the fixture stack.)
2. **Click on "Unused IAM role" finding** → show the resource details, the policy decision (`prompt` — Production-tagged), the rule YAML config.
3. **Approve the finding** → SSM Automation document runs in a sub-window, snapshot lands in S3, role gets deleted, audit log updates live.
4. **Show the Forecasts page** → "Lambda function count, your account ceiling is 1000, current 412, growing 5/day, forecast says you'll hit 800 (alert threshold) in 78 days." Weekly seasonality visible in the chart.
5. **Edit a rule's YAML** in the dashboard → save → show the file landed in S3 → next detector run uses the new threshold. (Or: trigger a manual run to skip the wait.)
6. **Show the audit log** → every action of the last 5 minutes.
7. **Show the SNS topic** → "anything emitted here, you route to Slack/PagerDuty/whatever."
8. **Closing slide**: roadmap, with MWAA as the visible next adapter and SaaS control plane after that.

Target demo length: **8–12 minutes**.

---

## 11. Out of scope for POC (explicit)

- Multi-account / AWS Organizations
- StackSets-based deployment
- Step Functions for approvals
- Approval timeouts, reviewer assignment, escalation logic
- Native Slack / Teams / PagerDuty (customer wires via SNS)
- Custom rules via Python SDK (only built-in + YAML overrides)
- MWAA adapter
- Other 6 services (SNS/SQS, EventBridge, SF, Glue, API GW, ECR)
- Real production traffic, real load, real customers
- Production-grade IAM least privilege (POC uses scoped-but-not-minimal roles)
- Federated identity / SAML / SSO
- The cost-attribution feature
- The "rollback hints" UX (we snapshot to S3, but the restore flow is documented, not built)

---

## 12. Definition of done

The POC is done when:

- [ ] `cdk deploy` from a fresh clone, on a fresh AWS account, ends with a working dashboard URL in ≤ 15 minutes
- [ ] AWS Budgets shows $10 alarm + $20 stop action configured
- [ ] Demo script can be executed end-to-end without errors in a screen-share
- [ ] All 12 detectors produce at least 1 finding each on the demo fixtures
- [ ] At least one rule auto-remediates and one prompts (showing both modes)
- [ ] Forecast chart renders for at least one rule with visible seasonality
- [ ] Audit log shows every action of the demo session
- [ ] EventBridge bus + SNS topic visibly emit at least one event during the demo
- [ ] One full week of unattended running stays under $5 of actual spend
- [ ] README explains: install, demo flow, teardown, known limitations
