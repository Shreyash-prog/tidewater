# Platform Hygiene Framework — v1 Scope

**Status:** Locked
**Date:** 2026-05-28

---

## 1. Product summary

A configurable framework that tracks **operational hygiene rules** across AWS services — focusing on the soft, service-internal limits and accumulated cruft that AWS-native tools (Service Quotas, Trusted Advisor, Compute Optimizer) do not cover. Platform engineers describe what "clean" looks like; the framework continuously detects drift, forecasts when limits will be breached, and either auto-remediates or prompts a human, based on per-rule policy.

### Positioning vs. AWS-native

| Concern | AWS-native covers it? | We cover it? |
|---|---|---|
| Hard service quotas + auto-increase requests | Yes (Service Quotas Automatic Management, GA Oct 2025) | We surface them in one pane, but don't reimplement |
| Cost-flavored idle infrastructure (idle NAT, unused EBS) | Yes (Trusted Advisor / Compute Optimizer) | We surface them, don't reimplement |
| **Service-internal soft limits (idle DAGs, idle Lambdas, dead SNS subs, IAM bloat)** | **No** | **Yes — our primary value** |
| Auto-remediation with workflow nuance (approval, freeze windows, per-team policy) | Partially (AMS Trusted Remediator, paid + AMS-only) | Yes, open/self-hostable |

---

## 2. v1 scope decisions (locked)

| Decision | Choice |
|---|---|
| Deployment model | Self-hosted in customer's AWS account (CDK + Terraform); SaaS control plane on roadmap |
| Launch services | **IAM, Lambda, MWAA** (other 6 on public roadmap) |
| Remediation default | Auto-remediate based on tag/policy, prompt otherwise (Trusted Remediator–style) |
| Primary UI | Web dashboard, hosted in customer's account |
| Approval workflows | In v1 — table stakes |
| Forecasting | Linear extrapolation + seasonality detection (Prophet/ARIMA), accepting ML overhead |
| Account scope | Multi-account from v1 (one deployment monitors a whole AWS Organization) |
| Rule extensibility | Built-in catalog + custom rules via declarative YAML (no code) |
| Notifications | EventBridge + SNS only at v1; customer routes to Slack/PagerDuty/etc. themselves |

---

## 3. Launch service catalog (v1)

### IAM
- Roles with `iam:LastUsed` older than configurable threshold (default 90d)
- Access keys older than threshold and/or unused
- Roles attached to no principal / unused trust relationships
- Policies with `*:*` or overly broad wildcards (flag, don't auto-fix)
- Inline policy bloat per role/user/group (count + size approaching service limit)
- Managed policy attachment counts approaching per-entity limits

### Lambda
- Functions with zero invocations in N days (configurable)
- Unused function versions (versions with no alias, older than threshold)
- Per-region code storage approaching the 75 GB quota (forecast)
- Functions with no log activity but log groups still retained
- Reserved concurrency allocations on idle functions
- Dead-letter-queue configurations pointing to non-existent destinations

### MWAA
- DAGs paused for > N days
- DAGs with zero successful runs in N days
- Orphaned Airflow Variables and Connections (not referenced by any active DAG)
- DAG parse-time approaching scheduler tolerance (perf indicator, not a quota)
- `plugins.zip` and `requirements.txt` size trending toward MWAA limits
- Environments approaching worker/scheduler concurrency saturation
- Inactive users in the Airflow metadata DB

Each service ships with **~8–15 detectors** at GA. Out-of-the-box thresholds set to conservative defaults; everything overridable per rule, per account, per tag.

---

## 4. Architecture (high-level)

```
┌─────────────────────────────────────────────────────────────────────┐
│  Customer's "monitoring" AWS account (where framework is deployed)  │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │  Detector    │───▶│  Findings    │───▶│  Policy Engine       │   │
│  │  Lambdas     │    │  Store       │    │  (auto / prompt /    │   │
│  │  (per rule)  │    │  (DynamoDB)  │    │   skip per tag+rule) │   │
│  └──────┬───────┘    └──────────────┘    └──────────┬───────────┘   │
│         │                                           │               │
│         ▼                                           ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │  Forecaster  │    │  Approval    │    │  Remediator          │   │
│  │  (linear +   │    │  Workflow    │◀──▶│  (SSM Automation     │   │
│  │   Prophet)   │    │  (DynamoDB)  │    │   documents)         │   │
│  └──────────────┘    └──────┬───────┘    └──────────┬───────────┘   │
│                             │                       │               │
│                             ▼                       ▼               │
│  ┌─────────────────────────────────────┐   ┌───────────────────┐    │
│  │  Web dashboard (React + API GW)     │   │  EventBridge bus  │    │
│  │  - Findings view                    │   │  + SNS topics     │    │
│  │  - Approval queue                   │   │  (customer routes │    │
│  │  - Rule config (YAML editor)        │   │   downstream)     │    │
│  │  - Forecast charts                  │   └───────────────────┘    │
│  │  - Audit log                        │                            │
│  └─────────────────────────────────────┘                            │
└────────────────────┬────────────────────────────────────────────────┘
                     │ assumes IAM role in each spoke account
                     ▼
        ┌──────────────────────────────────────┐
        │  Spoke accounts (the ones monitored) │
        │  - read-only by default              │
        │  - elevated role for remediation     │
        │  - per-service scoped permissions    │
        └──────────────────────────────────────┘
```

### Components

- **Detector Lambdas** — one per rule (or one per service with sub-handlers). Triggered on a schedule (EventBridge Scheduler) and on-demand. Stateless; emit findings.
- **Findings Store** — DynamoDB. Keyed by `(account, region, service, resource_arn, rule_id)`. TTL on resolved findings.
- **Policy Engine** — evaluates each finding against config: which tags trigger auto-remediation, which require approval, which are dry-run only, which are skipped. Outputs an action (auto / prompt / dry-run / skip).
- **Forecaster** — separate Lambda or Fargate task. Reads time-series usage from CloudWatch + framework-internal counters. Linear extrapolation always runs; seasonality model runs only when ≥ 60 days of history available.
- **Approval Workflow** — Step Functions state machine. Receives prompts, manages reviewer assignment, timeouts, escalation, and final execute/cancel.
- **Remediator** — invokes SSM Automation documents per rule. All destructive actions go through SSM (auditable, reviewable runbooks). Never `boto3.delete_*` directly from Lambda code.
- **Web dashboard** — React SPA + API Gateway + Lambda. Cognito for auth. Hosted entirely in customer account.
- **EventBridge bus + SNS topics** — every finding, approval request, and remediation event published. Customer wires their own routing.

### Multi-account model

- Hub-and-spoke: monitoring account hosts the control plane; each monitored account has a thin CloudFormation stack that creates a cross-account role.
- StackSets recommended for org-wide rollout; manual install supported for non-Organizations setups.
- Read-only and write/remediate are **separate roles** — customer can install read-only first to evaluate, add the remediator role later.

---

## 5. Rule configuration model

Rules are declared in YAML. Built-in rules live in our packaged catalog; customer rules live in their Git repo and are loaded at startup + on file-change.

```yaml
# Example: built-in rule, overridden by customer
rule: lambda.idle_function
enabled: true
schedule: rate(6 hours)
threshold:
  idle_days: 60                # default was 90
forecast:
  enabled: true
  alert_at_days_remaining: 14
policy:
  default: prompt              # prompt | auto | dry_run | skip
  overrides:
    - match: { tag.Environment: nonprod }
      action: auto
    - match: { tag.Team: payments }
      action: prompt
      approvers: ["payments-platform@corp"]
    - match: { tag.Freeze: "true" }
      action: skip
notifications:
  channels: [eventbridge, sns]
  sns_topic: arn:aws:sns:...:platform-hygiene-alerts
```

Schema validated at load time; bad config fails closed (no rules loaded for that file, alert raised).

---

## 6. Safety guarantees

These are non-negotiable design constraints:

1. **Dry-run is the default mode** on first install. Customer flips rules to `auto` deliberately.
2. **All destructive actions run via SSM Automation documents** — versioned, reviewable, with `--check` semantics.
3. **A 14-day grace period** between first detection and any remediation, for every rule. Tunable, but the default protects against rules misfiring on fresh installs.
4. **Per-account rate limits** on remediation actions (default: max 10 destructive actions per account per hour). Prevents runaway loops.
5. **Tag-based exclusion** (`hygiene:skip=true`) is always honored, regardless of other policy.
6. **Full audit log** in CloudTrail + framework's own audit table — every action, every approval, every config change.
7. **Rollback hints surfaced where feasible** — e.g., for IAM role deletion, framework snapshots the role + policies + trust doc to S3 before deletion, with a 30-day retention.

---

## 7. Out of scope for v1

Explicit non-goals — to keep us honest:

- Other 6 services (SNS/SQS, EventBridge, Step Functions, Glue, API Gateway, ECR)
- SaaS hosted control plane
- Custom rule authoring via code (Python plugin SDK)
- Native Slack / Teams / PagerDuty integrations (customer wires via SNS)
- Cost attribution per finding (roadmap — useful but not v1)
- Cross-cloud (GCP, Azure)
- Reimplementing what Service Quotas Automatic Management already does for hard quotas — we surface its data, we don't replace it
- A mobile app
- AI-driven rule suggestions

---

## 8. Success criteria for v1

A v1 launch is successful if:

- A platform engineer can install in ≤ 30 minutes for a single account, ≤ 2 hours for an organization
- The 3 launch services ship with ≥ 30 working detectors total
- A new YAML rule can be added and live within 1 minute
- Dashboard renders findings, forecasts, and approval queue with < 2s load on 10k findings
- Zero customer-reported destructive false positives in the first 90 days post-GA (proxy: dry-run output reviewed before any auto enabled)
- Documentation includes a runbook for every built-in rule explaining what it detects, what it deletes, and how to roll back

---

## 9. Open questions (to resolve before build)

These didn't need to block scope-lock, but the team should answer them in the first sprint:

1. **Pricing model** when SaaS layer arrives — per-account, per-finding, per-remediation, or flat?
2. **Auth for the dashboard** — Cognito only, or also IAM Identity Center / SAML to enterprise IdPs from day one?
3. **Rule versioning** — when we update a built-in rule's logic, how do we handle customers who pinned the old behavior?
4. **Backfill** — when a customer first installs, do we mark existing 90-day-idle Lambdas as findings immediately (alarming) or start the clock from install time (safe but slow)?
5. **Org vs. account-level policy precedence** — when both define a rule, who wins? (Proposed: account overrides org, with org able to lock specific rules.)

---

## 10. Roadmap (post-v1, indicative)

- **v1.1**: SNS/SQS + EventBridge service coverage
- **v1.2**: Cost attribution per finding; native Slack integration
- **v2.0**: SaaS control plane; SAML SSO; custom rules via Python SDK
- **v2.1**: Step Functions + Glue + API Gateway + ECR service coverage
- **v3.0**: Cross-cloud (start with GCP)
