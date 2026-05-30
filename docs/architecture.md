# Platform Hygiene Framework — POC Architecture & Design

**Status:** Locked
**Date:** 2026-05-29
**Parent docs:** `scope-v1.md`, `scope-poc.md`

This document captures the technical decisions, repo layout, and design conventions for the POC. Everything here is downstream of decisions already locked in the scope docs.

---

## 1. Technology stack (locked)

### Backend
| Layer | Choice |
|---|---|
| Language | **Python 3.12** |
| Lambda framework | **AWS Lambda Powertools** (logging, tracing, metrics, parameters, event handlers) |
| Detector pattern | **Custom `Detector` base class** built on Powertools + boto3 |
| Data validation | **Pydantic v2** for all internal models |
| Dependency mgmt | **pip + `requirements.txt`** (one per Lambda's deployment package) |
| Lint / format | **Ruff** (`ruff check` + `ruff format`) |
| Type checking | **mypy default + `disallow_untyped_defs = True`** (with `boto3-stubs[iam,lambda,dynamodb,s3,events,sns,ssm,scheduler,cognito-idp,apigatewayv2]`) |
| Unit tests | **pytest + moto** for detectors; pytest for the rest |
| Integration tests | **One smoke test** that runs against deployed `FixturesStack` post-deploy |

### Frontend
| Layer | Choice |
|---|---|
| Framework | **React 18 + TypeScript 5 + Vite 5** |
| Styling | **Tailwind CSS + shadcn/ui** |
| Charts | **Recharts** |
| API client | **OpenAPI-generated TypeScript client** (`openapi-typescript` + `openapi-fetch`) |
| Auth (POC) | **Pre-shared bearer token** in localStorage, validated by a Lambda authorizer |
| State mgmt | **TanStack Query** for server state; React `useState` for local |
| Routing | **React Router 6** |
| Hosting | **S3 + CloudFront** (static SPA) |

### Infrastructure
| Layer | Choice |
|---|---|
| IaC | **AWS CDK v2 in Python** |
| Stack layout | **Two stacks**: `CoreStack` + `FixturesStack` |
| API layer | **API Gateway HTTP API** |
| Compute | **Lambda** (no containers, no EC2, no Fargate) |
| Database | **DynamoDB on-demand** |
| Object storage | **S3** (audit logs, snapshots, rule YAMLs, demo fixtures bootstrap data) |
| Scheduling | **EventBridge Scheduler** |
| Eventing | **EventBridge custom bus** + **SNS topic** |
| Runbooks | **SSM Automation documents** |
| Cost guardrails | **AWS Budgets** with budget action stopping EventBridge Schedules at $20 |
| Secrets | **SSM Parameter Store** (`SecureString`) — never env vars, never source |
| Region | **`us-east-1` only** |

### CI/CD & repo hygiene
| Layer | Choice |
|---|---|
| Repo structure | **Monorepo**: `/infra`, `/lambdas`, `/dashboard`, `/runbooks`, `/docs` |
| CI | **GitHub Actions** from day one |
| Versioning | **Date-based tag** (e.g., `poc-2026-05-29-001`) on every deploy |
| Pre-commit | Ruff + mypy + prettier (dashboard) |

---

## 2. Repository layout

```
platform-hygiene/
├── README.md                       # install + demo + teardown
├── pyproject.toml                  # ruff + mypy config (shared)
├── .python-version                 # 3.12
├── .pre-commit-config.yaml
├── .github/
│   └── workflows/
│       ├── ci.yml                  # lint + typecheck + tests + cdk synth on PR
│       └── deploy.yml              # manual-trigger deploy to AWS
├── docs/
│   ├── scope-v1.md
│   ├── scope-poc.md
│   ├── architecture.md             # this doc
│   ├── demo-script.md
│   └── runbooks/                   # one per remediation
├── infra/                          # CDK app
│   ├── app.py                      # entrypoint
│   ├── requirements.txt
│   ├── stacks/
│   │   ├── __init__.py
│   │   ├── core_stack.py
│   │   └── fixtures_stack.py
│   ├── constructs/
│   │   ├── __init__.py
│   │   ├── detector_lambda.py      # reusable construct for a detector
│   │   ├── api.py                  # API GW + Lambda authorizer + routes
│   │   └── dashboard.py            # S3 + CloudFront for SPA
│   └── tests/
│       └── test_synth.py           # snapshot test of synthesized templates
├── lambdas/                        # all backend code
│   ├── shared/                     # shared module, packaged into each Lambda
│   │   ├── __init__.py
│   │   ├── models.py               # Pydantic models (Finding, Rule, Approval, ...)
│   │   ├── detector_base.py        # Detector ABC
│   │   ├── policy_engine.py
│   │   ├── audit.py                # writes JSONL to S3
│   │   ├── rule_loader.py          # reads YAML from S3
│   │   └── aws_clients.py          # boto3 client factory w/ Powertools tracing
│   ├── detectors/
│   │   ├── iam/
│   │   │   ├── handler.py          # entry, dispatches to detector classes
│   │   │   ├── requirements.txt
│   │   │   └── detectors/
│   │   │       ├── unused_role.py
│   │   │       ├── stale_access_key.py
│   │   │       ├── orphaned_trust.py
│   │   │       ├── unused_policy.py
│   │   │       ├── wildcard_policy.py  # flag-only
│   │   │       └── policy_quota.py
│   │   └── lambda_svc/             # "lambda" is a reserved word
│   │       ├── handler.py
│   │       ├── requirements.txt
│   │       └── detectors/
│   │           ├── idle_function.py
│   │           ├── orphan_version.py
│   │           ├── package_storage.py
│   │           ├── idle_reserved_concurrency.py
│   │           ├── broken_dlq.py
│   │           └── orphan_log_group.py
│   ├── policy_engine/              # consumes findings, decides action
│   │   ├── handler.py
│   │   └── requirements.txt
│   ├── remediator/                 # invokes SSM Automation
│   │   ├── handler.py
│   │   └── requirements.txt
│   ├── forecaster/                 # linear + Prophet
│   │   ├── handler.py
│   │   └── requirements.txt
│   ├── api/                        # dashboard backend
│   │   ├── handler.py              # uses Powertools APIGatewayHttpResolver
│   │   ├── routes/
│   │   │   ├── findings.py
│   │   │   ├── approvals.py
│   │   │   ├── rules.py
│   │   │   ├── forecasts.py
│   │   │   └── audit.py
│   │   └── requirements.txt
│   ├── authorizer/                 # bearer token validator
│   │   ├── handler.py
│   │   └── requirements.txt
│   ├── bootstrap_history/          # one-shot: seeds 90d synthetic data
│   │   ├── handler.py
│   │   └── requirements.txt
│   └── tests/                      # pytest tests (mirror structure above)
├── runbooks/                       # SSM Automation document YAMLs
│   ├── delete_iam_role.yml
│   ├── delete_iam_access_key.yml
│   ├── detach_unused_policy.yml
│   ├── delete_lambda_version.yml
│   └── delete_orphan_log_group.yml
├── dashboard/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── api/
│       │   ├── client.ts           # generated from OpenAPI
│       │   └── generated/          # gitignored, regen on schema change
│       ├── pages/
│       │   ├── Findings.tsx
│       │   ├── Approvals.tsx
│       │   ├── Rules.tsx
│       │   ├── Forecasts.tsx
│       │   └── Audit.tsx
│       ├── components/
│       │   ├── ui/                 # shadcn components
│       │   ├── FindingCard.tsx
│       │   ├── ForecastChart.tsx
│       │   └── RuleEditor.tsx
│       └── lib/
│           └── auth.ts             # localStorage bearer token helper
└── openapi/
    └── api.yaml                    # hand-edited; source of truth for client gen
```

---

## 3. Architecture diagram

```
                  ┌────────────────────────────────────────────┐
                  │           Demo user's browser              │
                  │                                            │
                  │   React SPA (CloudFront-hosted)            │
                  │   - bearer token in localStorage           │
                  └────────────────┬───────────────────────────┘
                                   │ HTTPS, Authorization: Bearer <token>
                                   ▼
                  ┌────────────────────────────────────────────┐
                  │   API Gateway HTTP API                     │
                  │   - Lambda authorizer (token validation)   │
                  │   - Routes: /findings /approvals /rules    │
                  │             /forecasts /audit              │
                  └────────────────┬───────────────────────────┘
                                   ▼
                  ┌────────────────────────────────────────────┐
                  │   api Lambda (Powertools resolver)         │
                  │   - reads DynamoDB + S3                    │
                  │   - writes approval decisions              │
                  └────────────────┬───────────────────────────┘
                                   │
   ┌───────────────────────────────┼───────────────────────────────┐
   │                               │                               │
   ▼                               ▼                               ▼
DynamoDB                        S3                          EventBridge bus
- findings                  - rules/*.yaml                  - finding.created
- approvals                 - audit/YYYY/MM/DD/*.jsonl      - approval.requested
- metric_history            - snapshots/role-*.json         - finding.remediated
- forecasts                 - dashboard SPA build
- rules_meta                                                     │
                                                                 ▼
                                                              SNS topic
                                                              (customer routes
                                                               downstream)

   ┌───────────────────────── Detection loop ──────────────────────────┐
   │                                                                   │
   │   EventBridge Scheduler ──► detector Lambdas (per service)        │
   │                              │                                    │
   │                              ▼                                    │
   │                          DynamoDB findings table                  │
   │                              │                                    │
   │                              ▼                                    │
   │                          DynamoDB Stream                          │
   │                              │                                    │
   │                              ▼                                    │
   │                          policy_engine Lambda                     │
   │                              │                                    │
   │                ┌─────────────┼──────────────┐                     │
   │           auto │             │ prompt        │ dry_run/skip       │
   │                ▼             ▼               ▼                    │
   │          remediator    approvals table    audit only              │
   │          Lambda        (waits for human)                          │
   │                │             │                                    │
   │                │             │ (approved via API)                 │
   │                │             ▼                                    │
   │                │         remediator Lambda                        │
   │                │             │                                    │
   │                ▼             ▼                                    │
   │          SSM Automation document runs ──► snapshot → S3           │
   │                          │                ──► delete resource     │
   │                          ▼                ──► audit log to S3     │
   │                       result ────────────► EventBridge bus + SNS  │
   └───────────────────────────────────────────────────────────────────┘

   ┌──────────────────────── Forecasting loop ─────────────────────────┐
   │                                                                   │
   │   EventBridge Scheduler (daily) ──► forecaster Lambda             │
   │                                       │                           │
   │                                       ▼                           │
   │                              reads metric_history                 │
   │                                       │                           │
   │                                       ▼                           │
   │                              linear extrapolation                 │
   │                                       │                           │
   │                                       ▼                           │
   │                              Prophet (if ≥60d data)               │
   │                                       │                           │
   │                                       ▼                           │
   │                              writes forecasts table               │
   └───────────────────────────────────────────────────────────────────┘

   ┌──────────────────────── Cost guardrail ───────────────────────────┐
   │   AWS Budgets: $10 alarm via SNS                                  │
   │                $20 ceiling → action: disable EventBridge          │
   │                Scheduler rules (detectors stop firing)            │
   └───────────────────────────────────────────────────────────────────┘
```

---

## 4. Data model (DynamoDB tables)

### `findings`
- **PK**: `account#region#service` (e.g., `123456789012#us-east-1#iam`)
- **SK**: `resource_arn#rule_id`
- **Attributes**: `status` (open|in_remediation|resolved|skipped), `severity`, `detected_at`, `last_seen_at`, `details` (JSON), `policy_decision`, `ttl` (TTL on resolved)
- **GSI**: `status-detected_at` for dashboard "open findings" view

### `approvals`
- **PK**: `approval_id` (ULID)
- **SK**: `metadata`
- **Attributes**: `finding_pk`, `finding_sk`, `requested_at`, `status` (pending|approved|rejected|expired), `decided_by`, `decided_at`, `reason`
- **GSI**: `status-requested_at` for the approval queue view

### `metric_history`
- **PK**: `metric_name` (e.g., `iam.role_count#account#region`)
- **SK**: ISO timestamp (`2026-05-29T00:00:00Z`)
- **Attributes**: `value` (number), `synthetic` (bool — true for backfilled, false for real)
- **No TTL** (history is the point)

### `forecasts`
- **PK**: `metric_name`
- **SK**: `model_type#run_id` (`linear#2026-05-29` or `prophet#2026-05-29`)
- **Attributes**: `forecast` (JSON of `{date, value, lower, upper}` points), `generated_at`

### `rules_meta`
- **PK**: `rule_id`
- **SK**: `metadata`
- **Attributes**: `version`, `last_loaded_at`, `enabled`, `schedule`, `s3_key` (where the YAML lives)

---

## 5. Pydantic models (core types)

```python
# lambdas/shared/models.py

from datetime import datetime
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class PolicyAction(str, Enum):
    AUTO = "auto"
    PROMPT = "prompt"
    DRY_RUN = "dry_run"
    SKIP = "skip"

class FindingStatus(str, Enum):
    OPEN = "open"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    SKIPPED = "skipped"

class Finding(BaseModel):
    account: str
    region: str
    service: Literal["iam", "lambda"]
    resource_arn: str
    rule_id: str
    status: FindingStatus = FindingStatus.OPEN
    severity: Severity
    detected_at: datetime
    last_seen_at: datetime
    details: dict
    policy_decision: PolicyAction | None = None

class RuleOverride(BaseModel):
    match: dict[str, str]   # tag.Environment: nonprod
    action: PolicyAction
    approvers: list[str] = Field(default_factory=list)

class ForecastConfig(BaseModel):
    enabled: bool = False
    alert_at_days_remaining: int = 14

class Rule(BaseModel):
    rule_id: str = Field(alias="rule")
    enabled: bool = True
    schedule: str = "rate(1 hour)"
    threshold: dict
    forecast: ForecastConfig = Field(default_factory=ForecastConfig)
    policy_default: PolicyAction = Field(alias="policy.default", default=PolicyAction.PROMPT)
    overrides: list[RuleOverride] = Field(default_factory=list)
    notifications_channels: list[str] = Field(default_factory=lambda: ["eventbridge", "sns"])
```

---

## 6. Detector base class (design sketch)

```python
# lambdas/shared/detector_base.py

from abc import ABC, abstractmethod
from typing import Iterator
from aws_lambda_powertools import Logger, Tracer, Metrics
from .models import Finding

logger = Logger()
tracer = Tracer()
metrics = Metrics()

class Detector(ABC):
    rule_id: str        # subclass sets, e.g., "iam.unused_role"
    service: str        # "iam" or "lambda"
    severity: str

    def __init__(self, account: str, region: str, threshold: dict):
        self.account = account
        self.region = region
        self.threshold = threshold

    @abstractmethod
    def scan(self) -> Iterator[Finding]:
        """Yield findings. Implementations call boto3 and emit zero or more Findings."""

    @tracer.capture_method
    def run(self) -> list[Finding]:
        findings = []
        for f in self.scan():
            findings.append(f)
            metrics.add_metric(name="FindingEmitted", unit="Count", value=1)
        logger.info(f"{self.rule_id} emitted {len(findings)} findings")
        return findings
```

A handler dispatches to the registered detector classes for that service:

```python
# lambdas/detectors/iam/handler.py

from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from .detectors import unused_role, stale_access_key, orphaned_trust, \
    unused_policy, wildcard_policy, policy_quota
from shared.models import Finding
from shared.rule_loader import load_enabled_rules_for_service
from shared.aws_clients import findings_table_writer

REGISTRY = {
    "iam.unused_role": unused_role.UnusedRoleDetector,
    "iam.stale_access_key": stale_access_key.StaleAccessKeyDetector,
    "iam.orphaned_trust": orphaned_trust.OrphanedTrustDetector,
    "iam.unused_policy": unused_policy.UnusedPolicyDetector,
    "iam.wildcard_policy": wildcard_policy.WildcardPolicyDetector,
    "iam.policy_quota": policy_quota.PolicyQuotaDetector,
}

logger = Logger()

def handler(event: dict, context: LambdaContext) -> dict:
    rules = load_enabled_rules_for_service("iam")
    all_findings: list[Finding] = []
    for rule in rules:
        cls = REGISTRY[rule.rule_id]
        det = cls(account=event["account"], region=event["region"], threshold=rule.threshold)
        all_findings.extend(det.run())
    findings_table_writer().write_batch(all_findings)
    return {"count": len(all_findings)}
```

---

## 7. Authentication (POC)

A pre-shared bearer token, kept honest:

- Token is **generated by CDK at deploy time** (32-byte random string) and stored in **SSM Parameter Store** as `/platform-hygiene/poc/bearer-token` (`SecureString`).
- Token is **printed once** at the end of `cdk deploy` to stdout for the operator to copy.
- Token is **never** committed, never in env vars, never in the SPA build.
- Operator pastes the token into a one-time form on first dashboard load; it's stored in `localStorage` from there.
- API Gateway HTTP API uses a **Lambda authorizer** that reads the token from SSM (cached for 5 minutes via Powertools `parameters`) and constant-time-compares.
- README documents: "POC-grade auth. Do not deploy publicly. Token rotation = redeploy CDK + clear localStorage."

This is still bearer-in-localStorage; it's just bearer-in-localStorage *done as carefully as possible*. The README will say so.

---

## 8. API surface (OpenAPI)

Hand-edited `openapi/api.yaml`. Generated TS client via `openapi-typescript` + `openapi-fetch`. Endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/findings` | List open findings, paginated, filterable by service/severity/status |
| GET | `/findings/{id}` | Single finding detail |
| POST | `/findings/{id}/skip` | Mark a finding as skipped (with reason) |
| GET | `/approvals` | List pending approvals |
| POST | `/approvals/{id}/approve` | Approve a pending action |
| POST | `/approvals/{id}/reject` | Reject a pending action |
| GET | `/rules` | List all rules with current YAML |
| PUT | `/rules/{id}` | Update a rule's YAML (validated against Pydantic) |
| GET | `/forecasts` | List all forecasts |
| GET | `/forecasts/{metric}` | Single forecast detail (used by chart) |
| GET | `/audit` | Recent audit events (paginated; old events queried via Athena in v1) |

Schemas in the spec mirror the Pydantic models. CI step regenerates the TS client on every push; PRs that change the spec without regenerating fail.

---

## 9. CDK stack design

### `CoreStack`
Everything the framework needs to run: tables, buckets, Lambdas, API Gateway, CloudFront, EventBridge bus + scheduler, SNS topic, SSM parameters, Budgets.

### `FixturesStack`
Demo resources only: ~100 stub Lambda functions (no code, just empty handlers), ~30 IAM roles with various violation patterns, 5 access keys, bootstrap Lambda that seeds 90 days of synthetic metric history. **Depends on `CoreStack`** for the metric_history table name but uses CDK SSM Parameter Store lookup, not direct cross-stack references — so destroying FixturesStack alone is safe.

```python
# infra/app.py
import aws_cdk as cdk
from stacks.core_stack import CoreStack
from stacks.fixtures_stack import FixturesStack

app = cdk.App()
core = CoreStack(app, "PlatformHygiene-Core")
FixturesStack(app, "PlatformHygiene-Fixtures")  # no direct dep; uses SSM lookup
app.synth()
```

Deploy commands:
- `cdk deploy PlatformHygiene-Core` — every dev iteration
- `cdk deploy PlatformHygiene-Fixtures` — once after Core; rare changes
- `cdk destroy PlatformHygiene-Fixtures` — when you want a clean fixtures slate
- `cdk destroy --all` — full teardown

---

## 10. CI/CD pipeline (GitHub Actions)

### `.github/workflows/ci.yml` — runs on every PR
1. **Lint**: `ruff check`, `ruff format --check`
2. **Type check**: `mypy lambdas/ infra/` with `disallow_untyped_defs`
3. **Unit tests**: `pytest lambdas/tests/` (with moto)
4. **CDK synth**: `cd infra && cdk synth` (catches IaC errors)
5. **Dashboard**: `pnpm install && pnpm typecheck && pnpm build`
6. **OpenAPI client drift check**: regenerate client, fail if `git diff` is non-empty

### `.github/workflows/deploy.yml` — manual trigger
1. Same as CI plus:
2. **OIDC auth to AWS** (no long-lived keys in GitHub)
3. **Tag deploy**: `git tag poc-$(date +%Y-%m-%d)-$RUN_NUMBER`
4. `cdk deploy --all`
5. Run smoke test against deployed `FixturesStack`
6. Post deploy notification to a Slack webhook (optional)

---

## 11. Versioning convention

Every deploy is tagged in git as `poc-YYYY-MM-DD-NNN` where NNN is the GitHub Actions run number that day. The tag is also written to:
- CloudFormation stack tag `DeployVersion`
- SSM parameter `/platform-hygiene/poc/deploy-version`
- Dashboard footer (read at runtime from `/health` endpoint)

So at any moment, an operator can match the live deploy back to a git tag, which matches a commit, which matches a PR. Important for "which version deleted my IAM role?" investigations even in a POC.

---

## 12. Local development

- `make install` — installs Python deps for infra + all Lambdas + dashboard deps
- `make lint` — runs ruff + mypy + prettier
- `make test` — runs pytest + dashboard tests
- `make synth` — `cdk synth` to sanity-check IaC
- `make deploy` — runs synth, then `cdk deploy --all`
- `make destroy` — `cdk destroy --all` with confirmation
- `make seed-history` — invokes the bootstrap_history Lambda manually
- `make smoke` — runs the integration smoke test against deployed stacks
- `make demo-reset` — destroys + redeploys FixturesStack only (resets demo state)

---

## 13. Operational conventions

- **Logging**: Powertools `Logger`. JSON-structured. Every log line includes `rule_id`, `account`, `region`, `correlation_id`. Log retention: 1 day (Free Tier guardrail).
- **Tracing**: Powertools `Tracer` (X-Ray). Sampled at 10% for the POC.
- **Metrics**: Powertools `Metrics` (CloudWatch EMF). Counters for `FindingEmitted`, `RemediationExecuted`, `ApprovalGranted`, `BudgetGuardrailTriggered`.
- **Error handling**: detector failures emit a `DetectorError` finding (severity=info) rather than crashing the Lambda — partial degradation is fine, total silence is not.
- **Idempotency**: detector writes use DynamoDB conditional writes keyed on `(resource_arn, rule_id)`; re-detecting the same resource within the dedup window updates `last_seen_at` only.
- **Audit log format**: JSONL, one event per line, schema in `openapi/api.yaml` for the `/audit` response (single source of truth).
- **Snapshot before delete**: every IAM role / policy deletion writes a JSON snapshot to `s3://<audit-bucket>/snapshots/<resource>/<timestamp>.json` first. Restore is documented, not built.

---

## 14. Things deliberately not designed yet

These need design but only when their phase begins in the build plan:

1. **Lambda authorizer caching semantics** — how to balance SSM read cost vs. rotation responsiveness.
2. **Synthetic data generator** — the shape of the 90-day backfill (Poisson process? Step function with weekly seasonality? Random walk?). Will iterate during the forecaster phase.
3. **shadcn component selection** — picked as needed; not worth designing the full dashboard ahead of build.
4. **Rule YAML editor in the dashboard** — Monaco editor vs. textarea + validate-on-save. Decide during dashboard phase.
5. **Forecast chart styling** — colors, confidence band rendering, hover interactions. Decide during forecaster phase.

These are explicitly deferred to keep this doc from becoming fiction.

---

## 15. Open technical questions

- **DynamoDB Streams vs. EventBridge Pipes** for findings → policy engine. Streams are simpler; Pipes give better filtering. Default: Streams for POC.
- **Prophet on Lambda**: cold-start size with `prophet` package is large (~150MB unzipped, plus pandas/numpy). May need a Lambda layer or container image. Decide during forecaster phase; fallback is to run forecasting in a one-shot Fargate task scheduled via EventBridge.
- **CloudFront for the SPA**: a single distribution is ~$0 at our traffic, but the first request can be slow until cache warms. Acceptable for POC.
- **Cognito later**: when we move past POC, what's the migration path from bearer token? Probably: introduce Cognito alongside, deprecate token endpoint, remove. Document but don't build.
