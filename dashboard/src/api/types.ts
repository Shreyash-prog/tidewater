export type Severity = "info" | "low" | "medium" | "high";
export type FindingStatus = "open" | "in_remediation" | "resolved" | "skipped";
export type PolicyDecision = "auto" | "prompt" | "dry_run" | "skip" | null;

export interface Finding {
  pk: string;
  sk: string;
  account: string;
  region: string;
  service: string;
  resource_arn: string;
  rule_id: string;
  status: FindingStatus;
  severity: Severity;
  detected_at: string;
  last_seen_at: string;
  details: Record<string, unknown>;
  policy_decision?: PolicyDecision;
  decision_reason?: string | null;
  snapshot_s3_key?: string;
  notified_at?: string;
}

export interface FindingsPage {
  items: Finding[];
  count: number;
  next_token?: string;
}

export interface AuditEntry {
  audit_id?: string;
  timestamp?: string;
  event_type?: string;
  rule_id?: string;
  actor?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AuditResponse {
  items: AuditEntry[];
  count: number;
}

export interface SnapshotResponse {
  url?: string;
  expires_in?: number;
  error?: string;
}

export interface RuleSummary {
  rule_id: string;
  enabled: boolean;
  schedule?: string;
  policy_default?: PolicyDecision;
  has_overrides: boolean;
  forecast_enabled: boolean;
}

export interface RulesResponse {
  items: RuleSummary[];
  count: number;
}

export type RuleDetail = Record<string, unknown>;
