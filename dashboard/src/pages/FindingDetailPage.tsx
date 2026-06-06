import { Link, useParams } from "react-router-dom";

import { apiGet } from "@/api/client";
import type { AuditResponse, Finding, SnapshotResponse } from "@/api/types";
import { useAsync } from "@/hooks/useAsync";
import { DecisionBadge, SeverityBadge, StatusBadge } from "@/components/badges";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border bg-card p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="break-all text-sm">{value || "—"}</span>
    </div>
  );
}

async function downloadSnapshot(pk: string, sk: string) {
  const resp = await apiGet<SnapshotResponse>(
    `/findings/${encodeURIComponent(pk)}/${encodeURIComponent(sk)}/snapshot`,
  );
  if (resp.url) window.open(resp.url, "_blank", "noopener");
}

export function FindingDetailPage() {
  const { pk = "", sk = "" } = useParams();
  const finding = useAsync<Finding>(
    () => apiGet<Finding>(`/findings/${encodeURIComponent(pk)}/${encodeURIComponent(sk)}`),
    [pk, sk],
  );
  const audit = useAsync<AuditResponse>(
    () =>
      apiGet<AuditResponse>(`/findings/${encodeURIComponent(pk)}/${encodeURIComponent(sk)}/audit`),
    [pk, sk],
  );

  if (finding.loading) return <p className="p-6 text-sm text-muted-foreground">Loading…</p>;
  if (finding.error || !finding.data)
    return <p className="p-6 text-sm text-red-600">Error: {finding.error ?? "not found"}</p>;

  const f = finding.data;
  return (
    <div className="space-y-4 p-6">
      <Link to="/" className="text-sm text-blue-600 hover:underline">
        ← Back to findings
      </Link>
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={f.severity} />
        <StatusBadge status={f.status} />
        <h1 className="text-xl font-semibold">{f.rule_id}</h1>
      </div>
      <p className="break-all font-mono text-sm text-muted-foreground">{f.resource_arn}</p>

      <Section title="Metadata">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <Field label="Account" value={f.account} />
          <Field label="Region" value={f.region} />
          <Field label="Service" value={f.service} />
          <Field label="Detected at" value={f.detected_at} />
          <Field label="Last seen at" value={f.last_seen_at} />
          <Field label="Decision" value={<DecisionBadge decision={f.policy_decision ?? null} />} />
          <Field label="Decision reason" value={f.decision_reason} />
          <Field label="Notified at" value={f.notified_at} />
        </div>
      </Section>

      <Section title="Details">
        <pre className="overflow-x-auto rounded bg-muted p-3 text-xs">
          {JSON.stringify(f.details, null, 2)}
        </pre>
      </Section>

      <Section title="Snapshot">
        {f.snapshot_s3_key ? (
          <button
            onClick={() => void downloadSnapshot(pk, sk)}
            className="rounded-md border px-4 py-1.5 text-sm hover:bg-muted"
          >
            Download snapshot
          </button>
        ) : (
          <p className="text-sm text-muted-foreground">No snapshot for this finding.</p>
        )}
      </Section>

      <Section title="Audit log">
        {audit.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
        {audit.data && audit.data.items.length === 0 && (
          <p className="text-sm text-muted-foreground">No audit entries.</p>
        )}
        <ul className="space-y-2">
          {audit.data?.items.map((entry, i) => (
            <li
              key={entry.audit_id ?? i}
              className="rounded border-l-2 border-blue-300 bg-muted/40 p-2"
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">{entry.event_type}</span>
                <span className="text-muted-foreground">{entry.timestamp}</span>
              </div>
              {entry.details ? (
                <pre className="mt-1 overflow-x-auto text-xs">
                  {JSON.stringify(entry.details, null, 2)}
                </pre>
              ) : null}
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}
