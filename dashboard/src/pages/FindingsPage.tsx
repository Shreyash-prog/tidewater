import { useCallback, useState } from "react";
import { Link } from "react-router-dom";

import { apiGet } from "@/api/client";
import type { Finding, FindingsPage as FindingsPageData } from "@/api/types";
import { useAsync } from "@/hooks/useAsync";
import { DecisionBadge, SeverityBadge, StatusBadge } from "@/components/badges";

interface Filters {
  severity: string;
  service: string;
  status: string;
  rule_id: string;
}

const EMPTY: Filters = { severity: "", service: "", status: "", rule_id: "" };

function queryFor(filters: Filters, limit = 50): string {
  const params = new URLSearchParams({ limit: String(limit) });
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  return `/findings?${params.toString()}`;
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <label className="block text-sm">
      <span className="text-muted-foreground">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 text-sm"
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FindingsPage() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [extra, setExtra] = useState<Finding[]>([]);
  const [nextToken, setNextToken] = useState<string | undefined>(undefined);

  const set = (patch: Partial<Filters>) => {
    setExtra([]);
    setNextToken(undefined);
    setFilters((f) => ({ ...f, ...patch }));
  };

  const { data, error, loading } = useAsync<FindingsPageData>(
    () => apiGet<FindingsPageData>(queryFor(filters)),
    [filters],
  );

  const loadMore = useCallback(async () => {
    const token = nextToken ?? data?.next_token;
    if (!token) return;
    const page = await apiGet<FindingsPageData>(`${queryFor(filters)}&next_token=${token}`);
    setExtra((prev) => [...prev, ...page.items]);
    setNextToken(page.next_token);
  }, [filters, nextToken, data]);

  const items = [...(data?.items ?? []), ...extra];
  const moreToken = nextToken ?? data?.next_token;

  return (
    <div className="p-6">
      <h1 className="mb-4 text-2xl font-semibold">Findings</h1>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[200px_1fr]">
        <div className="space-y-3 rounded-lg border bg-card p-4">
          <Select
            label="Severity"
            value={filters.severity}
            options={["high", "medium", "low"]}
            onChange={(v) => set({ severity: v })}
          />
          <Select
            label="Service"
            value={filters.service}
            options={["iam", "lambda"]}
            onChange={(v) => set({ service: v })}
          />
          <Select
            label="Status"
            value={filters.status}
            options={["open", "in_remediation", "resolved", "skipped"]}
            onChange={(v) => set({ status: v })}
          />
          <label className="block text-sm">
            <span className="text-muted-foreground">Rule ID</span>
            <input
              value={filters.rule_id}
              onChange={(e) => set({ rule_id: e.target.value })}
              placeholder="iam.unused_role"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 text-sm"
            />
          </label>
        </div>

        <div className="overflow-x-auto rounded-lg border bg-card">
          {error && <p className="p-4 text-sm text-red-600">Error: {error}</p>}
          {loading && <p className="p-4 text-sm text-muted-foreground">Loading…</p>}
          {!loading && !error && (
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-muted/60 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Service</th>
                  <th className="px-3 py-2">Rule</th>
                  <th className="px-3 py-2">Resource</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Decision</th>
                  <th className="px-3 py-2">Detected</th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => (
                  <tr key={`${f.pk}|${f.sk}`} className="border-t hover:bg-muted/40">
                    <td className="px-3 py-2">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-3 py-2">{f.service}</td>
                    <td className="px-3 py-2">
                      <Link
                        to={`/findings/${encodeURIComponent(f.pk)}/${encodeURIComponent(f.sk)}`}
                        className="font-medium text-blue-600 hover:underline"
                      >
                        {f.rule_id}
                      </Link>
                    </td>
                    <td className="max-w-xs truncate px-3 py-2 font-mono text-xs">
                      {f.resource_arn}
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="px-3 py-2">
                      <DecisionBadge decision={f.policy_decision ?? null} />
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {f.detected_at.slice(0, 19).replace("T", " ")}
                    </td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-6 text-center text-muted-foreground">
                      No findings match these filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
          {moreToken && (
            <div className="border-t p-3 text-center">
              <button
                onClick={loadMore}
                className="rounded-md border px-4 py-1.5 text-sm hover:bg-muted"
              >
                Load more
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
