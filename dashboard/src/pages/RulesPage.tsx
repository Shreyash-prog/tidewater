import { Link } from "react-router-dom";

import { apiGet } from "@/api/client";
import type { RulesResponse } from "@/api/types";
import { useAsync } from "@/hooks/useAsync";
import { DecisionBadge } from "@/components/badges";

export function RulesPage() {
  const { data, error, loading } = useAsync<RulesResponse>(
    () => apiGet<RulesResponse>("/rules"),
    [],
  );

  return (
    <div className="p-6">
      <h1 className="mb-4 text-2xl font-semibold">Rules</h1>
      {error && <p className="text-sm text-red-600">Error: {error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {data?.items.map((rule) => (
          <Link
            key={rule.rule_id}
            to={`/rules/${encodeURIComponent(rule.rule_id)}`}
            className="rounded-lg border bg-card p-4 hover:border-primary"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm font-medium">{rule.rule_id}</span>
              <span
                className={
                  rule.enabled
                    ? "text-xs font-medium text-green-600"
                    : "text-xs font-medium text-muted-foreground"
                }
              >
                {rule.enabled ? "enabled" : "disabled"}
              </span>
            </div>
            <div className="mt-3 flex items-center gap-2">
              <DecisionBadge decision={rule.policy_default ?? null} />
              {rule.has_overrides && (
                <span className="text-xs text-muted-foreground">+ overrides</span>
              )}
              {rule.forecast_enabled && (
                <span className="text-xs text-muted-foreground">forecast</span>
              )}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
