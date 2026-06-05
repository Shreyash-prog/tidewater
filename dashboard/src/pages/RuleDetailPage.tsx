import { Link, useParams } from "react-router-dom";

import { apiGet } from "@/api/client";
import type { RuleDetail } from "@/api/types";
import { useAsync } from "@/hooks/useAsync";

export function RuleDetailPage() {
  const { ruleId = "" } = useParams();
  const { data, error, loading } = useAsync<RuleDetail>(
    () => apiGet<RuleDetail>(`/rules/${encodeURIComponent(ruleId)}`),
    [ruleId],
  );

  return (
    <div className="space-y-4 p-6">
      <Link to="/rules" className="text-sm text-blue-600 hover:underline">
        ← Back to rules
      </Link>
      <h1 className="font-mono text-xl font-semibold">{ruleId}</h1>
      {error && <p className="text-sm text-red-600">Error: {error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {data && (
        <pre className="overflow-x-auto rounded-lg border bg-card p-4 text-xs leading-relaxed">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}
