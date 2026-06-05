import { cn } from "@/lib/utils";
import type { FindingStatus, PolicyDecision, Severity } from "@/api/types";

const SEVERITY_CLASS: Record<Severity, string> = {
  high: "bg-red-100 text-red-800 ring-red-600/20",
  medium: "bg-orange-100 text-orange-800 ring-orange-600/20",
  low: "bg-yellow-100 text-yellow-800 ring-yellow-600/20",
  info: "bg-slate-100 text-slate-700 ring-slate-500/20",
};

const STATUS_CLASS: Record<FindingStatus, string> = {
  open: "bg-red-100 text-red-800 ring-red-600/20",
  in_remediation: "bg-blue-100 text-blue-800 ring-blue-600/20",
  resolved: "bg-green-100 text-green-800 ring-green-600/20",
  skipped: "bg-slate-100 text-slate-600 ring-slate-500/20",
};

const DECISION_CLASS: Record<string, string> = {
  auto: "bg-purple-100 text-purple-800 ring-purple-600/20",
  prompt: "bg-amber-100 text-amber-800 ring-amber-600/20",
  skip: "bg-slate-100 text-slate-600 ring-slate-500/20",
  dry_run: "bg-slate-100 text-slate-500 ring-slate-400/20",
};

function Pill({ className, label }: { className: string; label: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
        className,
      )}
    >
      {label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill className={SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info} label={severity} />;
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  return <Pill className={STATUS_CLASS[status] ?? STATUS_CLASS.skipped} label={status} />;
}

export function DecisionBadge({ decision }: { decision: PolicyDecision }) {
  if (!decision) return <span className="text-muted-foreground">—</span>;
  return <Pill className={DECISION_CLASS[decision] ?? DECISION_CLASS.dry_run} label={decision} />;
}
