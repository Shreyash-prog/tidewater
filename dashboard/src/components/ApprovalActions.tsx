import { useEffect, useState } from "react";

import { apiPost, getApprover } from "@/api/client";
import { ApiError } from "@/api/client";
import type { ApprovalDecision, Finding } from "@/api/types";
import { approvalIdFor } from "@/lib/approval";
import { ApproverPrompt } from "@/components/ApproverPrompt";

type Action = "approve" | "reject";

/**
 * Approve / reject controls for a finding awaiting human review. Renders only for
 * policy_decision=prompt + status=open. Approve is styled destructive (red): the
 * click runs the remediation runbook against the resource.
 */
export function ApprovalActions({
  finding,
  onDecided,
}: {
  finding: Finding;
  onDecided: () => void;
}) {
  const [approvalId, setApprovalId] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<Action | null>(null);
  const [needName, setNeedName] = useState<Action | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    approvalIdFor(finding.pk, finding.sk).then((id) => {
      if (active) setApprovalId(id);
    });
    return () => {
      active = false;
    };
  }, [finding.pk, finding.sk]);

  const eligible = finding.policy_decision === "prompt" && finding.status === "open";
  if (!eligible) return null;

  function start(action: Action) {
    setMessage(null);
    if (!getApprover()) {
      setNeedName(action);
      return;
    }
    setReason("");
    setPendingAction(action);
  }

  async function submit(action: Action) {
    const approver = getApprover();
    if (!approver || !approvalId) return;
    setBusy(true);
    setMessage(null);
    try {
      await apiPost<ApprovalDecision>(`/approvals/${approvalId}`, {
        action,
        approver,
        ...(action === "reject" ? { reason } : {}),
      });
      setPendingAction(null);
      onDecided();
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 409) {
        setMessage("This finding was already decided by someone else. Refreshing…");
        setPendingAction(null);
        onDecided();
      } else {
        const detail = err instanceof Error ? err.message : String(err);
        setMessage(`Action failed (state unchanged): ${detail}`);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border-2 border-amber-300 bg-amber-50/50 p-4">
      <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-amber-800">
        Human review required
      </h2>
      <p className="mb-3 text-sm text-muted-foreground">
        This finding is waiting for an approve/reject decision.
      </p>
      <div className="flex gap-3">
        <button
          onClick={() => start("approve")}
          className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white
            hover:bg-red-700"
        >
          Approve &amp; remediate
        </button>
        <button
          onClick={() => start("reject")}
          className="rounded-md border px-4 py-2 text-sm font-medium hover:bg-muted"
        >
          Reject
        </button>
      </div>
      {message && <p className="mt-3 text-sm text-red-600">{message}</p>}

      {needName && (
        <ApproverPrompt
          onSaved={() => {
            const action = needName;
            setNeedName(null);
            setReason("");
            setPendingAction(action);
          }}
          onCancel={() => setNeedName(null)}
        />
      )}

      {pendingAction === "approve" && (
        <ConfirmModal
          title="Approve this finding?"
          confirmLabel={busy ? "Approving…" : "Approve"}
          destructive
          busy={busy}
          onConfirm={() => void submit("approve")}
          onCancel={() => setPendingAction(null)}
        >
          <p className="text-sm">You&apos;re about to APPROVE remediation of:</p>
          <dl className="mt-2 space-y-1 text-sm">
            <div>
              <span className="text-muted-foreground">Rule: </span>
              <span className="font-mono">{finding.rule_id}</span>
            </div>
            <div className="break-all">
              <span className="text-muted-foreground">Resource: </span>
              <span className="font-mono">{finding.resource_arn}</span>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            This runs the remediation runbook for this rule against the resource. The runbook
            snapshots the resource to S3 before any destructive action.
          </p>
        </ConfirmModal>
      )}

      {pendingAction === "reject" && (
        <ConfirmModal
          title="Reject this finding?"
          confirmLabel={busy ? "Rejecting…" : "Reject"}
          busy={busy}
          onConfirm={() => void submit("reject")}
          onCancel={() => setPendingAction(null)}
        >
          <p className="text-sm text-muted-foreground">
            Closes this finding (status → skipped). It does not permanently exclude the resource —
            if the rule trips again a new finding fires. Use the{" "}
            <code className="rounded bg-muted px-1">tidewater-skip: true</code> tag for permanent
            exclusion.
          </p>
          <label className="mt-3 block text-sm">
            <span className="text-muted-foreground">Reason (optional, 200 chars)</span>
            <textarea
              value={reason}
              maxLength={200}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 text-sm"
            />
          </label>
        </ConfirmModal>
      )}
    </section>
  );
}

function ConfirmModal({
  title,
  confirmLabel,
  destructive = false,
  busy,
  onConfirm,
  onCancel,
  children,
}: {
  title: string;
  confirmLabel: string;
  destructive?: boolean;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
        <h3 className="text-lg font-semibold">{title}</h3>
        <div className="mt-3">{children}</div>
        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={busy}
            className={
              destructive
                ? "rounded-md bg-red-600 px-3 py-1.5 text-sm font-semibold text-white " +
                  "hover:bg-red-700 disabled:opacity-50"
                : "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground " +
                  "hover:opacity-90 disabled:opacity-50"
            }
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
