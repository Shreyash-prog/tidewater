import { useState } from "react";

import { clearApprover, getApprover, setApprover } from "@/api/client";

/**
 * Modal that captures the operator's name (self-attested, for audit attribution).
 * Used both as a first-action gate and from the "change" affordance in the layout.
 */
export function ApproverPrompt({
  onSaved,
  onCancel,
}: {
  onSaved: (name: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(getApprover() ?? "");

  function save() {
    const name = value.trim();
    if (!name) return;
    setApprover(name);
    onSaved(name);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
        <h2 className="text-lg font-semibold">Who is approving?</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Your name is recorded with the decision for the audit trail. It is self-attested — the
          bearer token is what authenticates the request.
        </p>
        <input
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") save();
          }}
          maxLength={100}
          placeholder="e.g. alice@example.com"
          className="mt-4 w-full rounded-md border bg-background px-3 py-2 text-sm
            focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <div className="mt-4 flex items-center justify-between">
          {getApprover() ? (
            <button
              onClick={() => {
                clearApprover();
                setValue("");
              }}
              className="text-xs text-muted-foreground hover:underline"
            >
              Clear saved name
            </button>
          ) : (
            <span />
          )}
          <div className="flex gap-2">
            <button
              onClick={onCancel}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Cancel
            </button>
            <button
              onClick={save}
              className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium
                text-primary-foreground hover:opacity-90"
            >
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
