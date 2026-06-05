import { useState } from "react";

import { setToken } from "@/api/client";

const RETRIEVE_CMD =
  "aws ssm get-parameter --name /platform-hygiene/poc/bearer-token " +
  "--with-decryption --query Parameter.Value --output text";

export function TokenPrompt() {
  const [value, setValue] = useState("");

  function save() {
    const token = value.trim();
    if (!token) return;
    setToken(token);
    window.location.reload();
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-lg rounded-lg border bg-card p-6 shadow-sm">
        <h1 className="text-xl font-semibold">Tidewater dashboard</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Enter the dashboard bearer token to continue. It is stored only in this browser
          (localStorage).
        </p>
        <p className="mt-3 text-sm text-muted-foreground">Retrieve it once with:</p>
        <pre className="mt-1 overflow-x-auto rounded bg-muted p-3 text-xs">{RETRIEVE_CMD}</pre>
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") save();
          }}
          placeholder="Paste bearer token"
          className="mt-4 w-full rounded-md border bg-background px-3 py-2 text-sm
            focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <button
          onClick={save}
          className="mt-3 w-full rounded-md bg-primary px-3 py-2 text-sm font-medium
            text-primary-foreground hover:opacity-90"
        >
          Save token
        </button>
      </div>
    </div>
  );
}
