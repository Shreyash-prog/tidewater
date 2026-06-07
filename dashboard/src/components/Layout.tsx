import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";

import { cn } from "@/lib/utils";
import { clearToken, getApprover } from "@/api/client";
import { ApproverPrompt } from "@/components/ApproverPrompt";

const NAV = [
  { to: "/", label: "Findings", end: true },
  { to: "/rules", label: "Rules", end: false },
];

export function Layout() {
  const [editingName, setEditingName] = useState(false);
  const [approver, setApproverState] = useState(getApprover());
  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="flex w-52 flex-col border-r bg-card">
        <div className="border-b px-4 py-4">
          <span className="text-lg font-semibold tracking-tight">Tidewater</span>
          <p className="text-xs text-muted-foreground">platform hygiene</p>
        </div>
        <nav className="flex-1 space-y-1 p-2">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "block rounded-md px-3 py-2 text-sm font-medium",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted",
                )
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t px-3 py-2 text-xs text-muted-foreground">
          {approver ? (
            <>
              Approving as <span className="font-medium text-foreground">{approver}</span> ·{" "}
              <button onClick={() => setEditingName(true)} className="hover:underline">
                change
              </button>
            </>
          ) : (
            <button onClick={() => setEditingName(true)} className="hover:underline">
              Set approver name
            </button>
          )}
        </div>
        <button
          onClick={() => {
            clearToken();
            window.location.reload();
          }}
          className="m-2 rounded-md px-3 py-2 text-left text-xs text-muted-foreground hover:bg-muted"
        >
          Clear token
        </button>
      </aside>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
      {editingName && (
        <ApproverPrompt
          onSaved={(name) => {
            setApproverState(name);
            setEditingName(false);
          }}
          onCancel={() => {
            setApproverState(getApprover());
            setEditingName(false);
          }}
        />
      )}
    </div>
  );
}
