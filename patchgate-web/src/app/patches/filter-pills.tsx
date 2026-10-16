"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

const FILTERS = [
  { label: "Needed by any PC", query: "" },
  { label: "All patches", query: "needed=0" },
  { label: "Windows", query: "kind=WINDOWS" },
  { label: "Third-party", query: "kind=THIRD_PARTY&needed=0" },
  { label: "Tactical agent", query: "kind=AGENT_UPGRADE&needed=0" },
  { label: "Critical", query: "severity=CRITICAL" },
] as const;

export function FilterPills() {
  const current = useSearchParams().toString();
  return (
    <div role="tablist" aria-label="Patch filters" className="mb-5 flex flex-wrap gap-2">
      {FILTERS.map((f) => {
        const active = current === f.query;
        return (
          <Link
            key={f.label}
            role="tab"
            aria-selected={active}
            href={f.query ? `/patches?${f.query}` : "/patches"}
            className={`rounded-full border px-3.5 py-1.5 text-xs font-medium transition-colors ${
              active
                ? "border-primary bg-primary text-primary-fg shadow-sm"
                : "border-border-strong bg-surface text-muted hover:border-primary hover:text-primary"
            }`}
          >
            {f.label}
          </Link>
        );
      })}
    </div>
  );
}
