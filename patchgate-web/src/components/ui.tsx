import type { ReactNode } from "react";

/* PatchGate design system primitives — all colours come from theme tokens in globals.css. */

const TONES = {
  neutral: "bg-neutral-soft text-muted ring-border",
  info: "bg-info-soft text-info ring-info/25",
  warn: "bg-warning-soft text-warning ring-warning/25",
  good: "bg-success-soft text-success ring-success/25",
  bad: "bg-danger-soft text-danger ring-danger/25",
  busy: "bg-busy-soft text-busy ring-busy/25",
} as const;

export type Tone = keyof typeof TONES;

const STATUS_TONE: Record<string, Tone> = {
  DRAFT: "neutral",
  PENDING_APPROVAL: "warn",
  APPROVED: "info",
  DEPLOYING: "busy",
  COMPLETED: "good",
  PARTIAL: "warn",
  FAILED: "bad",
  REJECTED: "bad",
  CANCELLED: "neutral",
  QUEUED: "neutral",
  SENDING: "busy",
  SENT: "busy",
  SUCCEEDED: "good",
  TIMED_OUT: "bad",
  VERIFIED: "good",
  PENDING: "warn",
  HELD: "warn",
  CRITICAL: "bad",
  IMPORTANT: "warn",
  MODERATE: "info",
  LOW: "neutral",
  UNSPECIFIED: "neutral",
  NEEDED: "warn",
  INSTALLED: "good",
  NOT_APPLICABLE: "neutral",
};

export function Badge({ children, tone, dot = true }: { children: ReactNode; tone?: Tone; dot?: boolean }) {
  const t = tone ?? (typeof children === "string" ? STATUS_TONE[children] : undefined) ?? "neutral";
  const label = typeof children === "string" ? children.replaceAll("_", " ").toLowerCase() : children;
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${TONES[t]}`}
    >
      {dot && <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />}
      {label}
    </span>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-border pb-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-start gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ title, description, children, actions, padded = true }: {
  title?: string;
  description?: string;
  children: ReactNode;
  actions?: ReactNode;
  padded?: boolean;
}) {
  return (
    <section className="overflow-hidden rounded-xl border border-border bg-surface shadow-card">
      {(title || actions) && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface-2 px-5 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-fg">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
          </div>
          {actions && <div className="flex gap-2">{actions}</div>}
        </div>
      )}
      <div className={padded ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, tone = "neutral", icon, hint }: {
  label: string;
  value: ReactNode;
  tone?: "neutral" | "bad" | "good" | "warn";
  icon?: ReactNode;
  hint?: string;
}) {
  const accent = { neutral: "bg-primary", bad: "bg-danger", good: "bg-success", warn: "bg-warning" }[tone];
  const color = { neutral: "text-fg", bad: "text-danger", good: "text-success", warn: "text-warning" }[tone];
  return (
    <div className="relative overflow-hidden rounded-xl border border-border bg-surface p-4 shadow-card">
      <span aria-hidden className={`absolute inset-y-0 left-0 w-1 ${accent}`} />
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wide text-muted">{label}</span>
        {icon && <span className="text-muted">{icon}</span>}
      </div>
      <div className={`mt-2 text-3xl font-semibold tabular-nums ${color}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-border-strong bg-surface p-10 text-center">
      <p className="font-medium text-fg">{title}</p>
      {children && <div className="mt-1 text-sm text-muted">{children}</div>}
    </div>
  );
}

export function Alert({ tone = "bad", children }: { tone?: "bad" | "warn" | "info" | "good"; children: ReactNode }) {
  const cls = {
    bad: "border-danger/30 bg-danger-soft text-danger",
    warn: "border-warning/30 bg-warning-soft text-warning",
    info: "border-info/30 bg-info-soft text-info",
    good: "border-success/30 bg-success-soft text-success",
  }[tone];
  return (
    <div role="alert" className={`rounded-lg border px-4 py-3 text-sm ${cls}`}>
      {children}
    </div>
  );
}

/* Tables */
export const tableWrapCls = "overflow-x-auto rounded-xl border border-border bg-surface shadow-card";
export const tableCls = "w-full text-left text-sm";
export const theadCls =
  "border-b border-border bg-surface-2 text-xs uppercase tracking-wide text-muted [&_th]:px-4 [&_th]:py-3 [&_th]:font-semibold";
export const rowCls =
  "border-b border-border last:border-0 align-top transition-colors hover:bg-surface-2 [&_td]:px-4 [&_td]:py-3";

/* Forms */
export const inputCls =
  "mt-1 block w-full rounded-lg border border-border-strong bg-surface px-3 py-2 text-sm text-fg shadow-sm placeholder:text-muted focus:border-primary focus:outline-none focus:ring-2 focus:ring-ring";
export const labelCls = "block text-sm font-medium text-fg";

/* Buttons */
export const BUTTON = {
  primary: "bg-primary text-primary-fg hover:bg-primary-hover shadow-sm",
  danger: "bg-danger text-white hover:opacity-90 shadow-sm",
  default: "border border-border-strong bg-surface text-fg hover:bg-surface-2 shadow-sm",
} as const;
export const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50";

export function fmtDate(d: Date | null | undefined): string {
  return d ? d.toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—";
}

export function Loading() {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading">
      {[0, 1, 2].map((i) => (
        <div key={i} className="h-12 animate-pulse rounded-lg bg-surface-2" />
      ))}
    </div>
  );
}
