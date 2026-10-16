import { DEPLOY_STAGES, STAGE_LABEL, type RolloutProgress } from "@/lib/deploy/progress";

/**
 * Rollout progress bar (server component): % of target endpoints finished (succeeded + failed), coloured
 * segments succeeded / failed / in progress / queued, counts, and (full size) the per-stage breakdown.
 */

interface Segment {
  key: string;
  label: string;
  count: number;
  cls: string;
}

function segmentsOf(p: RolloutProgress): Segment[] {
  return [
    { key: "succeeded", label: "succeeded", count: p.succeeded, cls: "bg-success" },
    { key: "failed", label: "failed", count: p.failed, cls: "bg-danger" },
    { key: "progress", label: "in progress", count: p.inProgress, cls: "bg-busy" },
    { key: "queued", label: "queued", count: p.queued, cls: "bg-border-strong" },
  ];
}

export interface DeploymentProgressProps {
  progress: RolloutProgress;
  /** List view: thin bar + one line of text, no stage breakdown */
  compact?: boolean;
}

export function DeploymentProgress({ progress: p, compact = false }: DeploymentProgressProps) {
  if (p.total === 0) return null;
  const segments = segmentsOf(p);
  const summary = `${p.percent}% finished · ${p.finished} of ${p.total} endpoint${p.total === 1 ? "" : "s"}`;
  return (
    <div className={compact ? "min-w-[9rem] space-y-1" : "space-y-2"} data-testid="deployment-progress">
      <div
        role="progressbar"
        aria-label="Deployment progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={p.percent}
        aria-valuetext={summary}
        className={`flex w-full overflow-hidden rounded-full bg-surface-2 ${compact ? "h-1.5" : "h-3"}`}
      >
        {segments
          .filter((s) => s.count > 0)
          .map((s) => (
            <div key={s.key} className={`${s.cls} h-full`} style={{ width: `${(s.count / p.total) * 100}%` }} title={`${s.count} ${s.label}`} />
          ))}
      </div>
      <div className={`flex flex-wrap items-center gap-x-3 gap-y-1 text-xs ${compact ? "text-muted" : "text-fg"}`}>
        <span className="font-medium tabular-nums">{compact ? `${p.percent}% · ${p.finished}/${p.total}` : summary}</span>
        {!compact &&
          segments.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1 text-muted tabular-nums">
              <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${s.cls}`} />
              {s.count} {s.label}
            </span>
          ))}
        {compact && p.failed > 0 && <span className="text-danger tabular-nums">{p.failed} failed</span>}
      </div>
      {!compact && (
        <ol className="flex flex-wrap gap-1.5 text-xs" aria-label="Endpoints per stage">
          {DEPLOY_STAGES.map((s) => (
            <li
              key={s}
              className={`rounded-md border px-2 py-0.5 tabular-nums ${p.stages[s] > 0 ? "border-border-strong text-fg" : "border-border text-muted opacity-60"}`}
            >
              {STAGE_LABEL[s]} <b>{p.stages[s]}</b>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
