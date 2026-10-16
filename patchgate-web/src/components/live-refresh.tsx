"use client";

import { useEffect, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { liveIntervalMs, refreshDue, updatedAgoText } from "@/lib/views/live";

export interface LiveRefreshProps {
  /** Active work on the page (deployment running, jobs queued): refresh every 5 s instead of 30 s */
  active: boolean;
}

/**
 * Keeps a server-rendered page current: router.refresh() re-renders its Server Components with fresh data
 * (client state such as open forms is kept). Paused while the tab is hidden; refreshes right away when the
 * tab becomes visible again. Shows "Live · updated Xs ago".
 */
export function LiveRefresh({ active }: LiveRefreshProps) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [clock, setClock] = useState<{ now: number; last: number } | null>(null);

  useEffect(() => {
    let last = Date.now();
    const refresh = (now: number) => {
      last = now;
      startTransition(() => router.refresh());
    };
    const timer = window.setInterval(() => {
      const now = Date.now();
      if (refreshDue(now, last, active, document.visibilityState === "hidden")) refresh(now);
      setClock({ now, last });
    }, 1_000);
    const onVisible = () => {
      if (document.visibilityState !== "visible") return;
      const now = Date.now();
      if (now - last >= 2_000) refresh(now);
      setClock({ now, last });
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [active, router]);

  const every = Math.round(liveIntervalMs(active) / 1000);
  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs text-muted"
      title={`Refreshes every ${every} s while this tab is open${active ? " (work in progress)" : ""}; paused while the tab is hidden.`}
      data-testid="live-indicator"
      aria-live="off"
    >
      <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${pending ? "animate-pulse bg-busy" : "bg-success"}`} />
      Live · {pending ? "updating…" : clock ? updatedAgoText(clock.now, clock.last) : "updated just now"}
    </span>
  );
}
