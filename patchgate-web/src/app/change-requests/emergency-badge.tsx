import { Siren } from "lucide-react";

/** Shown wherever an emergency change request appears (list, detail). */
export function EmergencyBadge() {
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-full bg-danger px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide text-white">
      <Siren size={12} aria-hidden /> Emergency
    </span>
  );
}
