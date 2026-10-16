/**
 * Prometheus text exposition format 0.0.4 (no dependencies). Pure: build families, then `renderFamilies`.
 *
 *   # HELP patchgate_endpoints Endpoints per bank.
 *   # TYPE patchgate_endpoints gauge
 *   patchgate_endpoints{bank="bank-a"} 1234
 */

export type MetricType = "gauge" | "counter";
export type Labels = Readonly<Record<string, string>>;

export interface Sample {
  labels?: Labels;
  value: number;
}

export interface MetricFamily {
  name: string;
  help: string;
  type: MetricType;
  samples: Sample[];
}

export const CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

const METRIC_NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const MAX_LABEL_VALUE = 200;

/** Label values: backslash, double quote and newline are escaped; long values are cut (cardinality/size guard). */
export function escapeLabelValue(v: string): string {
  const cut = v.length > MAX_LABEL_VALUE ? v.slice(0, MAX_LABEL_VALUE) : v;
  return cut.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/** HELP text: backslash and newline are escaped. */
export function escapeHelp(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n");
}

export function formatValue(v: number): string {
  if (Number.isNaN(v)) return "NaN";
  if (v === Infinity) return "+Inf";
  if (v === -Infinity) return "-Inf";
  return Number.isInteger(v) ? v.toString() : String(Number(v.toPrecision(12)));
}

function formatLabels(labels: Labels | undefined): string {
  if (!labels) return "";
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return "";
  const parts = keys.map((k) => {
    if (!LABEL_NAME_RE.test(k) || k.startsWith("__")) throw new Error(`invalid label name: ${k}`);
    return `${k}="${escapeLabelValue(labels[k])}"`;
  });
  return `{${parts.join(",")}}`;
}

/** One family; empty families still print HELP/TYPE so dashboards see the metric exists. */
export function renderFamily(f: MetricFamily): string {
  if (!METRIC_NAME_RE.test(f.name)) throw new Error(`invalid metric name: ${f.name}`);
  const lines = [`# HELP ${f.name} ${escapeHelp(f.help)}`, `# TYPE ${f.name} ${f.type}`];
  const seen = new Set<string>();
  for (const s of f.samples) {
    const labels = formatLabels(s.labels);
    if (seen.has(labels)) continue; // duplicate series are invalid exposition: keep the first
    seen.add(labels);
    lines.push(`${f.name}${labels} ${formatValue(s.value)}`);
  }
  return lines.join("\n");
}

export function renderFamilies(families: readonly MetricFamily[]): string {
  return `${families.map(renderFamily).join("\n")}\n`;
}

/** Small builder so collectors read like a list of metrics. */
export class Registry {
  private readonly families = new Map<string, MetricFamily>();

  private family(name: string, help: string, type: MetricType): MetricFamily {
    let f = this.families.get(name);
    if (!f) {
      f = { name, help, type, samples: [] };
      this.families.set(name, f);
    } else if (!f.help && help) {
      f.help = help;
    }
    return f;
  }

  /** Declare a family (printed even without samples). */
  declare(name: string, help: string, type: MetricType = "gauge"): void {
    this.family(name, help, type);
  }

  gauge(name: string, help: string, value: number, labels?: Labels): void {
    this.family(name, help, "gauge").samples.push({ labels, value });
  }

  counter(name: string, help: string, value: number, labels?: Labels): void {
    this.family(name, help, "counter").samples.push({ labels, value });
  }

  toFamilies(): MetricFamily[] {
    return [...this.families.values()];
  }

  render(): string {
    return renderFamilies(this.toFamilies());
  }
}
