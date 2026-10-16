import { runChecks } from "./check.ts";
import { ConfigError, loadConfig, requireEnrolled } from "./config.ts";
import { runInit } from "./init.ts";
import { startService } from "./service.ts";
import { createLogger, errorMessage, type LogLevel } from "./util/log.ts";
import { CONNECTOR_VERSION } from "./version.ts";

/**
 * patchgate-connector <command> --config <path> [options]
 *   init   --server https://patchgate.example.com --code XXXX-XXXX-XXXX-XXXX-XXXX --job-key-fingerprint <sha256 hex>
 *          [--ca <pem>] [--force] [--insecure-dev]
 *   run    the service (SIGTERM/SIGINT; on Windows also Ctrl+Break/SIGBREAK, console close and service
 *          stop through a wrapper = graceful shutdown)
 *   check  probe config, Tactical, cache dir, PatchGate (and SIEM); exit 0 = healthy, 1 = unhealthy
 *   version
 * The enrolment code may also be given as env PATCHGATE_ENROLL_CODE (keeps it out of the process list).
 */

export const EXIT = { ok: 0, unhealthy: 1, usage: 2, config: 3, runtime: 4 } as const;

const USAGE = `usage: patchgate-connector <init|run|check|version> --config <path>
  init  --server <https://...> --code <XXXX-XXXX-XXXX-XXXX-XXXX> --job-key-fingerprint <sha256 hex>
        [--ca <pem>] [--force] [--insecure-dev]
  run
  check`;

/** Signals that mean "stop gracefully" on this platform. */
export function shutdownSignals(platform: NodeJS.Platform): NodeJS.Signals[] {
  // Windows: Ctrl+C = SIGINT, Ctrl+Break = SIGBREAK (what service wrappers such as WinSW/NSSM send),
  // console window closed / logoff = SIGHUP. Node never delivers SIGTERM from the Windows SCM itself.
  return platform === "win32" ? ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] : ["SIGTERM", "SIGINT"];
}

type ShutdownProcess = Pick<NodeJS.Process, "on" | "off"> & { send?: unknown };

/**
 * Calls `onStop` once on the first shutdown request: a stop signal, or the IPC message "shutdown" that
 * Windows process managers (e.g. PM2 on Windows) send instead of a signal. Returns an unsubscribe fn.
 */
export function onShutdownRequest(proc: ShutdownProcess, platform: NodeJS.Platform, onStop: (reason: string) => void): () => void {
  const signals = shutdownSignals(platform);
  let fired = false;
  const fire = (reason: string) => {
    if (fired) return;
    fired = true;
    off();
    onStop(reason);
  };
  const onSignal = (sig: NodeJS.Signals) => fire(sig);
  const onMessage = (msg: unknown) => {
    if (msg === "shutdown" || (typeof msg === "object" && msg !== null && (msg as { type?: unknown }).type === "shutdown")) fire("ipc:shutdown");
  };
  const off = () => {
    for (const s of signals) proc.off(s, onSignal);
    proc.off("message", onMessage);
  };
  for (const s of signals) proc.on(s, onSignal);
  if (typeof proc.send === "function") proc.on("message", onMessage);
  return off;
}

export interface ParsedArgs {
  command: string | undefined;
  flags: Record<string, string | true>;
}

const VALUE_FLAGS = new Set(["config", "server", "code", "ca", "job-key-fingerprint"]);
const BOOL_FLAGS = new Set(["insecure-dev", "force", "help"]);

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const flags: Record<string, string | true> = {};
  let command: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a.startsWith("--")) {
      const [name, inline] = a.slice(2).split("=", 2) as [string, string | undefined];
      if (VALUE_FLAGS.has(name)) {
        const v = inline ?? argv[++i];
        if (v === undefined || v.startsWith("--")) throw new ConfigError(`--${name} needs a value`);
        flags[name] = v;
      } else if (BOOL_FLAGS.has(name)) {
        flags[name] = true;
      } else {
        throw new ConfigError(`unknown option --${name}`);
      }
    } else if (command === undefined) {
      command = a;
    } else {
      throw new ConfigError(`unexpected argument ${a}`);
    }
  }
  return { command, flags };
}

function str(f: ParsedArgs["flags"], k: string): string | undefined {
  const v = f[k];
  return typeof v === "string" ? v : undefined;
}

export async function main(argv: readonly string[]): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`${errorMessage(err)}\n${USAGE}\n`);
    return EXIT.usage;
  }
  if (args.command === "version") {
    process.stdout.write(`${CONNECTOR_VERSION}\n`);
    return EXIT.ok;
  }
  if (!args.command || args.flags.help || !["init", "run", "check"].includes(args.command)) {
    process.stderr.write(`${USAGE}\n`);
    return args.flags.help ? EXIT.ok : EXIT.usage;
  }
  const configPath = str(args.flags, "config") ?? process.env.PATCHGATE_CONNECTOR_CONFIG;
  if (!configPath) {
    process.stderr.write(`--config is required\n${USAGE}\n`);
    return EXIT.usage;
  }

  let log = createLogger({ level: "info", base: { svc: "patchgate-connector" } });
  try {
    if (args.command === "init") {
      const server = str(args.flags, "server");
      const code = str(args.flags, "code") ?? process.env.PATCHGATE_ENROLL_CODE;
      if (!server || !code) {
        process.stderr.write(`init needs --server and --code\n${USAGE}\n`);
        return EXIT.usage;
      }
      const cfg = await runInit({
        configPath,
        serverUrl: server,
        code,
        caFile: str(args.flags, "ca"),
        jobKeyFingerprint: str(args.flags, "job-key-fingerprint") ?? process.env.PATCHGATE_JOB_KEY_FINGERPRINT,
        insecureDev: args.flags["insecure-dev"] === true,
        force: args.flags.force === true,
        version: CONNECTOR_VERSION,
        log,
      });
      process.stdout.write(`${JSON.stringify({ enrolled: true, connectorId: cfg.identity.connectorId, tenantId: cfg.identity.tenantId, name: cfg.identity.name })}\n`);
      return EXIT.ok;
    }

    const cfg = await loadConfig(configPath);
    log = createLogger({ level: cfg.logLevel as LogLevel, base: { svc: "patchgate-connector" } });

    if (args.command === "check") {
      const results = await runChecks(cfg, CONNECTOR_VERSION);
      for (const r of results) process.stdout.write(`${JSON.stringify(r)}\n`);
      const healthy = results.every((r) => r.ok);
      process.stdout.write(`${JSON.stringify({ healthy })}\n`);
      return healthy ? EXIT.ok : EXIT.unhealthy;
    }

    // run
    const enrolled = requireEnrolled(cfg);
    if (enrolled.insecureDev) log.warn("insecureDev is ON: http/tcp allowed. Never use this in a bank.");
    const svc = await startService(enrolled, { log, version: CONNECTOR_VERSION });
    await new Promise<void>((resolve) => {
      onShutdownRequest(process, process.platform, (reason) => {
        log.info("shutdown requested", { reason });
        svc.stop().then(resolve, (err: unknown) => {
          log.error("error during shutdown", { err });
          resolve();
        });
      });
    });
    return EXIT.ok;
  } catch (err) {
    if (err instanceof ConfigError) {
      log.error(err.message);
      return EXIT.config;
    }
    log.error("fatal", { error: errorMessage(err) });
    return EXIT.runtime;
  }
}

// Entry point (bundle and `tsx src/cli.ts`); importing this module from tests does not run it.
const isEntry = (() => {
  const entry = process.argv[1] ?? "";
  return /(?:^|[\\/])(cli\.ts|patchgate-connector(\.mjs)?)$/.test(entry);
})();
if (isEntry) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err: unknown) => {
      process.stderr.write(`fatal: ${errorMessage(err)}\n`);
      process.exit(EXIT.runtime);
    },
  );
}
