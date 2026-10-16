// Lab SIEM: TLS syslog receiver (RFC 5425 / RFC 6587 octet counting) with the lab server certificate.
// Stands in for the bank SIEM (Splunk/QRadar/Sentinel). Every record is appended to received.log.
// Usage: node lab/siem/receiver.mjs [port=6514]
import { appendFileSync, readFileSync } from "node:fs";
import { createServer } from "node:tls";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const certs = join(here, "..", "certs", "out");
const port = Number(process.argv[2] ?? 6514);
const out = join(here, "received.log");

const server = createServer(
  { key: readFileSync(join(certs, "server.key")), cert: readFileSync(join(certs, "fullchain.crt")), minVersion: "TLSv1.2" },
  (sock) => {
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (chunk) => {
      buf += chunk;
      // octet-counting frames: "<len> <msg>"
      for (;;) {
        const sp = buf.indexOf(" ");
        if (sp < 1) break;
        const len = Number(buf.slice(0, sp));
        if (!Number.isInteger(len)) { buf = ""; break; }
        const rest = Buffer.from(buf.slice(sp + 1), "utf8");
        if (rest.length < len) break;
        const msg = rest.subarray(0, len).toString("utf8");
        buf = rest.subarray(len).toString("utf8");
        appendFileSync(out, msg + "\n");
      }
    });
    sock.on("error", () => {});
  },
);
server.listen(port, "0.0.0.0", () => console.log(`lab SIEM listening on tls://0.0.0.0:${port} -> ${out}`));
