// PatchGate colleague test kit — stand-in for the platform SIEM (TEST KIT ONLY, not product code).
// A syslog-over-TLS receiver (RFC 5425 octet-counting frames) that accepts PatchGate's audit export and counts
// the records. PatchGate's readiness check (siemExport) and smoke test need a SIEM that really receives the
// audit chain; a bank-grade installation points SIEM_SYSLOG_URL at its real SIEM.
//   node siem-sink.mjs   (env: SIEM_DIR with cert.pem + key.pem, PORT default 6514)
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:tls";

const dir = process.env.SIEM_DIR ?? "/siem";
const port = Number(process.env.PORT ?? 6514);
let records = 0;
let connections = 0;
const status = () =>
  writeFileSync(`${dir}/received.txt`, `connections=${connections} records=${records} updated=${new Date().toISOString()}\n`);

const server = createServer({ key: readFileSync(`${dir}/key.pem`), cert: readFileSync(`${dir}/cert.pem`), minVersion: "TLSv1.2" }, (sock) => {
  connections++;
  let buf = Buffer.alloc(0);
  sock.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    // Octet counting: "<len> <msg>" repeated (len in bytes).
    for (;;) {
      const sp = buf.indexOf(0x20);
      if (sp < 1 || sp > 10) break;
      const len = Number(buf.subarray(0, sp).toString("ascii"));
      if (!Number.isInteger(len) || buf.length < sp + 1 + len) break;
      buf = buf.subarray(sp + 1 + len);
      records++;
    }
  });
  sock.on("end", () => {
    sock.end();
    status();
  });
  sock.on("error", () => sock.destroy());
});
server.listen(port, "0.0.0.0", () => console.log(`test SIEM listening on tls/${port}`));
status();
