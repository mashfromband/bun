// A `ca` that is given replaces the default roots, also when it lists no certificate: then no CA is trusted.
// https://github.com/nodejs/node/blob/v26.3.0/lib/internal/tls/secure-context.js#L177-L184
import { spawn } from "bun";
import { describe, expect, test } from "bun:test";
import { bunEnv, bunExe, tls as pair, tempDir } from "harness";
import { join } from "path";

// A debug build takes seconds to start a child and to load node:tls, node:https or node:http2.
const timeout = 30_000;

// In each child the certificate in use is a default root (NODE_EXTRA_CA_CERTS), so a "no ca" row is authorized
// and a `ca: []` row is refused only because the empty list took the place of the defaults.
describe("an empty ca list trusts no certificate", () => {
  const refused = "error DEPTH_ZERO_SELF_SIGNED_CERT";
  const unauthorized = "unauthorized DEPTH_ZERO_SELF_SIGNED_CERT";
  const expected = {
    "tls.connect": {
      "no ca": "authorized",
      "ca: []": refused,
      "no ca, again": "authorized",
      "ca: [], rejectUnauthorized: false": unauthorized,
    },
    "tls.createSecureContext": {
      "ca: []": refused,
      "ca: [], then addCACert(another root)": refused,
      "ca: [], then addCACert(the issuer)": "authorized",
    },
    "tls.connect over a Duplex": {
      "no ca": "authorized",
      "ca: []": refused,
      "secureContext: createSecureContext({ ca: [] })": refused,
    },
    "tls.setDefaultCACertificates([])": {
      "no ca, before the call": "authorized",
      "no ca": refused,
      "ca: ''": refused,
    },
    "https.get": { "no ca": "status 200", "ca: []": refused },
    "http2.connect": { "no ca": "connected", "ca: []": refused },
    "tls.createServer, requestCert": {
      "no ca": "accepted, authorized=true, a peer certificate",
      "ca: []": "accepted, authorized=false, a peer certificate",
      "ca: [], rejectUnauthorized": "rejected",
    },
    "tls.Server": {
      "requestCert, then setSecureContext({ ca: [] })": "accepted, authorized=false, a peer certificate",
      "requestCert, then addContext('localhost', { ca: [] })": "accepted, authorized=false, a peer certificate",
      "ca: [], no requestCert": "accepted, authorized=false, no peer certificate",
    },
    "fetch, WebSocket, Bun.connect": {
      "fetch": { "no ca": "status 200", "ca: []": refused },
      "WebSocket": { "no ca": "open", "ca: []": "error" },
      "Bun.connect": { "tls: true": "authorized", "ca: []": unauthorized },
    },
    "fetch through a CONNECT proxy": {
      "serverName": "status 200 ok",
      "serverName, ca: []": refused,
      "CONNECT requests": 2,
    },
    "Bun.serve, Bun.listen": {
      "Bun.serve": {
        "requestCert, no ca": { "client certificate": "status 200", "no client certificate": "refused" },
        "requestCert, ca: []": { "client certificate": "refused", "no client certificate": "refused" },
        "ca: [], no requestCert": { "client certificate": "status 200", "no client certificate": "status 200" },
      },
      "Bun.listen": {
        "requestCert, no ca": { "client certificate": "accepted, authorized=true", "no client certificate": "refused" },
        "requestCert, ca: []": { "client certificate": "refused", "no client certificate": "refused" },
        "ca: [], no requestCert": {
          "client certificate": "accepted, authorized=false",
          "no client certificate": "accepted, authorized=false",
        },
      },
    },
  };

  for (const [mode, rows] of Object.entries(expected)) {
    test.concurrent(
      mode,
      async () => {
        using dir = tempDir("ca-empty", { "root.pem": pair.cert });
        await using proc = spawn({
          cmd: [bunExe(), join(import.meta.dir, "node-tls-ca-empty.fixture.ts"), mode],
          env: {
            ...bunEnv,
            NODE_EXTRA_CA_CERTS: join(String(dir), "root.pem"),
            CERT: pair.cert,
            KEY: pair.key,
            OTHER_CA: await Bun.file(join(import.meta.dir, "..", "test", "fixtures", "keys", "ca2-cert.pem")).text(),
          },
          stdout: "pipe",
          stderr: "pipe",
        });
        const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
        let printed: unknown = stdout;
        try {
          printed = JSON.parse(stdout);
        } catch {}
        expect({ rows: printed, stderr, exitCode }).toEqual({ rows, stderr: "", exitCode: 0 });
      },
      timeout,
    );
  }
});

// The default roots are loaded for a context that trusts them, and for no other. The load is visible here:
// it warns about a NODE_EXTRA_CA_CERTS file that does not exist.
test.concurrent(
  "a context that was given a ca does not load the default roots",
  async () => {
    using dir = tempDir("ca-empty-no-defaults", { "ca.pem": pair.cert });
    const listen = async (contexts: string) => {
      await using proc = spawn({
        cmd: [
          bunExe(),
          "-e",
          `const ca = require("node:fs").readFileSync("ca.pem", "utf8");
          for (const tls of ${contexts}) {
            Bun.listen({ hostname: "127.0.0.1", port: 0, tls, socket: { data() {} } }).stop(true);
          }`,
        ],
        env: { ...bunEnv, NODE_EXTRA_CA_CERTS: "missing.pem" },
        cwd: String(dir),
        stdout: "ignore",
        stderr: "pipe",
      });
      const [stderr, exitCode] = await Promise.all([proc.stderr.text(), proc.exited]);
      return { stderr, exitCode };
    };
    const [givenCA, noCA] = await Promise.all([
      listen(`[{ ca: [] }, { ca: [], allowPartialTrustChain: true }, { ca, allowPartialTrustChain: true }]`),
      listen(`[{ allowPartialTrustChain: true }]`),
    ]);
    expect({ givenCA, noCA }).toEqual({
      givenCA: { stderr: "", exitCode: 0 },
      noCA: {
        stderr: "Warning: Ignoring extra certs from `missing.pem`, load failed: No such file or directory\n",
        exitCode: 0,
      },
    });
  },
  timeout,
);
