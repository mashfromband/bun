// What `ca: []` does on each API that takes TLS options. Prints one JSON object for the mode in argv[2].
//
// env: CERT + KEY, a self-signed pair for localhost that is its own root. The pair is the server's identity, and
// the client's where a client certificate is wanted. NODE_EXTRA_CA_CERTS names a file that holds CERT, so the
// default trust of this process accepts the pair. OTHER_CA is a root that did not issue it.
//
// A mode is small and loads only the modules it uses: a debug build takes a second to load node:tls.
const { CERT: cert, KEY: key, OTHER_CA: otherCA } = process.env;

async function listen(server) {
  const { promise, resolve } = Promise.withResolvers();
  server.listen(0, "127.0.0.1", resolve);
  await promise;
  return server.address().port;
}

// "authorized", "unauthorized <code>" (the handshake completed) or "error <code>" (it was refused).
async function tlsConnect(port, options) {
  const tls = await import("node:tls");
  const { promise, resolve } = Promise.withResolvers();
  const socket = tls.connect({ host: "127.0.0.1", port, servername: "localhost", ...options }, () => {
    resolve(socket.authorized ? "authorized" : `unauthorized ${socket.authorizationError}`);
    socket.destroy();
  });
  socket.on("error", (err: NodeJS.ErrnoException) => resolve(`error ${err.code}`));
  return promise;
}

async function tlsServer() {
  const tls = await import("node:tls");
  const server = tls.createServer({ cert, key }, socket => socket.on("error", () => {}));
  return { server, port: await listen(server) };
}

// What a node:tls server makes of a client that presents CERT.
async function tlsServerSees(options, configure?) {
  const tls = await import("node:tls");
  const server = tls.createServer({ cert, key, ...options });
  configure?.(server);
  const { promise, resolve } = Promise.withResolvers();
  server.on("secureConnection", socket => {
    const peer = Object.keys(socket.getPeerCertificate()).length > 0 ? "a peer certificate" : "no peer certificate";
    resolve(`accepted, authorized=${socket.authorized}, ${peer}`);
    socket.end();
  });
  server.on("tlsClientError", () => resolve("rejected"));
  const port = await listen(server);
  const closed = Promise.withResolvers();
  const client = tls.connect({
    host: "127.0.0.1",
    port,
    servername: "localhost",
    cert,
    key,
    rejectUnauthorized: false,
  });
  client.on("error", () => {});
  client.on("close", closed.resolve);
  client.resume();
  const [outcome] = await Promise.all([promise, closed.promise]);
  server.close();
  return outcome;
}

const modes = {
  async "tls.connect"() {
    const { server, port } = await tlsServer();
    const result = {
      "no ca": await tlsConnect(port, {}),
      "ca: []": await tlsConnect(port, { ca: [] }),
      // The two must not share one cached context, in either order.
      "no ca, again": await tlsConnect(port, {}),
      "ca: [], rejectUnauthorized: false": await tlsConnect(port, { ca: [], rejectUnauthorized: false }),
    };
    server.close();
    return result;
  },

  async "tls.createSecureContext"() {
    const tls = await import("node:tls");
    const { server, port } = await tlsServer();
    const addedOtherCA = tls.createSecureContext({ ca: [] });
    addedOtherCA.context.addCACert(otherCA);
    const addedIssuer = tls.createSecureContext({ ca: [] });
    addedIssuer.context.addCACert(cert);
    const result = {
      "ca: []": await tlsConnect(port, { secureContext: tls.createSecureContext({ ca: [] }) }),
      "ca: [], then addCACert(another root)": await tlsConnect(port, { secureContext: addedOtherCA }),
      "ca: [], then addCACert(the issuer)": await tlsConnect(port, { secureContext: addedIssuer }),
    };
    server.close();
    return result;
  },

  // A stream that is not a socket takes the TLS engine that has no file descriptor.
  async "tls.connect over a Duplex"() {
    const tls = await import("node:tls");
    const net = await import("node:net");
    const { Duplex } = await import("node:stream");
    const { server, port } = await tlsServer();
    const overDuplex = options => {
      const raw = net.connect(port, "127.0.0.1");
      const duplex = new Duplex({
        read() {},
        write(chunk, encoding, callback) {
          raw.write(chunk, callback);
        },
        final(callback) {
          raw.end(callback);
        },
      });
      raw.on("data", chunk => duplex.push(chunk));
      raw.on("end", () => duplex.push(null));
      raw.on("error", err => duplex.destroy(err));
      return tlsConnect(port, { socket: duplex, ...options }).finally(() => raw.destroy());
    };
    const result = {
      "no ca": await overDuplex({}),
      "ca: []": await overDuplex({ ca: [] }),
      "secureContext: createSecureContext({ ca: [] })": await overDuplex({
        secureContext: tls.createSecureContext({ ca: [] }),
      }),
    };
    server.close();
    return result;
  },

  async "tls.setDefaultCACertificates([])"() {
    const tls = await import("node:tls");
    const { server, port } = await tlsServer();
    const result = { "no ca, before the call": await tlsConnect(port, {}) };
    tls.setDefaultCACertificates([]);
    result["no ca"] = await tlsConnect(port, {});
    // A falsy `ca` is not given, so it takes the defaults, which are empty now.
    result["ca: ''"] = await tlsConnect(port, { ca: "" });
    server.close();
    return result;
  },

  async "https.get"() {
    const https = await import("node:https");
    const server = https.createServer({ cert, key }, (req, res) => res.end("ok"));
    const port = await listen(server);
    const get = options => {
      const { promise, resolve } = Promise.withResolvers();
      https
        .get({ host: "127.0.0.1", port, servername: "localhost", agent: false, ...options }, res => {
          res.resume();
          resolve(`status ${res.statusCode}`);
        })
        .on("error", (err: NodeJS.ErrnoException) => resolve(`error ${err.code}`));
      return promise;
    };
    const result = { "no ca": await get({}), "ca: []": await get({ ca: [] }) };
    server.close();
    return result;
  },

  async "http2.connect"() {
    const http2 = await import("node:http2");
    const server = http2.createSecureServer({ cert, key });
    const port = await listen(server);
    const connect = options => {
      const { promise, resolve } = Promise.withResolvers();
      const session = http2.connect(`https://127.0.0.1:${port}`, options, () => {
        resolve("connected");
        session.destroy();
      });
      session.on("error", (err: NodeJS.ErrnoException) => resolve(`error ${err.code}`));
      return promise;
    };
    const result = { "no ca": await connect({}), "ca: []": await connect({ ca: [] }) };
    server.close();
    return result;
  },

  async "tls.createServer, requestCert"() {
    const asks = { requestCert: true, rejectUnauthorized: false };
    return {
      "no ca": await tlsServerSees(asks),
      "ca: []": await tlsServerSees({ ...asks, ca: [] }),
      "ca: [], rejectUnauthorized": await tlsServerSees({ requestCert: true, rejectUnauthorized: true, ca: [] }),
    };
  },

  async "tls.Server"() {
    const asks = { requestCert: true, rejectUnauthorized: false };
    return {
      "requestCert, then setSecureContext({ ca: [] })": await tlsServerSees(asks, server =>
        server.setSecureContext({ cert, key, ca: [] }),
      ),
      "requestCert, then addContext('localhost', { ca: [] })": await tlsServerSees(asks, server =>
        server.addContext("localhost", { cert, key, ca: [] }),
      ),
      // Without requestCert a server asks for no certificate, whatever `ca` is.
      "ca: [], no requestCert": await tlsServerSees({ ca: [] }),
    };
  },

  async "fetch, WebSocket, Bun.connect"() {
    using server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      tls: { cert, key },
      fetch(req, server) {
        if (server.upgrade(req)) return;
        return new Response("ok");
      },
      websocket: { message() {} },
    });
    const doFetch = tls =>
      fetch(`https://127.0.0.1:${server.port}/`, { tls, keepalive: false }).then(
        res => `status ${res.status}`,
        err => `error ${err.code}`,
      );
    const webSocket = tls => {
      const { promise, resolve } = Promise.withResolvers();
      const ws = new WebSocket(`wss://127.0.0.1:${server.port}/`, { tls });
      ws.onopen = () => {
        resolve("open");
        ws.close();
      };
      ws.onerror = () => resolve("error");
      return promise;
    };
    const bunConnect = tls => {
      const { promise, resolve } = Promise.withResolvers();
      Bun.connect({
        hostname: "127.0.0.1",
        port: server.port!,
        tls,
        socket: {
          // A socket without TLS sends this in the clear, and the server hangs up on it.
          open(socket) {
            socket.write("hello");
          },
          handshake(socket, success, verifyError: NodeJS.ErrnoException | null) {
            resolve(socket.authorized ? "authorized" : `unauthorized ${verifyError?.code}`);
            socket.end();
          },
          data() {},
          connectError(socket, err: NodeJS.ErrnoException) {
            resolve(`error ${err.code}`);
          },
          error(socket, err: NodeJS.ErrnoException) {
            resolve(`error ${err.code}`);
          },
          close() {
            resolve("closed without a TLS handshake");
          },
        },
      }).catch(err => resolve(`error ${err.code}`));
      return promise;
    };
    return {
      "fetch": { "no ca": await doFetch(undefined), "ca: []": await doFetch({ ca: [] }) },
      "WebSocket": { "no ca": await webSocket(undefined), "ca: []": await webSocket({ ca: [] }) },
      "Bun.connect": {
        "tls: true": await bunConnect(true),
        // `ca` is the only TLS option here, and it still asks for TLS.
        "ca: []": await bunConnect({ ca: [] }),
      },
    };
  },

  // The second request must not ride the tunnel that the first one left in the keep-alive pool: the peer on it was
  // verified against the default roots.
  async "fetch through a CONNECT proxy"() {
    using origin = Bun.serve({ port: 0, hostname: "127.0.0.1", tls: { cert, key }, fetch: () => new Response("ok") });
    let connects = 0;
    const upstreams = new Map();
    using proxy = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data(client, chunk) {
          if (upstreams.has(client)) return void upstreams.get(client).write(chunk);
          connects++;
          Bun.connect({
            hostname: "127.0.0.1",
            port: origin.port!,
            socket: {
              open(upstream) {
                upstreams.set(client, upstream);
                client.write("HTTP/1.1 200 Connection established\r\n\r\n");
              },
              data(upstream, chunk) {
                client.write(chunk);
              },
              close() {
                client.end();
              },
              error() {},
            },
          });
        },
        close(client) {
          upstreams.get(client)?.end();
        },
        error() {},
      },
    });
    const get = tls =>
      fetch(`https://127.0.0.1:${origin.port}/`, { proxy: `http://127.0.0.1:${proxy.port}`, tls }).then(
        async res => `status ${res.status} ${await res.text()}`,
        err => `error ${err.code}`,
      );
    return {
      "serverName": await get({ serverName: "localhost" }),
      "serverName, ca: []": await get({ serverName: "localhost", ca: [] }),
      "CONNECT requests": connects,
    };
  },

  // What a Bun server makes of a client with and without a certificate that a default root issued.
  async "Bun.serve, Bun.listen"() {
    const request = (port, tls) =>
      fetch(`https://127.0.0.1:${port}/`, { tls, keepalive: false }).then(
        res => `status ${res.status}`,
        () => "refused",
      );
    const serve = async tls => {
      using server = Bun.serve({
        port: 0,
        hostname: "127.0.0.1",
        tls: { cert, key, ...tls },
        fetch: () => new Response("ok"),
      });
      return {
        "client certificate": await request(server.port, { cert, key }),
        "no client certificate": await request(server.port, undefined),
      };
    };
    // The listener says what it made of the client once the handshake is done. "refused" when it hangs up first.
    const dial = (port, tls) => {
      const { promise, resolve } = Promise.withResolvers();
      Bun.connect({
        hostname: "127.0.0.1",
        port,
        tls,
        socket: {
          data(socket, data) {
            resolve(data.toString());
            socket.end();
          },
          error() {},
          connectError() {
            resolve("refused");
          },
          close() {
            resolve("refused");
          },
        },
      }).catch(() => resolve("refused"));
      return promise;
    };
    const listen = async tls => {
      using listener = Bun.listen({
        hostname: "127.0.0.1",
        port: 0,
        tls: { cert, key, ...tls },
        socket: {
          handshake(socket, success) {
            if (success) socket.write(`accepted, authorized=${socket.authorized}`);
          },
          data() {},
          error() {},
        },
      });
      return {
        "client certificate": await dial(listener.port, { cert, key }),
        "no client certificate": await dial(listener.port, true),
      };
    };
    return {
      "Bun.serve": {
        "requestCert, no ca": await serve({ requestCert: true }),
        "requestCert, ca: []": await serve({ requestCert: true, ca: [] }),
        "ca: [], no requestCert": await serve({ ca: [] }),
      },
      "Bun.listen": {
        "requestCert, no ca": await listen({ requestCert: true }),
        "requestCert, ca: []": await listen({ requestCert: true, ca: [] }),
        "ca: [], no requestCert": await listen({ ca: [] }),
      },
    };
  },
};

console.log(JSON.stringify(await modes[process.argv[2]](), null, 2));
process.exit(0);
