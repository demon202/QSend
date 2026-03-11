/**
 * QSend Signaling Server — Cloudflare Workers + Durable Objects
 *
 * Deploy:
 *   npm install -g wrangler
 *   wrangler publish
 *
 * wrangler.toml must define:
 *   [[durable_objects.bindings]]
 *   name = "SESSIONS"
 *   class_name = "SessionStore"
 *
 * NOTE: Cloudflare Workers supports WebSockets natively via the
 * WebSocketPair API. Sessions live in a Durable Object for
 * cross-datacenter state (still stateless from a storage perspective).
 */

const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ── Main Worker entry point ───────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // WebSocket upgrade
    if (request.headers.get('Upgrade') === 'websocket') {
      // Route to the Durable Object for this session
      const id     = env.SESSIONS.idFromName('global');
      const stub   = env.SESSIONS.get(id);
      return stub.fetch(request);
    }

    return new Response('QSend Signaling Server', {
      headers: { 'Content-Type': 'text/plain' },
    });
  },
};

// ── Durable Object: SessionStore ─────────────────────────────
export class SessionStore {
  constructor(state) {
    this.state    = state;
    this.sessions = new Map(); // code → { sender, receiver, timer }
    this.sockets  = new Map(); // ws   → { code, role }
  }

  async fetch(request) {
    const [client, server] = Object.values(new WebSocketPair());
    this.state.acceptWebSocket(server);
    server._meta = {};
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    let msg;
    try { msg = JSON.parse(message); } catch { return; }
    this.handleMessage(ws, msg);
  }

  async webSocketClose(ws) {
    const meta = ws._meta || {};
    if (meta.code) {
      const session = this.sessions.get(meta.code);
      if (session) {
        const peer = meta.role === 'sender' ? session.receiver : session.sender;
        this.relay(peer, { type: 'peer-disconnected' });
        clearTimeout(session.timer);
        this.sessions.delete(meta.code);
      }
    }
  }

  handleMessage(ws, msg) {
    switch (msg.type) {
      case 'create': {
        const code  = this.genCode();
        const timer = setTimeout(() => this.expire(code), SESSION_TTL_MS);
        this.sessions.set(code, { sender: ws, receiver: null, timer });
        ws._meta = { code, role: 'sender' };
        this.relay(ws, { type: 'created', code });
        break;
      }
      case 'join': {
        const { code } = msg;
        if (!code || !/^\d{6}$/.test(code)) {
          this.relay(ws, { type: 'error', message: 'Invalid code' });
          return;
        }
        const session = this.sessions.get(code);
        if (!session) {
          this.relay(ws, { type: 'error', message: 'Session not found' });
          return;
        }
        if (session.receiver) {
          this.relay(ws, { type: 'error', message: 'Session full' });
          return;
        }
        session.receiver = ws;
        ws._meta = { code, role: 'receiver' };
        this.relay(ws,           { type: 'joined'      });
        this.relay(session.sender, { type: 'peer-joined' });
        break;
      }
      case 'offer':
      case 'answer':
      case 'ice': {
        const { code, role } = ws._meta || {};
        if (!code) return;
        const session = this.sessions.get(code);
        if (!session) return;
        const peer = role === 'sender' ? session.receiver : session.sender;
        this.relay(peer, msg);
        break;
      }
      case 'done': {
        const { code } = ws._meta || {};
        if (code) this.expire(code);
        break;
      }
    }
  }

  relay(ws, obj) {
    try {
      if (ws && ws.readyState === 1 /* OPEN */) {
        ws.send(JSON.stringify(obj));
      }
    } catch {}
  }

  expire(code) {
    const session = this.sessions.get(code);
    if (!session) return;
    clearTimeout(session.timer);
    const msg = { type: 'session-expired' };
    this.relay(session.sender,   msg);
    this.relay(session.receiver, msg);
    this.sessions.delete(code);
  }

  genCode() {
    let code;
    do {
      code = String(Math.floor(100000 + Math.random() * 900000));
    } while (this.sessions.has(code));
    return code;
  }
}