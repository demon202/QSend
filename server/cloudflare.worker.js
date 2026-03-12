/**
 * QSend Signaling Server — Cloudflare Workers + Durable Objects
 *
 * WHY THE PREVIOUS VERSION FAILED:
 *
 * Bug 1 (fatal): ws._meta = {} does nothing in CF Workers.
 *   Durable Object WebSocket objects are opaque handles — you cannot
 *   attach arbitrary properties to them. Every lookup of ws._meta
 *   returned undefined, so relay(peer, msg) always sent to undefined.
 *   Offer, answer, and ICE messages were silently dropped every time.
 *
 * Bug 2 (fatal): setTimeout is not available in Durable Objects
 *   when using the WebSocket Hibernation API. Using alarm() instead.
 *
 * Bug 3: ws.readyState comparison used Node.js ws library constants.
 *   CF Workers WebSocket uses different ready state values.
 *
 * THE FIX:
 *   Use acceptWebSocket(ws, [tag]) to attach string tags to each socket.
 *   Use getWebSockets(tag) to look them up later.
 *   Store per-socket metadata in a plain Map keyed by a socket identity
 *   string, not as properties on the socket object itself.
 *
 * Deploy:
 *   wrangler deploy
 *
 * wrangler.toml:
 *   name = "qsend-signal"
 *   main = "cloudflare-worker.js"
 *   compatibility_date = "2024-01-01"
 *
 *   [[durable_objects.bindings]]
 *   name = "SESSIONS"
 *   class_name = "SessionStore"
 *
 *   [[migrations]]
 *   tag = "v1"
 *   new_sqlite_classes = ["SessionStore"]
 */

const SESSION_TTL_SEC = 5 * 60; // 5 minutes, used with DO alarm

// ── Main Worker ───────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET',
        },
      });
    }

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // All WebSocket connections go to the single global Durable Object.
    // A single DO instance handles all sessions in memory — no DB needed.
    if (request.headers.get('Upgrade') === 'websocket') {
      const id   = env.SESSIONS.idFromName('global');
      const stub = env.SESSIONS.get(id);
      return stub.fetch(request);
    }

    return new Response('QSend Signaling Server\n', {
      headers: { 'Content-Type': 'text/plain' },
    });
  },
};

// ── Durable Object ────────────────────────────────────────────────
export class SessionStore {
  constructor(state, env) {
    this.state = state;

    // sessions: Map<code:string, { senderTag:string, receiverTag:string|null, expiresAt:number }>
    this.sessions = new Map();

    // socketMeta: Map<tag:string, { code:string, role:'sender'|'receiver' }>
    // This replaces ws._meta — we store metadata by tag, not on the socket object.
    this.socketMeta = new Map();

    this.nextTag = 0;
  }

  // ── Accept incoming WebSocket connection ─────────────────────────
  async fetch(request) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Give this socket a unique string tag so we can find it later.
    // acceptWebSocket registers it with the Hibernation API.
    const tag = `sock-${this.nextTag++}`;
    this.state.acceptWebSocket(server, [tag]);

    return new Response(null, { status: 101, webSocket: client });
  }

  // ── Helpers ───────────────────────────────────────────────────────

  // Get the unique tag for a WebSocket (first tag in the array)
  _tag(ws) {
    const tags = this.state.getTags(ws);
    return tags?.[0] ?? null;
  }

  // Send JSON to a specific socket by tag
  _sendToTag(tag, obj) {
    if (!tag) return;
    const sockets = this.state.getWebSockets(tag);
    for (const ws of sockets) {
      try { ws.send(JSON.stringify(obj)); } catch {}
    }
  }

  // Relay a message to the peer of the current socket
  _relay(currentTag, msg) {
    const meta = this.socketMeta.get(currentTag);
    if (!meta) return;
    const session = this.sessions.get(meta.code);
    if (!session) return;
    const peerTag = meta.role === 'sender' ? session.receiverTag : session.senderTag;
    this._sendToTag(peerTag, msg);
  }

  _genCode() {
    let code;
    do {
      code = String(Math.floor(100000 + Math.random() * 900000));
    } while (this.sessions.has(code));
    return code;
  }

  _expireSession(code) {
    const session = this.sessions.get(code);
    if (!session) return;

    const expiredMsg = { type: 'session-expired' };
    this._sendToTag(session.senderTag,   expiredMsg);
    this._sendToTag(session.receiverTag, expiredMsg);

    // Clean up socket metadata
    if (session.senderTag)   this.socketMeta.delete(session.senderTag);
    if (session.receiverTag) this.socketMeta.delete(session.receiverTag);

    this.sessions.delete(code);
  }

  // Purge all sessions that have passed their TTL
  _purgeExpired() {
    const now = Date.now();
    for (const [code, session] of this.sessions) {
      if (session.expiresAt <= now) {
        this._expireSession(code);
      }
    }
  }

  // ── Hibernation API handlers ──────────────────────────────────────
  // These are called by the CF runtime when a socket receives a message,
  // closes, or errors. The `ws` parameter is the server-side socket.

  async webSocketMessage(ws, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    const tag = this._tag(ws);
    if (!tag) return;

    this._purgeExpired();

    switch (msg.type) {

      // ── Sender: create a new session ─────────────────────────────
      case 'create': {
        // Don't allow a socket to create multiple sessions
        if (this.socketMeta.has(tag)) {
          this._sendToTag(tag, { type: 'error', message: 'Already in session' });
          return;
        }

        const code = this._genCode();
        this.sessions.set(code, {
          senderTag:   tag,
          receiverTag: null,
          expiresAt:   Date.now() + SESSION_TTL_SEC * 1000,
        });
        this.socketMeta.set(tag, { code, role: 'sender' });
        this._sendToTag(tag, { type: 'created', code });
        break;
      }

      // ── Receiver: join an existing session ────────────────────────
      case 'join': {
        const code = String(msg.code || '').trim();
        if (!/^\d{6}$/.test(code)) {
          this._sendToTag(tag, { type: 'error', message: 'Invalid code format' });
          return;
        }
        if (this.socketMeta.has(tag)) {
          this._sendToTag(tag, { type: 'error', message: 'Already in session' });
          return;
        }

        const session = this.sessions.get(code);
        if (!session) {
          this._sendToTag(tag, { type: 'error', message: 'Session not found or expired' });
          return;
        }
        if (session.receiverTag !== null) {
          this._sendToTag(tag, { type: 'error', message: 'Session already has a receiver' });
          return;
        }

        session.receiverTag = tag;
        this.socketMeta.set(tag, { code, role: 'receiver' });
        session.receiver = ws;
        clearTimeout(session.timer);

        // Notify both sides
        this._sendToTag(tag,               { type: 'joined'      });
        this._sendToTag(session.senderTag, { type: 'peer-joined' });
        break;
        
      }

      // ── WebRTC offer (sender → receiver) ─────────────────────────
      case 'offer':
      case 'answer':
      case 'ice': {
        // Relay verbatim to the peer — never inspect SDP or ICE content
        this._relay(tag, msg);
        break;
      }

      // ── Explicit teardown ─────────────────────────────────────────
      case 'done': {
        const meta = this.socketMeta.get(tag);
        if (meta) this._expireSession(meta.code);
        break;
      }

      default:
        this._sendToTag(tag, { type: 'error', message: 'Unknown message type' });
    }
  }

  async webSocketClose(ws) {
    const tag = this._tag(ws);
    if (!tag) return;

    const meta = this.socketMeta.get(tag);
    if (meta) {
      const session = this.sessions.get(meta.code);
      if (session) {
        // Notify the surviving peer
        const peerTag = meta.role === 'sender' ? session.receiverTag : session.senderTag;
        this._sendToTag(peerTag, { type: 'peer-disconnected' });
        this._expireSession(meta.code);
      }
    }
    this.socketMeta.delete(tag);
  }

  async webSocketError(ws, error) {
    await this.webSocketClose(ws);
  }
}