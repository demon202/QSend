/**
 * QSend Signaling Server — Cloudflare Workers + Durable Objects
 *
 * ROOT CAUSE OF "Session not found or expired" ON FIRST TRANSFER:
 *
 *   Durable Objects using the WebSocket Hibernation API (acceptWebSocket)
 *   are evicted from memory between messages to save resources. When the
 *   DO wakes up, the constructor runs again and this.sessions = new Map()
 *   is EMPTY — the session the sender just created is gone.
 *
 * FIX:
 *   Store all session data in this.state.storage (persistent KV),
 *   not in in-memory Maps. Storage survives hibernation indefinitely.
 *
 *   socketMeta (tag → {code, role}) is ALSO stored in persistent storage
 *   because the socket's tag is our only link back to its session when
 *   the DO wakes up from hibernation.
 *
 * TAG SCHEME:
 *   Each WebSocket gets a unique tag: `ws-{timestamp}-{random}`
 *   Storage keys:
 *     session:{code}  → { senderTag, receiverTag|null, expiresAt }
 *     meta:{tag}      → { code, role: 'sender'|'receiver' }
 */

const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ── Main Worker ───────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET',
        },
      });
    }

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

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
    // NO in-memory Maps — everything goes to this.state.storage
    // so it survives DO hibernation.
  }

  // ── Accept incoming WebSocket connection ─────────────────────────
  async fetch(request) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    const tag = `ws-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    this.state.acceptWebSocket(server, [tag]);

    return new Response(null, { status: 101, webSocket: client });
  }

  // ── Storage helpers ───────────────────────────────────────────────

  _tag(ws) {
    return this.state.getTags(ws)?.[0] ?? null;
  }

  async _send(tag, obj) {
    if (!tag) return;
    for (const ws of this.state.getWebSockets(tag)) {
      try { ws.send(JSON.stringify(obj)); } catch {}
    }
  }

  async _getSession(code)        { return (await this.state.storage.get(`session:${code}`)) ?? null; }
  async _setSession(code, val)   { await this.state.storage.put(`session:${code}`, val); }
  async _delSession(code)        { await this.state.storage.delete(`session:${code}`); }

  async _getMeta(tag)            { return (await this.state.storage.get(`meta:${tag}`)) ?? null; }
  async _setMeta(tag, val)       { await this.state.storage.put(`meta:${tag}`, val); }
  async _delMeta(tag)            { await this.state.storage.delete(`meta:${tag}`); }

  async _expireSession(code) {
    const session = await this._getSession(code);
    if (!session) return;

    await this._send(session.senderTag,   { type: 'session-expired' });
    await this._send(session.receiverTag, { type: 'session-expired' });

    if (session.senderTag)   await this._delMeta(session.senderTag);
    if (session.receiverTag) await this._delMeta(session.receiverTag);
    await this._delSession(code);
  }

  // ── Hibernation API ───────────────────────────────────────────────

  async webSocketMessage(ws, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    const tag = this._tag(ws);
    if (!tag) return;

    switch (msg.type) {

      case 'create': {
        if (await this._getMeta(tag)) {
          await this._send(tag, { type: 'error', message: 'Already in session' });
          return;
        }

        // Generate unique code
        let code, attempts = 0;
        do {
          code = String(Math.floor(100000 + Math.random() * 900000));
          attempts++;
        } while ((await this._getSession(code)) && attempts < 20);

        await this._setSession(code, {
          senderTag:   tag,
          receiverTag: null,
          expiresAt:   Date.now() + SESSION_TTL_MS,
        });
        await this._setMeta(tag, { code, role: 'sender' });
        await this._send(tag, { type: 'created', code });
        break;
      }

      case 'join': {
        const code = String(msg.code || '').trim();
        if (!/^\d{6}$/.test(code)) {
          await this._send(tag, { type: 'error', message: 'Invalid code format' });
          return;
        }
        if (await this._getMeta(tag)) {
          await this._send(tag, { type: 'error', message: 'Already in session' });
          return;
        }

        const session = await this._getSession(code);
        if (!session) {
          await this._send(tag, { type: 'error', message: 'Session not found or expired' });
          return;
        }
        if (Date.now() > session.expiresAt) {
          await this._expireSession(code);
          await this._send(tag, { type: 'error', message: 'Session not found or expired' });
          return;
        }
        if (session.receiverTag !== null) {
          await this._send(tag, { type: 'error', message: 'Session already has a receiver' });
          return;
        }

        session.receiverTag = tag;
        await this._setSession(code, session);
        await this._setMeta(tag, { code, role: 'receiver' });

        await this._send(tag,               { type: 'joined'      });
        await this._send(session.senderTag, { type: 'peer-joined' });
        break;
      }

      case 'offer':
      case 'answer':
      case 'ice': {
        const meta = await this._getMeta(tag);
        if (!meta) return;
        const session = await this._getSession(meta.code);
        if (!session) return;
        const peerTag = meta.role === 'sender' ? session.receiverTag : session.senderTag;
        await this._send(peerTag, msg);
        break;
      }

      case 'done': {
        const meta = await this._getMeta(tag);
        if (meta) await this._expireSession(meta.code);
        break;
      }

      default:
        await this._send(tag, { type: 'error', message: 'Unknown message type' });
    }
  }

  async webSocketClose(ws) {
    const tag = this._tag(ws);
    if (!tag) return;
    const meta = await this._getMeta(tag);
    if (!meta) return;

    const session = await this._getSession(meta.code);
    if (session) {
      const peerTag = meta.role === 'sender' ? session.receiverTag : session.senderTag;
      await this._send(peerTag, { type: 'peer-disconnected' });
      await this._expireSession(meta.code);
    }
    await this._delMeta(tag);
  }

  async webSocketError(ws) {
    await this.webSocketClose(ws);
  }
}