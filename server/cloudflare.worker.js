/**
 * QSend Signaling Server — Cloudflare Workers + Durable Objects
 *
 * KEY FIX: iOS Safari kills WebSocket connections when the app goes to background.
 * This happens routinely when the sender is showing the code and the user
 * switches away to type it on another device (screen dims, switches app, etc.)
 *
 * Previous behaviour: webSocketClose → _expireSession immediately.
 * Result: session deleted, receiver gets "Session not found or expired",
 *         or receiver joins but peer-joined is sent to a dead socket tag.
 *
 * New behaviour:
 *   - When the SENDER disconnects and no receiver has joined yet:
 *     keep the session alive (TTL still applies), null out senderTag.
 *   - When the SENDER disconnects after receiver has joined:
 *     notify receiver and expire normally.
 *   - New message type 'reclaim': sender reconnects and reclaims their session
 *     by supplying their old code. If the receiver already joined while sender
 *     was offline, we immediately send peer-joined to the new sender socket.
 *
 * All session data lives in this.state.storage (persistent KV) so it
 * survives Durable Object hibernation between messages.
 *
 * Storage keys:
 *   session:{code}  → { senderTag, receiverTag|null, expiresAt, senderGone? }
 *   meta:{tag}      → { code, role: 'sender'|'receiver' }
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
    // NO in-memory state — everything in this.state.storage (survives hibernation)
  }

  async fetch(request) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const tag = `ws-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    this.state.acceptWebSocket(server, [tag]);
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── Storage helpers ───────────────────────────────────────────────

  _tag(ws) { return this.state.getTags(ws)?.[0] ?? null; }

  async _send(tag, obj) {
    if (!tag) return;
    for (const ws of this.state.getWebSockets(tag)) {
      try { ws.send(JSON.stringify(obj)); } catch {}
    }
  }

  async _getSession(code)      { return (await this.state.storage.get(`session:${code}`)) ?? null; }
  async _setSession(code, val) { await this.state.storage.put(`session:${code}`, val); }
  async _delSession(code)      { await this.state.storage.delete(`session:${code}`); }
  async _getMeta(tag)          { return (await this.state.storage.get(`meta:${tag}`)) ?? null; }
  async _setMeta(tag, val)     { await this.state.storage.put(`meta:${tag}`, val); }
  async _delMeta(tag)          { await this.state.storage.delete(`meta:${tag}`); }

  async _expireSession(code) {
    const session = await this._getSession(code);
    if (!session) return;
    // Notify both sides if still connected
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

      // ── Sender: create a new session ─────────────────────────────
      case 'create': {
        if (await this._getMeta(tag)) {
          await this._send(tag, { type: 'error', message: 'Already in session' });
          return;
        }
        let code, attempts = 0;
        do {
          code = String(Math.floor(100000 + Math.random() * 900000));
          attempts++;
        } while ((await this._getSession(code)) && attempts < 20);

        await this._setSession(code, {
          senderTag:   tag,
          receiverTag: null,
          expiresAt:   Date.now() + SESSION_TTL_MS,
          senderGone:  false,
        });
        await this._setMeta(tag, { code, role: 'sender' });
        await this._send(tag, { type: 'created', code });
        break;
      }

      // ── Sender: reclaim a session after reconnecting ──────────────
      // Called when iOS kills the WS and the sender reconnects.
      // The sender supplies their old code from sessionStorage.
      case 'reclaim': {
        const code = String(msg.code || '').trim();
        if (!/^\d{6}$/.test(code)) {
          // Invalid code — fall back to creating a new session
          await this._send(tag, { type: 'reclaim-failed' });
          return;
        }
        const session = await this._getSession(code);
        if (!session || !session.senderGone || Date.now() > session.expiresAt) {
          // Session gone or expired — tell client to create fresh
          await this._send(tag, { type: 'reclaim-failed' });
          return;
        }

        // Re-link this new socket tag to the session
        session.senderTag  = tag;
        session.senderGone = false;
        await this._setSession(code, session);
        await this._setMeta(tag, { code, role: 'sender' });

        // Tell the sender they're back, and whether receiver has already joined
        await this._send(tag, {
          type:      'reclaimed',
          code,
          peerReady: session.receiverTag !== null,
        });
        break;
      }

      // ── Receiver: join an existing session ────────────────────────
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

        // Notify receiver they joined
        await this._send(tag, { type: 'joined' });

        // Notify sender — only if sender is currently connected.
        // If sender is gone (iOS backgrounded), the peer-joined will be
        // delivered when the sender reclaims via 'reclaim' message.
        if (!session.senderGone && session.senderTag) {
          await this._send(session.senderTag, { type: 'peer-joined' });
        }
        // If senderGone: sender will get peer-joined via 'reclaimed' response
        break;
      }

      // ── WebRTC relay — perfect negotiation uses 'description' for
      //    both offer and answer; 'ice' for candidates.
      //    Keep 'offer'/'answer' as aliases for backwards compatibility.
      case 'description':
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

      // ── Explicit teardown ─────────────────────────────────────────
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
      if (meta.role === 'sender') {
        if (session.receiverTag === null) {
          // ── Receiver hasn't joined yet ────────────────────────────
          // iOS Safari killed the WS while sender was waiting.
          // Keep the session alive — mark sender as gone.
          // Sender can reclaim via 'reclaim' message on reconnect.
          session.senderTag  = null;
          session.senderGone = true;
          await this._setSession(meta.code, session);
          // Don't expire, don't notify anyone
        } else {
          // ── Receiver IS connected — normal disconnect ─────────────
          await this._send(session.receiverTag, { type: 'peer-disconnected' });
          await this._expireSession(meta.code);
        }
      } else {
        // ── Receiver disconnected ─────────────────────────────────
        if (session.senderTag) {
          await this._send(session.senderTag, { type: 'peer-disconnected' });
        }
        await this._expireSession(meta.code);
      }
    }
    await this._delMeta(tag);
  }

  async webSocketError(ws) {
    await this.webSocketClose(ws);
  }
}