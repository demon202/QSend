/**
 * QSend Signaling Server
 * Minimal stateless WebSocket relay for WebRTC negotiation.
 *
 * Security guarantees:
 *  - No file data ever touches this server
 *  - No encryption keys ever visible here
 *  - No database, no logging, no storage
 *  - Sessions auto-expire after SESSION_TTL ms
 *  - Each session destroyed after transfer completes
 */

'use strict';

const WebSocket = require('ws');
const https = require('https');
const http = require('http');
const fs = require('fs');

const PORT = parseInt(process.env.PORT || '8080', 10);
const SESSION_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_SESSIONS = 10000;
const HEARTBEAT_INTERVAL = 30000;

// ── Session store (in-memory only, never persisted) ──────────────
// Map<code: string, Session>
const sessions = new Map();

/**
 * @typedef {Object} Session
 * @property {WebSocket|null} sender
 * @property {WebSocket|null} receiver
 * @property {NodeJS.Timeout} expireTimer
 * @property {number} createdAt
 */

// ── Server setup ─────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  // Health check endpoint
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, sessions: sessions.size }));
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocket.Server({
  server,
  // Security: limit message size to prevent abuse
  maxPayload: 64 * 1024, // 64 KB max message (SDP is typically < 2KB)
  verifyClient: ({ req }) => {
    // Allow all origins (clients configure their own CORS via CSP)
    // In production, restrict to your frontend domain:
    // const origin = req.headers.origin;
    // return origin === 'https://your-github-pages.github.io';
    return true;
  },
});

// ── Connection handler ────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.sessionCode = null;
  ws.role = null; // 'sender' | 'receiver'

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString('utf8'));
    } catch {
      safeSend(ws, { type: 'error', message: 'Invalid JSON' });
      return;
    }
    handleMessage(ws, msg);
  });

  ws.on('close', () => onClose(ws));
  ws.on('error', (err) => {
    // Suppress ECONNRESET etc — just close
    ws.terminate();
  });
});

// ── Message dispatcher ───────────────────────────────────────────
function handleMessage(ws, msg) {
  if (typeof msg.type !== 'string') {
    safeSend(ws, { type: 'error', message: 'Missing type' });
    return;
  }

  switch (msg.type) {

    // ── Sender creates a new session ────────────────────────────
    case 'create': {
      if (ws.sessionCode) {
        safeSend(ws, { type: 'error', message: 'Already in session' });
        return;
      }
      if (sessions.size >= MAX_SESSIONS) {
        safeSend(ws, { type: 'error', message: 'Server at capacity' });
        return;
      }

      const code = generateUniqueCode();
      const expireTimer = setTimeout(() => expireSession(code), SESSION_TTL);

      sessions.set(code, {
        sender: ws,
        receiver: null,
        expireTimer,
        createdAt: Date.now(),
      });

      ws.sessionCode = code;
      ws.role = 'sender';
      safeSend(ws, { type: 'created', code });
      break;
    }

    // ── Receiver joins an existing session ──────────────────────
    case 'join': {
      const code = String(msg.code || '').trim();
      if (!/^\d{6}$/.test(code)) {
        safeSend(ws, { type: 'error', message: 'Invalid code format' });
        return;
      }
      if (ws.sessionCode) {
        safeSend(ws, { type: 'error', message: 'Already in session' });
        return;
      }

      const session = sessions.get(code);
      if (!session) {
        safeSend(ws, { type: 'error', message: 'Session not found or expired' });
        return;
      }
      if (session.receiver !== null) {
        safeSend(ws, { type: 'error', message: 'Session already has a receiver' });
        return;
      }

      session.receiver = ws;
      ws.sessionCode = code;
      ws.role = 'receiver';

      // Notify both parties
      safeSend(ws, { type: 'joined' });
      safeSend(session.sender, { type: 'peer-joined' });
      break;
    }

    // ── WebRTC relay — bidirectional, no role restriction ───────
    // 'description' = unified offer+answer (perfect negotiation pattern)
    // 'offer'/'answer'/'ice' kept as aliases for compatibility
    case 'description':
    case 'offer':
    case 'answer':
    case 'ice': {
      if (!validateInSession(ws)) return;
      const session = sessions.get(ws.sessionCode);
      const peer = ws.role === 'sender' ? session?.receiver : session?.sender;
      relay(peer, msg);   // relay the full message object verbatim
      break;
    }

    // ── Explicit session teardown ────────────────────────────────
    case 'done': {
      if (ws.sessionCode) expireSession(ws.sessionCode);
      break;
    }

    default:
      safeSend(ws, { type: 'error', message: 'Unknown message type' });
  }
}

// ── Connection close cleanup ─────────────────────────────────────
function onClose(ws) {
  if (!ws.sessionCode) return;
  const session = sessions.get(ws.sessionCode);
  if (!session) return;

  // Notify surviving peer
  const peer = ws.role === 'sender' ? session.receiver : session.sender;
  relay(peer, { type: 'peer-disconnected' });

  // Destroy session
  expireSession(ws.sessionCode);
}

// ── Session expiry ───────────────────────────────────────────────
function expireSession(code) {
  const session = sessions.get(code);
  if (!session) return;

  clearTimeout(session.expireTimer);

  const msg = { type: 'session-expired' };
  relay(session.sender, msg);
  relay(session.receiver, msg);

  sessions.delete(code);
}

// ── Helpers ──────────────────────────────────────────────────────
function safeSend(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(obj)); } catch {}
  }
}

function relay(ws, obj) {
  safeSend(ws, obj);
}

function validateInSession(ws) {
  if (!ws.sessionCode || !sessions.has(ws.sessionCode)) {
    safeSend(ws, { type: 'error', message: 'Not in a session' });
    return false;
  }
  return true;
}

function generateUniqueCode() {
  let code;
  do {
    // Cryptographically random 6-digit code
    const arr = new Uint32Array(1);
    // Use crypto module for server-side randomness
    const { randomInt } = require('crypto');
    code = randomInt(100000, 1000000).toString();
  } while (sessions.has(code));
  return code;
}

// ── Heartbeat: detect dead connections ───────────────────────────
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);

wss.on('close', () => {
  clearInterval(heartbeat);
  sessions.clear();
});

// ── Start server ─────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`QSend signaling server running on port ${PORT}`);
  console.log(`Sessions expire after ${SESSION_TTL / 1000}s`);
  console.log(`Max sessions: ${MAX_SESSIONS}`);
});

// ── Graceful shutdown ────────────────────────────────────────────
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  sessions.forEach((_, code) => expireSession(code));
  wss.close(() => server.close(() => process.exit(0)));
});

process.on('SIGINT', () => {
  process.emit('SIGTERM');
});