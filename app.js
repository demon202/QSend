/**
 * QSend — Secure Peer-to-Peer File Transfer
 * app.js — Complete application logic
 *
 * Security model:
 *  1. WebRTC DataChannel provides DTLS transport encryption
 *  2. On top: ECDH P-256 key exchange (keys never leave browser)
 *  3. AES-256-GCM encrypts every chunk independently
 *  4. SHA-256 verifies file integrity after reassembly
 *  5. Signaling server sees only SDP/ICE — no keys, no data
 *
 * KEY FIXES vs. previous version:
 *  FIX 1 — Offer is now sent from the 'peer-joined' handler, NOT from initSend().
 *           Previously the offer was sent before the receiver had joined, so the
 *           signaling server rejected it with "No receiver yet" and the offer was
 *           silently dropped — leaving both sides stuck forever.
 *
 *  FIX 2 — ICE candidates from pendingICE are now applied AFTER setRemoteDescription().
 *           Previously they were added before the remote description was set, which
 *           causes silent failures in every browser.
 */

'use strict';

// ══════════════════════════════════════════════════════════════
//  CONFIGURATION
// ══════════════════════════════════════════════════════════════

const CONFIG = Object.freeze({
  SIGNAL_URL: (() => {
    const local = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    return local ? 'ws://localhost:8080' : 'wss://qsend-signal.qsend-test.workers.dev';
  })(),

  CHUNK_SIZE:    256 * 1024,
  MAX_BUFFER:    4   * 1024 * 1024,
  RESUME_BUFFER: 512 * 1024,

  ICE_SERVERS: [
    { urls: 'stun:stun.l.google.com:19302' },
    {
      urls: [
        'turn:openrelay.metered.ca:80',
        'turn:openrelay.metered.ca:443',
        'turn:openrelay.metered.ca:443?transport=tcp',
      ],
      username:   'openrelayproject',
      credential: 'openrelayproject',
    },
    { urls: 'stun:global.stun.twilio.com:3478' },
  ],
});

// ══════════════════════════════════════════════════════════════
//  STREAMING SHA-256
// ══════════════════════════════════════════════════════════════

class StreamSHA256 {
  constructor() {
    this._K = new Uint32Array([
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]);
    this.reset();
  }

  reset() {
    this._h = new Uint32Array([
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ]);
    this._buf    = new Uint8Array(64);
    this._bufLen = 0;
    this._total  = 0;
    return this;
  }

  _rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  _compress(blk) {
    const W  = new Uint32Array(64);
    const dv = new DataView(blk.buffer, blk.byteOffset);
    for (let i = 0;  i < 16; i++) W[i] = dv.getUint32(i << 2);
    for (let i = 16; i < 64; i++) {
      const s0 = this._rotr(W[i-15],7) ^ this._rotr(W[i-15],18) ^ (W[i-15]>>>3);
      const s1 = this._rotr(W[i-2],17) ^ this._rotr(W[i-2],19)  ^ (W[i-2]>>>10);
      W[i] = (W[i-16]+s0+W[i-7]+s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = this._h;
    for (let i = 0; i < 64; i++) {
      const S1 = this._rotr(e,6) ^ this._rotr(e,11) ^ this._rotr(e,25);
      const ch = (e&f) ^ (~e&g);
      const t1 = (h+S1+ch+this._K[i]+W[i]) >>> 0;
      const S0 = this._rotr(a,2) ^ this._rotr(a,13) ^ this._rotr(a,22);
      const mj = (a&b) ^ (a&c) ^ (b&c);
      const t2 = (S0+mj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    this._h[0]=(this._h[0]+a)>>>0; this._h[1]=(this._h[1]+b)>>>0;
    this._h[2]=(this._h[2]+c)>>>0; this._h[3]=(this._h[3]+d)>>>0;
    this._h[4]=(this._h[4]+e)>>>0; this._h[5]=(this._h[5]+f)>>>0;
    this._h[6]=(this._h[6]+g)>>>0; this._h[7]=(this._h[7]+h)>>>0;
  }

  update(data) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    this._total += bytes.length;
    let off = 0;
    if (this._bufLen > 0 && this._bufLen + bytes.length >= 64) {
      const need = 64 - this._bufLen;
      this._buf.set(bytes.subarray(0, need), this._bufLen);
      this._compress(this._buf);
      this._bufLen = 0;
      off = need;
    }
    while (off + 64 <= bytes.length) {
      this._compress(bytes.subarray(off, off + 64));
      off += 64;
    }
    if (off < bytes.length) {
      this._buf.set(bytes.subarray(off), this._bufLen);
      this._bufLen += bytes.length - off;
    }
    return this;
  }

  digest() {
    const len = this._bufLen, total = this._total;
    const pad = len < 56 ? 64 : 128;
    const blk = new Uint8Array(pad);
    blk.set(this._buf.subarray(0, len));
    blk[len] = 0x80;
    const dv = new DataView(blk.buffer);
    const bits = total * 8;
    dv.setUint32(pad - 8, Math.floor(bits / 0x100000000) >>> 0);
    dv.setUint32(pad - 4, bits >>> 0);
    for (let i = 0; i < pad; i += 64) this._compress(blk.subarray(i, i + 64));
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i << 2, this._h[i]);
    return out;
  }

  hex() {
    return Array.from(this.digest()).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

// ══════════════════════════════════════════════════════════════
//  CRYPTO MODULE
// ══════════════════════════════════════════════════════════════

const Crypto = {
  async generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']
    );
  },

  async exportPublicKey(keyPair) {
    const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  },

  async importPublicKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
      'raw', raw.buffer, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
  },

  async deriveSharedKey(keyPair, peerPublicKey) {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      keyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encryptChunk(key, chunkIndex, plaintext) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const aad = new Uint8Array(4);
    new DataView(aad.buffer).setUint32(0, chunkIndex);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, key, plaintext
    );
    const result = new Uint8Array(4 + 12 + ciphertext.byteLength);
    result.set(aad, 0);
    result.set(iv,  4);
    result.set(new Uint8Array(ciphertext), 16);
    return result.buffer;
  },

  async decryptChunk(key, buffer) {
    const bytes = new Uint8Array(buffer);
    if (bytes.length < 17) throw new Error('Chunk too short');
    const aad        = bytes.subarray(0, 4);
    const iv         = bytes.subarray(4, 16);
    const ciphertext = bytes.subarray(16);
    const index      = new DataView(aad.buffer, aad.byteOffset, 4).getUint32(0);
    const plain      = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext
    );
    return { index, data: new Uint8Array(plain) };
  },
};

// ══════════════════════════════════════════════════════════════
//  APPLICATION STATE
// ══════════════════════════════════════════════════════════════

const state = {
  mode:        null,
  ws:          null,
  pc:          null,
  dc:          null,
  pendingICE:  [],   // ICE candidates buffered before remote desc is set

  keyPair:     null,
  sharedKey:   null,
  sessionCode: null,

  file:        null,
  fileHasher:  null,
  totalChunks: 0,
  sentChunks:  0,
  paused:      false,

  fileMeta:    null,
  chunks:      [],
  rcvdChunks:  0,

  startTime:      null,
  bytesDone:      0,
  lastSpeedTs:    null,
  lastSpeedBytes: 0,
  currentSpeed:   0,

  keyReady:  false,
  xferDone:  false,

  reset() {
    try { this.ws?.close(); } catch {}
    try { this.dc?.close(); } catch {}
    try { this.pc?.close(); } catch {}
    Object.assign(this, {
      mode: null, ws: null, pc: null, dc: null, pendingICE: [],
      keyPair: null, sharedKey: null, sessionCode: null,
      file: null, fileHasher: null, totalChunks: 0, sentChunks: 0, paused: false,
      fileMeta: null, chunks: [], rcvdChunks: 0,
      startTime: null, bytesDone: 0, lastSpeedTs: null, lastSpeedBytes: 0, currentSpeed: 0,
      keyReady: false, xferDone: false,
    });
  },
};

// ══════════════════════════════════════════════════════════════
//  UTILITIES
// ══════════════════════════════════════════════════════════════

const sleep = ms => new Promise(r => setTimeout(r, ms));

function fmt(bytes) {
  if (bytes < 1024)       return `${bytes} B`;
  if (bytes < 1024 ** 2)  return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3)  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function fmtSpeed(bps) { return `${fmt(bps)}/s`; }

function esc(str) {
  return String(str).replace(/[&<>"']/g, m =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])
  );
}

// ══════════════════════════════════════════════════════════════
//  WEBRTC PEER CONNECTION
// ══════════════════════════════════════════════════════════════

function createPeerConnection() {
  const pc = new RTCPeerConnection({
    iceServers:           CONFIG.ICE_SERVERS,
    iceCandidatePoolSize: 10,
  });

  pc.onicecandidate = ({ candidate }) => {
    if (candidate && state.ws?.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ type: 'ice', candidate }));
    }
  };

  pc.oniceconnectionstatechange = () => {
    const s = pc.iceConnectionState;
    UI.setConnDot(s);
    if (s === 'failed') {
      UI.status('ICE failed — could not establish connection.', 'error');
      UI.setConnType('Failed');
    }
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'connected') detectConnType(pc);
  };

  return pc;
}

async function detectConnType(pc) {
  try {
    const stats = await pc.getStats();
    for (const r of stats.values()) {
      if (r.type === 'candidate-pair' && r.state === 'succeeded') {
        const local   = stats.get(r.localCandidateId);
        const isRelay = local?.candidateType === 'relay';
        UI.setConnType(isRelay ? 'TURN Relay' : '⚡ P2P Direct');
        return;
      }
    }
  } catch {}
}

// ══════════════════════════════════════════════════════════════
//  DATA CHANNEL
// ══════════════════════════════════════════════════════════════

function setupDataChannel(dc) {
  dc.binaryType = 'arraybuffer';
  dc.bufferedAmountLowThreshold = CONFIG.RESUME_BUFFER;

  dc.onopen = async () => {
    UI.status('Channel open — performing key exchange…', 'info');
    UI.setEncStatus('Exchanging keys…');
    state.keyPair = await Crypto.generateKeyPair();
    const pub = await Crypto.exportPublicKey(state.keyPair);
    dc.send(JSON.stringify({ type: 'ecdh-key', pub, role: state.mode }));
  };

  dc.onclose = () => {
    if (!state.xferDone) UI.status('Channel closed.', 'info');
  };

  dc.onerror = (e) => {
    UI.status(`Channel error: ${e.message || 'unknown'}`, 'error');
  };

  dc.onmessage = async ({ data }) => {
    if (typeof data === 'string') {
      await onControlMsg(JSON.parse(data));
    } else {
      await onChunk(data);
    }
  };
}

// ══════════════════════════════════════════════════════════════
//  CONTROL MESSAGES (over DataChannel)
// ══════════════════════════════════════════════════════════════

async function onControlMsg(msg) {
  switch (msg.type) {

    case 'ecdh-key': {
      const peerPub   = await Crypto.importPublicKey(msg.pub);
      state.sharedKey = await Crypto.deriveSharedKey(state.keyPair, peerPub);
      state.keyReady  = true;
      UI.setLockState(true);
      UI.status('🔒 End-to-end encryption active.', 'success');
      if (state.mode === 'send' && state.file) await startTransfer();
      break;
    }

    case 'file-meta': {
      state.fileMeta    = msg;
      state.totalChunks = msg.totalChunks;
      state.chunks      = new Array(msg.totalChunks).fill(null);
      state.rcvdChunks  = 0;
      state.startTime   = Date.now();
      state.bytesDone   = 0;
      UI.showReceiveMeta(msg);
      UI.status(`Receiving: ${esc(msg.name)} (${fmt(msg.size)})`, 'info');
      break;
    }

    case 'transfer-complete':
      await finalizeReceive(msg.sha256);
      break;

    case 'verified': {
      state.xferDone = true;
      if (msg.ok) {
        UI.status('✓ Verified — transfer complete!', 'success');
        UI.showSendComplete();
      } else {
        UI.status('⚠ Remote integrity check failed!', 'error');
      }
      state.ws?.send(JSON.stringify({ type: 'done' }));
      break;
    }

    case 'pause':  state.paused = true;  UI.status('Transfer paused.',  'info'); break;
    case 'resume': state.paused = false; UI.status('Transfer resumed.', 'info'); break;
  }
}

// ══════════════════════════════════════════════════════════════
//  SEND — chunked streaming
// ══════════════════════════════════════════════════════════════

async function startTransfer() {
  if (!state.sharedKey || !state.file) return;

  const file        = state.file;
  const totalChunks = Math.ceil(file.size / CONFIG.CHUNK_SIZE);

  state.totalChunks = totalChunks;
  state.sentChunks  = 0;
  state.startTime   = Date.now();
  state.bytesDone   = 0;
  state.fileHasher  = new StreamSHA256();

  state.dc.send(JSON.stringify({
    type: 'file-meta', name: file.name, size: file.size,
    mimeType: file.type || 'application/octet-stream',
    totalChunks, lastModified: file.lastModified,
  }));

  UI.status(`Sending ${esc(file.name)}…`, 'info');
  UI.setSendProgressVisible(true);

  for (let i = 0; i < totalChunks; i++) {
    while (state.dc.bufferedAmount > CONFIG.MAX_BUFFER || state.paused) {
      await sleep(30);
      if (state.dc.readyState !== 'open') {
        UI.status('Transfer aborted: channel closed.', 'error');
        return;
      }
    }

    const start     = i * CONFIG.CHUNK_SIZE;
    const end       = Math.min(start + CONFIG.CHUNK_SIZE, file.size);
    const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());

    state.fileHasher.update(plaintext);

    const encrypted = await Crypto.encryptChunk(state.sharedKey, i, plaintext);
    state.dc.send(encrypted);

    state.sentChunks++;
    state.bytesDone += plaintext.length;
    updateSpeed(plaintext.length);
    UI.setSendProgress(state.sentChunks / totalChunks, state.currentSpeed);
  }

  while (state.dc.bufferedAmount > 0) await sleep(50);

  const sha256 = state.fileHasher.hex();
  state.dc.send(JSON.stringify({ type: 'transfer-complete', sha256 }));
  UI.status('All chunks sent — awaiting integrity verification…', 'info');
}

// ══════════════════════════════════════════════════════════════
//  RECEIVE — decrypt and reconstruct
// ══════════════════════════════════════════════════════════════

async function onChunk(buffer) {
  if (!state.sharedKey) return;
  let index, data;
  try {
    ({ index, data } = await Crypto.decryptChunk(state.sharedKey, buffer));
  } catch (e) {
    UI.status('⚠ Chunk decryption failed — possible tampering!', 'error');
    console.error('Decrypt error:', e);
    return;
  }
  state.chunks[index] = data;
  state.rcvdChunks++;
  state.bytesDone += data.length;
  updateSpeed(data.length);
  UI.setRecvProgress(state.rcvdChunks / state.totalChunks, state.currentSpeed);
}

async function finalizeReceive(expectedSHA256) {
  UI.status('Verifying integrity…', 'info');

  const missing = state.chunks.findIndex(c => c === null);
  if (missing !== -1) {
    state.dc.send(JSON.stringify({ type: 'verified', ok: false }));
    UI.status(`⚠ Missing chunk ${missing}!`, 'error');
    return;
  }

  const hasher = new StreamSHA256();
  for (const chunk of state.chunks) hasher.update(chunk);
  const actualSHA256 = hasher.hex();

  if (actualSHA256 !== expectedSHA256) {
    state.dc.send(JSON.stringify({ type: 'verified', ok: false }));
    UI.status('⚠ Integrity check FAILED!', 'error');
    return;
  }

  const blob = new Blob(state.chunks, { type: state.fileMeta.mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = state.fileMeta.name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 30_000);

  state.chunks   = [];
  state.xferDone = true;

  state.dc.send(JSON.stringify({ type: 'verified', ok: true }));
  UI.status('✓ File saved — SHA-256 verified.', 'success');
  UI.showReceiveComplete(actualSHA256);
}

// ══════════════════════════════════════════════════════════════
//  SIGNALING
// ══════════════════════════════════════════════════════════════

function connectSignaling(code) {
  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new WebSocket(CONFIG.SIGNAL_URL);
    } catch (e) {
      reject(new Error(`Cannot connect to signaling server: ${e.message}`));
      return;
    }

    state.ws = ws;
    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error('Signaling server connection timed out'));
    }, 10_000);

    ws.onopen = () => {
      clearTimeout(timeout);
      if (state.mode === 'send') {
        ws.send(JSON.stringify({ type: 'create' }));
      } else {
        ws.send(JSON.stringify({ type: 'join', code }));
      }
    };

    ws.onmessage = async ({ data }) => {
      let msg;
      try { msg = JSON.parse(data); } catch { return; }

      switch (msg.type) {

        case 'created':
          state.sessionCode = msg.code;
          UI.showCode(msg.code);
          UI.status('Waiting for receiver — share the code or QR…', 'info');
          resolve();
          break;

        case 'joined':
          UI.status('Joined session — waiting for sender…', 'info');
          resolve();
          break;

        // ── FIX 1: Offer created here, after receiver has joined.
        //    Previously sent in initSend() before receiver existed —
        //    server returned "No receiver yet" and dropped the offer. ──
        case 'peer-joined':
          UI.status('Peer connected — negotiating connection…', 'info');
          await createAndSendOffer();
          break;

        // ── Receiver handles offer ──────────────────────────────
        case 'offer': {
          state.pc = createPeerConnection();
          state.pc.ondatachannel = ({ channel }) => {
            state.dc = channel;
            setupDataChannel(channel);
          };

          // Set remote description first …
          await state.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));

          // FIX 2: … THEN drain the ICE buffer.
          // Candidates added before setRemoteDescription() fail silently.
          for (const cand of state.pendingICE) {
            try { await state.pc.addIceCandidate(new RTCIceCandidate(cand)); } catch {}
          }
          state.pendingICE = [];

          const answer = await state.pc.createAnswer();
          await state.pc.setLocalDescription(answer);
          state.ws.send(JSON.stringify({ type: 'answer', sdp: state.pc.localDescription }));
          break;
        }

        // ── Sender handles answer ───────────────────────────────
        case 'answer':
          await state.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
          // Drain any candidates buffered before answer arrived
          for (const cand of state.pendingICE) {
            try { await state.pc.addIceCandidate(new RTCIceCandidate(cand)); } catch {}
          }
          state.pendingICE = [];
          break;

        // ── ICE candidates — buffer if remote desc not set yet ──
        case 'ice':
          if (msg.candidate) {
            if (state.pc && state.pc.remoteDescription) {
              try { await state.pc.addIceCandidate(new RTCIceCandidate(msg.candidate)); } catch {}
            } else {
              state.pendingICE.push(msg.candidate);
            }
          }
          break;

        case 'error':
          UI.status(`Signaling error: ${msg.message}`, 'error');
          reject(new Error(msg.message));
          break;

        case 'session-expired':
          UI.status('Session expired.', 'error');
          break;

        case 'peer-disconnected':
          if (!state.xferDone) UI.status('Peer disconnected.', 'error');
          break;
      }
    };

    ws.onerror = () => { clearTimeout(timeout); reject(new Error('WebSocket connection failed')); };
    ws.onclose = () => {};
  });
}

// ══════════════════════════════════════════════════════════════
//  CREATE AND SEND OFFER  (sender, triggered by peer-joined)
// ══════════════════════════════════════════════════════════════

async function createAndSendOffer() {
  try {
    const offer = await state.pc.createOffer();
    await state.pc.setLocalDescription(offer);
    state.ws.send(JSON.stringify({ type: 'offer', sdp: state.pc.localDescription }));
  } catch (e) {
    UI.status(`Failed to create offer: ${e.message}`, 'error');
  }
}

// ══════════════════════════════════════════════════════════════
//  SPEED TRACKING
// ══════════════════════════════════════════════════════════════

function updateSpeed(bytes) {
  const now = Date.now();
  if (!state.lastSpeedTs) { state.lastSpeedTs = now; state.lastSpeedBytes = 0; }
  state.lastSpeedBytes += bytes;
  const dt = now - state.lastSpeedTs;
  if (dt >= 500) {
    state.currentSpeed   = (state.lastSpeedBytes / dt) * 1000;
    state.lastSpeedTs    = now;
    state.lastSpeedBytes = 0;
  }
}

// ══════════════════════════════════════════════════════════════
//  UI MODULE
// ══════════════════════════════════════════════════════════════

const UI = {
  status(msg, type = 'info') {
    const el = document.getElementById('status-message');
    if (!el) return;
    el.innerHTML  = esc(msg);
    el.className  = `status-msg status-${type}`;
    el.style.display = 'block';
  },

  setEncStatus(text) {
    const el = document.getElementById('enc-status');
    if (el) { el.textContent = text; el.classList.toggle('active', !!text); }
  },

  setConnType(text) {
    const el = document.getElementById('conn-type');
    if (el) el.textContent = text;
  },

  setConnDot(iceState) {
    const dot = document.getElementById('conn-dot');
    if (!dot) return;
    dot.className = 'conn-dot ' + (
      iceState === 'connected' || iceState === 'completed' ? 'green'  :
      iceState === 'checking'  || iceState === 'new'       ? 'yellow' : 'red'
    );
  },

  setLockState(locked) {
    document.getElementById('lock-icon')?.classList.toggle('locked', locked);
    this.setEncStatus(locked ? 'AES-256-GCM ✓' : 'Not encrypted');
  },

  showCode(code) {
    const wrap = document.getElementById('code-display');
    const el   = document.getElementById('session-code');
    if (!wrap || !el) return;
    el.textContent = code.slice(0, 3) + ' ' + code.slice(3);
    wrap.classList.remove('hidden');
    const url = `${location.origin}${location.pathname}?receive=${code}`;
    renderQR(url);
  },

  setSendProgressVisible(v) {
    document.getElementById('send-progress-wrap')?.classList.toggle('hidden', !v);
  },

  setSendProgress(pct, speed) {
    const p   = Math.round(pct * 100);
    const bar = document.getElementById('send-bar');
    const lbl = document.getElementById('send-pct');
    const spd = document.getElementById('send-speed');
    if (bar) { bar.style.width = p + '%'; bar.setAttribute('aria-valuenow', p); }
    if (lbl) lbl.textContent = p + '%';
    if (spd && speed) spd.textContent = fmtSpeed(speed);
  },

  showSendComplete() {
    document.getElementById('send-complete')?.classList.remove('hidden');
  },

  showReceiveMeta(meta) {
    const el = document.getElementById('recv-meta');
    if (!el) return;
    el.innerHTML = `<span class="meta-name">${esc(meta.name)}</span><span class="meta-size">${fmt(meta.size)}</span>`;
    el.classList.remove('hidden');
    document.getElementById('recv-progress-wrap')?.classList.remove('hidden');
  },

  setRecvProgress(pct, speed) {
    const p   = Math.round(pct * 100);
    const bar = document.getElementById('recv-bar');
    const lbl = document.getElementById('recv-pct');
    const spd = document.getElementById('recv-speed');
    if (bar) { bar.style.width = p + '%'; bar.setAttribute('aria-valuenow', p); }
    if (lbl) lbl.textContent = p + '%';
    if (spd && speed) spd.textContent = fmtSpeed(speed);
  },

  showReceiveComplete(hash) {
    const el = document.getElementById('recv-complete');
    if (!el) return;
    el.innerHTML = `<div class="hash-label">SHA-256</div><div class="hash-value">${hash}</div>`;
    el.classList.remove('hidden');
    document.getElementById('recv-progress-wrap')?.classList.add('complete');
  },
};

// ══════════════════════════════════════════════════════════════
//  QR CODE
// ══════════════════════════════════════════════════════════════

function renderQR(text) {
  const container = document.getElementById('qr-container');
  if (!container) return;
  container.innerHTML = '';
  container.classList.remove('hidden');
  if (typeof QRCode !== 'undefined') {
    new QRCode(container, {
      text, width: 152, height: 152,
      colorDark: '#00e5ff', colorLight: '#0a0f1a',
      correctLevel: QRCode.CorrectLevel.M,
    });
  } else {
    container.textContent = text;
  }
}

// ══════════════════════════════════════════════════════════════
//  INIT FUNCTIONS
// ══════════════════════════════════════════════════════════════

async function initSend() {
  state.mode = 'send';
  await connectSignaling();         // resolves on 'created'

  // Create PC and DataChannel now so ICE gathering begins immediately.
  // The offer is NOT sent here — it is sent from createAndSendOffer()
  // which is triggered by the 'peer-joined' event. This guarantees the
  // receiver already exists in the session when the offer hits the server.
  state.pc = createPeerConnection();
  state.dc = state.pc.createDataChannel('qsend', { ordered: true });
  setupDataChannel(state.dc);
}

async function initReceive(code) {
  state.mode = 'receive';
  await connectSignaling(code);     // resolves on 'joined'
}

// ══════════════════════════════════════════════════════════════
//  MULTI-FILE QUEUE
// ══════════════════════════════════════════════════════════════

const fileQueue   = [];
let   queueActive = false;

async function enqueueFile(file) {
  fileQueue.push(file);
  if (!queueActive) processQueue();
}

async function processQueue() {
  queueActive = true;
  while (fileQueue.length > 0) {
    state.file = fileQueue.shift();
    showFileSelected(state.file);
    if (state.keyReady) await startTransfer();
  }
  queueActive = false;
}

// ══════════════════════════════════════════════════════════════
//  DOM / EVENT HANDLERS
// ══════════════════════════════════════════════════════════════

function showFileSelected(file) {
  const el = document.getElementById('file-info');
  if (!el) return;
  el.innerHTML = `
    <div class="file-icon">${getFileIcon(file.name)}</div>
    <div class="file-details">
      <div class="fn">${esc(file.name)}</div>
      <div class="fs">${fmt(file.size)} · ${file.type || 'unknown type'}</div>
    </div>`;
  el.classList.remove('hidden');
  document.getElementById('send-btn').disabled = false;
}

UI.showFileSelected = showFileSelected;

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = {
    pdf: '📄', zip: '🗜', rar: '🗜', gz: '🗜', tar: '🗜',
    mp4: '🎬', mov: '🎬', mkv: '🎬', avi: '🎬',
    mp3: '🎵', wav: '🎵', flac: '🎵', ogg: '🎵',
    jpg: '🖼', jpeg: '🖼', png: '🖼', gif: '🖼', webp: '🖼', svg: '🖼',
    doc: '📝', docx: '📝', txt: '📝', md: '📝',
    xls: '📊', xlsx: '📊', csv: '📊',
    exe: '⚙️', dmg: '⚙️', deb: '⚙️', apk: '⚙️',
  };
  return map[ext] || '📁';
}

function initDrop() {
  const zone = document.getElementById('drop-zone');
  if (!zone) return;
  ['dragenter', 'dragover'].forEach(ev => {
    zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.add('drag-over'); });
  });
  ['dragleave', 'drop'].forEach(ev => {
    zone.addEventListener(ev, e => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      if (ev === 'drop' && e.dataTransfer.files.length > 0) {
        Array.from(e.dataTransfer.files).forEach(enqueueFile);
        showFileSelected(e.dataTransfer.files[0]);
      }
    });
  });
  zone.addEventListener('click', () => document.getElementById('file-input')?.click());
  document.addEventListener('dragover', e => e.preventDefault());
  document.addEventListener('drop', e => {
    e.preventDefault();
    if (e.dataTransfer.files.length > 0 && state.mode !== 'receive') {
      Array.from(e.dataTransfer.files).forEach(enqueueFile);
      showFileSelected(e.dataTransfer.files[0]);
    }
  });
}

function initCodeInput() {
  const input = document.getElementById('receive-code-input');
  if (!input) return;
  input.addEventListener('input', () => {
    input.value = input.value.replace(/\D/g, '').slice(0, 6);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('receive-btn')?.click();
  });
  const urlCode = new URLSearchParams(location.search).get('receive');
  if (urlCode && /^\d{6}$/.test(urlCode)) {
    input.value = urlCode;
    UI.status('Code pre-filled from link. Click Connect when ready.', 'info');
    document.getElementById('receive-panel')?.scrollIntoView({ behavior: 'smooth' });
  }
}

function togglePause() {
  if (!state.dc || state.dc.readyState !== 'open') return;
  state.paused = !state.paused;
  state.dc.send(JSON.stringify({ type: state.paused ? 'pause' : 'resume' }));
  const btn = document.getElementById('pause-btn');
  if (btn) btn.textContent = state.paused ? '▶ Resume' : '⏸ Pause';
}

async function init() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }

  initDrop();
  initCodeInput();

  document.getElementById('file-input')?.addEventListener('change', (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length) { files.forEach(enqueueFile); showFileSelected(files[0]); }
    e.target.value = '';
  });

  document.getElementById('send-btn')?.addEventListener('click', async () => {
    if (!state.file && fileQueue.length === 0) {
      UI.status('Select a file first.', 'error'); return;
    }
    const btn = document.getElementById('send-btn');
    btn.disabled    = true;
    btn.textContent = 'Connecting…';
    try {
      await initSend();
    } catch (e) {
      UI.status(`Connection failed: ${e.message}`, 'error');
      btn.disabled    = false;
      btn.textContent = 'Send File';
    }
  });

  document.getElementById('receive-btn')?.addEventListener('click', async () => {
    const input = document.getElementById('receive-code-input');
    const code  = (input?.value || '').replace(/\D/g, '');
    if (!/^\d{6}$/.test(code)) {
      UI.status('Enter a valid 6-digit code.', 'error'); input?.focus(); return;
    }
    const btn = document.getElementById('receive-btn');
    btn.disabled    = true;
    btn.textContent = 'Connecting…';
    try {
      await initReceive(code);
    } catch (e) {
      UI.status(`Connection failed: ${e.message}`, 'error');
      btn.disabled    = false;
      btn.textContent = 'Connect';
    }
  });

  document.getElementById('copy-code-btn')?.addEventListener('click', async () => {
    if (!state.sessionCode) return;
    try {
      await navigator.clipboard.writeText(state.sessionCode);
      const btn = document.getElementById('copy-code-btn');
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    } catch { UI.status('Copy failed — please copy manually.', 'error'); }
  });

  document.getElementById('copy-link-btn')?.addEventListener('click', async () => {
    if (!state.sessionCode) return;
    const url = `${location.origin}${location.pathname}?receive=${state.sessionCode}`;
    try {
      await navigator.clipboard.writeText(url);
      const btn = document.getElementById('copy-link-btn');
      btn.textContent = 'Link Copied!';
      setTimeout(() => { btn.textContent = 'Copy Link'; }, 1500);
    } catch { UI.status('Could not copy link.', 'error'); }
  });

  document.getElementById('pause-btn')?.addEventListener('click', togglePause);

  document.getElementById('reset-btn')?.addEventListener('click', () => {
    state.reset();
    location.href = location.pathname;
  });

  if (location.search.includes('share-target')) {
    const params = new URLSearchParams(location.search);
    const title  = params.get('title') || '';
    UI.status(`Received share: "${esc(title)}" — select the file to send.`, 'info');
  }
}

document.addEventListener('DOMContentLoaded', init);