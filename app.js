/**
 * QSend — Secure Peer-to-Peer File Transfer  app.js
 *
 * Cumulative fixes applied in this version:
 *  1.  CHUNK_SIZE = 16 KB  (256 KB + GCM overhead exceeds Chrome's 262,144-byte DC limit)
 *  2.  TURN servers added  (STUN alone can't traverse symmetric NAT on mobile carriers)
 *  3.  Null ICE filter     (candidate.candidate === "" sentinel was being relayed)
 *  4.  ECDH race condition fixed  (peer key buffered if it arrives before our keypair ready)
 *  5.  try/catch in ecdh-key handler  (silent failures now shown as errors)
 *  6.  File read upfront as single ArrayBuffer  (Safari iOS File.slice() detaches in loops)
 *  7.  dc.send(new Uint8Array())  (Safari/Edge silently drop raw ArrayBuffer sends)
 *  8.  xferDone set before a.click()  (session-expired can't overwrite success status)
 *  9.  session-expired guarded by xferDone  (no more "expired" message after success)
 *
 * ARCHITECTURE REWRITE — Perfect Negotiation + Out-of-Band DataChannel
 * ─────────────────────────────────────────────────────────────────────
 * ROOT CAUSE of "mobile can't send" bug:
 *   The old code used fixed offerer/answerer roles (whoever got 'peer-joined'
 *   was always the offerer). On WebKit/iOS, calling createDataChannel() then
 *   createOffer() in the same tick causes WebKit to fire onnegotiationneeded
 *   a second time WHILE the first offer is already in flight. This creates two
 *   simultaneous negotiation cycles that deadlock the connection, leaving both
 *   sides stuck forever.
 *
 * THE FIX — two changes working together:
 *
 *   A) Out-of-band DataChannel { negotiated: true, id: 0 }
 *      Both peers create the DC with the same id. No SDP renegotiation is
 *      needed for the DC — it just opens once ICE connects. This eliminates
 *      the onnegotiationneeded double-fire entirely.
 *
 *   B) Perfect Negotiation (MDN / W3C recommended pattern)
 *      Both peers get a PC immediately on connect. The 'sender' (whoever
 *      gets 'peer-joined') triggers negotiation via onnegotiationneeded.
 *      Polite/impolite roles handle any offer collision race-free.
 *      The code is symmetric — identical on both ends.
 *
 * This is the pattern used by FilePizza, ShareDrop, and every production
 * WebRTC app that works reliably across iOS/Android/desktop.
 */

'use strict';

// ─── CONFIG ───────────────────────────────────────────────────────

const CONFIG = Object.freeze({
  // ← REPLACE THIS with your Railway/Render URL after deploying server/index.js
  // e.g. 'wss://qsend-signal-production.up.railway.app'
  // For local testing: set to 'ws://localhost:8080'
  SIGNAL_URL: (() => {
    const local = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    return local ? 'ws://localhost:8080' : 'wss://YOUR-RAILWAY-APP.up.railway.app';
  })(),

  CHUNK_SIZE:    16 * 1024,
  MAX_BUFFER:    1  * 1024 * 1024,
  RESUME_BUFFER: 128 * 1024,

  // TURN required for ~20% of real-world connections (symmetric NAT on mobile carriers).
  // Replace openrelay with your own Metered/Twilio/Xirsys credentials for production.
  ICE_SERVERS: [
    { urls: 'stun:stun.l.google.com:19302' },
    {
      urls:       'turn:openrelay.metered.ca:80',
      username:   'openrelayproject',
      credential: 'openrelayproject',
    },
    {
      urls:       'turn:openrelay.metered.ca:443',
      username:   'openrelayproject',
      credential: 'openrelayproject',
    },
  ],
});

// ─── STREAMING SHA-256 ────────────────────────────────────────────

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
    this._h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    this._buf = new Uint8Array(64); this._bufLen = 0; this._total = 0;
    return this;
  }
  _rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
  _compress(blk) {
    const W=new Uint32Array(64),dv=new DataView(blk.buffer,blk.byteOffset);
    for(let i=0;i<16;i++) W[i]=dv.getUint32(i<<2);
    for(let i=16;i<64;i++){
      const s0=this._rotr(W[i-15],7)^this._rotr(W[i-15],18)^(W[i-15]>>>3);
      const s1=this._rotr(W[i-2],17)^this._rotr(W[i-2],19)^(W[i-2]>>>10);
      W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;
    }
    let [a,b,c,d,e,f,g,h]=this._h;
    for(let i=0;i<64;i++){
      const S1=this._rotr(e,6)^this._rotr(e,11)^this._rotr(e,25),ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+this._K[i]+W[i])>>>0;
      const S0=this._rotr(a,2)^this._rotr(a,13)^this._rotr(a,22),mj=(a&b)^(a&c)^(b&c);
      const t2=(S0+mj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    for(let i=0;i<8;i++) this._h[i]=(this._h[i]+[a,b,c,d,e,f,g,h][i])>>>0;
  }
  update(data) {
    const bytes=data instanceof Uint8Array?data:new Uint8Array(data);
    this._total+=bytes.length; let off=0;
    if(this._bufLen>0&&this._bufLen+bytes.length>=64){
      const need=64-this._bufLen;
      this._buf.set(bytes.subarray(0,need),this._bufLen);
      this._compress(this._buf); this._bufLen=0; off=need;
    }
    while(off+64<=bytes.length){ this._compress(bytes.subarray(off,off+64)); off+=64; }
    if(off<bytes.length){ this._buf.set(bytes.subarray(off),this._bufLen); this._bufLen+=bytes.length-off; }
    return this;
  }
  digest() {
    const len=this._bufLen,total=this._total,pad=len<56?64:128;
    const blk=new Uint8Array(pad); blk.set(this._buf.subarray(0,len)); blk[len]=0x80;
    const dv=new DataView(blk.buffer),bits=total*8;
    dv.setUint32(pad-8,Math.floor(bits/0x100000000)>>>0); dv.setUint32(pad-4,bits>>>0);
    for(let i=0;i<pad;i+=64) this._compress(blk.subarray(i,i+64));
    const out=new Uint8Array(32),odv=new DataView(out.buffer);
    for(let i=0;i<8;i++) odv.setUint32(i<<2,this._h[i]);
    return out;
  }
  hex(){ return Array.from(this.digest()).map(b=>b.toString(16).padStart(2,'0')).join(''); }
}

// ─── CRYPTO ───────────────────────────────────────────────────────

const Crypto = {
  async generateKeyPair() {
    return crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, false, ['deriveKey']);
  },
  async exportPublicKey(kp) {
    const raw = await crypto.subtle.exportKey('raw', kp.publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  },
  async importPublicKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('raw', raw.buffer, { name:'ECDH', namedCurve:'P-256' }, false, []);
  },
  async deriveSharedKey(kp, peerPub) {
    return crypto.subtle.deriveKey(
      { name:'ECDH', public:peerPub }, kp.privateKey,
      { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
    );
  },
  async encryptChunk(key, idx, plain) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const aad = new Uint8Array(4);
    new DataView(aad.buffer).setUint32(0, idx);
    const ct  = await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData:aad }, key, plain);
    const out = new Uint8Array(4 + 12 + ct.byteLength);
    out.set(aad,0); out.set(iv,4); out.set(new Uint8Array(ct),16);
    return out.buffer;
  },
  async decryptChunk(key, buf) {
    const b = new Uint8Array(buf);
    if (b.length < 17) throw new Error('Chunk too short');
    const aad=b.subarray(0,4), iv=b.subarray(4,16), ct=b.subarray(16);
    const idx = new DataView(aad.buffer, aad.byteOffset, 4).getUint32(0);
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv, additionalData:aad }, key, ct);
    return { index:idx, data:new Uint8Array(plain) };
  },
};

// ─── STATE ────────────────────────────────────────────────────────

const state = {
  mode:null, ws:null, pc:null, dc:null,
  polite:false,               // perfect negotiation role (true = yield on collision)
  makingOffer:false,          // perfect negotiation guard
  ignoreOffer:false,          // perfect negotiation guard
  keyPair:null,
  pendingPeerKey:null,        // peer ecdh-key that arrived before our keypair was ready
  sharedKey:null, sessionCode:null,
  file:null, fileHasher:null, totalChunks:0, sentChunks:0, paused:false,
  fileMeta:null, chunks:[], rcvdChunks:0,
  startTime:null, bytesDone:0, lastSpeedTs:null, lastSpeedBytes:0, currentSpeed:0,
  keyReady:false, xferDone:false,

  reset() {
    try{this.ws?.close();}catch{}
    try{this.dc?.close();}catch{}
    try{this.pc?.close();}catch{}
    Object.assign(this,{
      mode:null,ws:null,pc:null,dc:null,
      polite:false,makingOffer:false,ignoreOffer:false,
      keyPair:null,pendingPeerKey:null,sharedKey:null,sessionCode:null,
      file:null,fileHasher:null,totalChunks:0,sentChunks:0,paused:false,
      fileMeta:null,chunks:[],rcvdChunks:0,
      startTime:null,bytesDone:0,lastSpeedTs:null,lastSpeedBytes:0,currentSpeed:0,
      keyReady:false,xferDone:false,
    });
  },
};

// ─── UTILS ────────────────────────────────────────────────────────

const sleep = ms => new Promise(r => setTimeout(r, ms));

function fmt(b) {
  if(b<1024) return `${b} B`;
  if(b<1024**2) return `${(b/1024).toFixed(1)} KB`;
  if(b<1024**3) return `${(b/1024**2).toFixed(1)} MB`;
  return `${(b/1024**3).toFixed(2)} GB`;
}
function fmtSpeed(bps){ return `${fmt(bps)}/s`; }
function esc(s){
  return String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

// ─── WEBRTC — PERFECT NEGOTIATION ────────────────────────────────
//
// Both peers run identical code. The 'polite' peer yields if there's
// a simultaneous offer collision; the 'impolite' peer wins.
// Roles are assigned by the server: the receiver (who joins) is polite,
// the sender (who created the session) is impolite.
// This matches the convention: the initiating side is impolite.

function createPeerConnection() {
  const pc = new RTCPeerConnection({ iceServers: CONFIG.ICE_SERVERS });

  // Out-of-band DataChannel — BOTH sides create it with the same id.
  // This bypasses in-band SDP negotiation for the DC entirely, which is
  // the root cause of WebKit/iOS sender failures (double onnegotiationneeded).
  const dc = pc.createDataChannel('qsend', { negotiated:true, id:0, ordered:true });
  state.dc = dc;
  setupDataChannel(dc);

  // onnegotiationneeded: backup handler for renegotiation cases.
  // The initial offer is sent explicitly in the 'peer-joined' handler to
  // work around Safari iOS not firing this event for negotiated DataChannels.
  // makingOffer guard prevents double-offer if this DOES fire on Chrome/Firefox.
  pc.onnegotiationneeded = async () => {
    if (state.makingOffer) {
      console.log('[PC] onnegotiationneeded skipped — offer already in progress');
      return;
    }
    try {
      state.makingOffer = true;
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      state.ws?.send(JSON.stringify({ type:'description', sdp:pc.localDescription }));
      console.log('[PC] onnegotiationneeded — offer sent');
    } catch(e) {
      console.error('[PC] onnegotiationneeded error:', e);
    } finally {
      state.makingOffer = false;
    }
  };

  pc.onicecandidate = ({ candidate }) => {
    // Filter empty sentinel candidates
    if (candidate && candidate.candidate !== '' && state.ws?.readyState === WebSocket.OPEN) {
      console.log('[ICE] Sending:', candidate.type, candidate.protocol);
      state.ws.send(JSON.stringify({ type:'ice', candidate }));
    }
  };

  pc.oniceconnectionstatechange = () => {
    console.log('[ICE] State:', pc.iceConnectionState);
    UI.setConnDot(pc.iceConnectionState);
    if (pc.iceConnectionState === 'failed') {
      UI.status('ICE failed — could not connect. Try again on a different network.', 'error');
      UI.setConnType('Failed');
    }
  };

  pc.onconnectionstatechange = () => {
    console.log('[PC] Connection:', pc.connectionState);
    if (pc.connectionState === 'connected') detectConnType(pc);
  };

  pc.onsignalingstatechange = () => console.log('[PC] Signaling:', pc.signalingState);

  return pc;
}

async function detectConnType(pc) {
  try {
    const stats = await pc.getStats();
    for (const r of stats.values()) {
      if (r.type === 'candidate-pair' && r.state === 'succeeded') {
        const local = stats.get(r.localCandidateId);
        UI.setConnType(local?.candidateType === 'relay' ? 'TURN Relay' : '⚡ P2P Direct');
        return;
      }
    }
  } catch {}
}

// ─── DATA CHANNEL ─────────────────────────────────────────────────

function setupDataChannel(dc) {
  console.log('[DC] Setup, readyState:', dc.readyState);
  dc.binaryType = 'arraybuffer';
  dc.bufferedAmountLowThreshold = CONFIG.RESUME_BUFFER;

  dc.onopen = async () => {
    console.log('[DC] Open — ECDH key exchange');
    UI.status('Channel open — performing key exchange…', 'info');
    UI.setEncStatus('Exchanging keys…');

    // Generate our keypair. Both sides do this simultaneously.
    // pendingPeerKey handles the race where the peer's key arrives
    // before our generateKeyPair() completes (common on iOS vs desktop).
    state.keyPair = await Crypto.generateKeyPair();
    const pub = await Crypto.exportPublicKey(state.keyPair);
    dc.send(JSON.stringify({ type:'ecdh-key', pub }));

    // If peer's key arrived early while we were generating, process it now.
    if (state.pendingPeerKey) {
      console.log('[CRYPTO] Processing buffered peer key');
      const saved = state.pendingPeerKey;
      state.pendingPeerKey = null;
      await onControlMsg({ type:'ecdh-key', pub:saved });
    }
  };

  dc.onclose = () => {
    console.log('[DC] Closed');
    if (!state.xferDone) UI.status('Channel closed.', 'info');
  };

  dc.onerror = (e) => {
    console.error('[DC] Error:', e);
    if (!state.xferDone) UI.status(`Channel error: ${e.message||'unknown'}`, 'error');
  };

  dc.onmessage = async ({ data }) => {
    if (typeof data === 'string') {
      let msg;
      try { msg = JSON.parse(data); } catch(e) { console.error('[DC] Bad JSON:', e); return; }
      console.log('[DC] Msg:', msg.type);
      await onControlMsg(msg);
    } else {
      await onChunk(data);
    }
  };
}

// ─── CONTROL MESSAGES ─────────────────────────────────────────────

async function onControlMsg(msg) {
  switch (msg.type) {

    case 'ecdh-key': {
      // Buffer if our keypair isn't ready yet (generateKeyPair still awaiting)
      if (!state.keyPair) {
        console.log('[CRYPTO] Peer key arrived early — buffering');
        state.pendingPeerKey = msg.pub;
        return;
      }
      console.log('[CRYPTO] Deriving shared key…');
      try {
        const peerPub   = await Crypto.importPublicKey(msg.pub);
        state.sharedKey = await Crypto.deriveSharedKey(state.keyPair, peerPub);
        state.keyReady  = true;
        console.log('[CRYPTO] AES-256-GCM key ready ✓');
        UI.setLockState(true);
        UI.status('🔒 End-to-end encryption active.', 'success');
        if (state.mode === 'send' && state.file) await startTransfer();
      } catch(e) {
        console.error('[CRYPTO] Key exchange failed:', e);
        UI.status(`Key exchange failed: ${e.message}`, 'error');
      }
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

    case 'verified':
      state.xferDone = true;
      if (msg.ok) { UI.status('✓ Verified — transfer complete!', 'success'); UI.showSendComplete(); }
      else        { UI.status('⚠ Remote integrity check failed!', 'error'); }
      state.ws?.send(JSON.stringify({ type:'done' }));
      break;

    case 'pause':  state.paused=true;  UI.status('Transfer paused.',  'info'); break;
    case 'resume': state.paused=false; UI.status('Transfer resumed.', 'info'); break;
  }
}

// ─── SEND ─────────────────────────────────────────────────────────

async function startTransfer() {
  if (!state.sharedKey || !state.file) return;
  const file        = state.file;
  const totalChunks = Math.ceil(file.size / CONFIG.CHUNK_SIZE);

  state.totalChunks = totalChunks; state.sentChunks = 0;
  state.startTime   = Date.now(); state.bytesDone = 0;
  state.fileHasher  = new StreamSHA256();

  state.dc.send(JSON.stringify({
    type:'file-meta', name:file.name, size:file.size,
    mimeType:file.type||'application/octet-stream',
    totalChunks, lastModified:file.lastModified,
  }));

  UI.status(`Sending ${esc(file.name)}…`, 'info');
  UI.setSendProgressVisible(true);

  // Read entire file into memory once before the loop.
  // Safari iOS can detach or throw on File.slice() after many async yields.
  let fileBuf;
  try {
    fileBuf = new Uint8Array(await file.arrayBuffer());
  } catch(e) {
    UI.status(`Could not read file: ${e.message}`, 'error');
    return;
  }

  for (let i = 0; i < totalChunks; i++) {
    while (state.dc.bufferedAmount > CONFIG.MAX_BUFFER || state.paused) {
      await sleep(30);
      if (state.dc.readyState !== 'open') { UI.status('Transfer aborted.', 'error'); return; }
    }

    const start = i * CONFIG.CHUNK_SIZE;
    const plain = fileBuf.subarray(start, Math.min(start + CONFIG.CHUNK_SIZE, file.size));
    state.fileHasher.update(plain);

    const encrypted = await Crypto.encryptChunk(state.sharedKey, i, plain);

    try {
      // Send as Uint8Array — Safari/Edge silently drop raw ArrayBuffer sends
      state.dc.send(new Uint8Array(encrypted));
    } catch(e) {
      console.error('[SEND] dc.send failed chunk', i, e);
      UI.status(`Send error on chunk ${i}: ${e.message}`, 'error');
      return;
    }

    state.sentChunks++;
    state.bytesDone += plain.length;
    updateSpeed(plain.length);
    UI.setSendProgress(state.sentChunks / totalChunks, state.currentSpeed);
  }

  while (state.dc.bufferedAmount > 0) await sleep(50);
  state.dc.send(JSON.stringify({ type:'transfer-complete', sha256:state.fileHasher.hex() }));
  UI.status('All chunks sent — awaiting verification…', 'info');
}

// ─── RECEIVE ──────────────────────────────────────────────────────

async function onChunk(buf) {
  if (!state.sharedKey) return;
  let index, data;
  try { ({index,data} = await Crypto.decryptChunk(state.sharedKey, buf)); }
  catch(e) { UI.status('⚠ Decryption failed — possible tampering!', 'error'); console.error(e); return; }
  state.chunks[index] = data;
  state.rcvdChunks++;
  state.bytesDone += data.length;
  updateSpeed(data.length);
  UI.setRecvProgress(state.rcvdChunks / state.totalChunks, state.currentSpeed);
}

async function finalizeReceive(expected) {
  UI.status('Verifying integrity…', 'info');
  const miss = state.chunks.findIndex(c => c === null);
  if (miss !== -1) {
    state.dc.send(JSON.stringify({ type:'verified', ok:false }));
    UI.status(`⚠ Missing chunk ${miss}!`, 'error'); return;
  }
  const h = new StreamSHA256();
  for (const c of state.chunks) h.update(c);
  const actual = h.hex();
  if (actual !== expected) {
    state.dc.send(JSON.stringify({ type:'verified', ok:false }));
    UI.status('⚠ Integrity FAILED!', 'error'); return;
  }
  const blob = new Blob(state.chunks, { type:state.fileMeta.mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href:url, download:state.fileMeta.name });

  // Mark done and send verified BEFORE triggering download.
  // Any session-expired / DC-close events during the save dialog won't
  // overwrite the success status (guarded by xferDone below).
  state.chunks=[]; state.xferDone=true;
  state.dc.send(JSON.stringify({ type:'verified', ok:true }));
  UI.status('✓ File saved — SHA-256 verified.', 'success');
  UI.showReceiveComplete(actual);

  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// ─── SIGNALING — PERFECT NEGOTIATION ─────────────────────────────

function connectSignaling(joinCode) {
  return new Promise((resolve, reject) => {
    let ws;
    try { ws = new WebSocket(CONFIG.SIGNAL_URL); }
    catch(e) { reject(new Error(`WebSocket failed: ${e.message}`)); return; }

    state.ws = ws;
    const timeout = setTimeout(() => { ws.close(); reject(new Error('Signaling timed out')); }, 10_000);

    ws.onopen = () => {
      clearTimeout(timeout);
      console.log('[WS] Connected');
      if (state.mode === 'send') {
        ws.send(JSON.stringify({ type:'create' }));
      } else {
        ws.send(JSON.stringify({ type:'join', code:joinCode }));
      }
    };

    ws.onmessage = async ({ data }) => {
      let msg;
      try { msg = JSON.parse(data); } catch { return; }
      console.log('[WS] ←', msg.type, msg.code||msg.message||'');

      switch (msg.type) {

        case 'created':
          state.sessionCode = msg.code;
          // Sender is IMPOLITE — it initiates and doesn't yield on collision
          state.polite = false;
          UI.showCode(msg.code);
          UI.status('Waiting for receiver — share the code or QR…', 'info');
          resolve();
          break;

        case 'joined':
          // Receiver is POLITE — create PC eagerly so it's ready when the
          // offer arrives. Creating it lazily inside 'description' can cause
          // onnegotiationneeded to race with the incoming offer.
          state.polite = true;
          state.pc = createPeerConnection();
          UI.status('Joined session — establishing P2P connection…', 'info');
          resolve();
          break;

        // peer-joined: receiver connected — create PC and explicitly send offer.
        // We do NOT rely on onnegotiationneeded here because Safari iOS has a
        // confirmed bug: when a DataChannel is created with {negotiated:true},
        // Safari never fires onnegotiationneeded (it treats "negotiated" as
        // "no negotiation needed at all"). Chrome iOS (WKWebView) does not have
        // this bug, which is why Chrome iOS works and Safari iOS doesn't.
        case 'peer-joined':
          UI.status('Peer connected — setting up encrypted channel…', 'info');
          state.pc = createPeerConnection();
          // Set makingOffer=true immediately so onnegotiationneeded (if it
          // does fire on non-Safari browsers) doesn't race with us.
          state.makingOffer = true;
          try {
            const offer = await state.pc.createOffer();
            await state.pc.setLocalDescription(offer);
            ws.send(JSON.stringify({ type:'description', sdp:state.pc.localDescription }));
            console.log('[SEND] Offer sent explicitly (Safari onnegotiationneeded bypass)');
          } catch(e) {
            console.error('[SEND] createOffer failed:', e);
            UI.status('Offer failed: ' + (e.message||e), 'error');
          } finally {
            state.makingOffer = false;
          }
          break;

        // peer-present: sent to the RECEIVER when they join a session that
        // already has a sender. Receiver creates their PC which triggers
        // onnegotiationneeded on the sender's side via the server's peer-joined.
        // Receiver just needs to create their PC to be ready for the offer.
        case 'peer-present':
          UI.status('Connected to sender — establishing P2P connection…', 'info');
          state.pc = createPeerConnection();
          break;

        // Perfect Negotiation: unified handler for offer AND answer
        case 'description': {
          if (!state.pc) {
            // Late arrival before our PC was ready — create it now
            state.pc = createPeerConnection();
          }
          const pc = state.pc;
          const description = msg.sdp;
          const offerCollision = description.type === 'offer' &&
            (state.makingOffer || pc.signalingState !== 'stable');

          state.ignoreOffer = !state.polite && offerCollision;
          if (state.ignoreOffer) {
            console.log('[SDP] Impolite — ignoring colliding offer');
            break;
          }

          try {
            await pc.setRemoteDescription(description);
            if (description.type === 'offer') {
              // Explicit createAnswer() for Safari compatibility (same reason as createOffer above)
              const answer = await pc.createAnswer();
              await pc.setLocalDescription(answer);
              ws.send(JSON.stringify({ type:'description', sdp:pc.localDescription }));
            }
          } catch(e) {
            console.error('[SDP] setRemoteDescription failed:', e);
            UI.status(`SDP error: ${e.message}`, 'error');
          }
          break;
        }

        case 'ice':
          if (msg.candidate && state.pc) {
            try {
              await state.pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
              console.log('[ICE] Applied');
            } catch(e) {
              // Ignore ICE errors during perfect negotiation offer collisions
              if (!state.ignoreOffer) console.warn('[ICE] Failed:', e.message);
            }
          }
          break;

        case 'error':
          console.error('[WS] Error:', msg.message);
          UI.status(`Signaling error: ${msg.message}`, 'error');
          reject(new Error(msg.message));
          break;

        case 'session-expired':
          if (!state.xferDone && (!state.pc || state.pc.connectionState !== 'connected')) {
            UI.status('Session expired.', 'error');
          } else {
            console.log('[WS] Session expired — ignoring (xferDone or P2P active)');
          }
          break;

        case 'peer-disconnected':
          if (!state.xferDone) UI.status('Peer disconnected.', 'error');
          break;
      }
    };

    ws.onerror = (e) => { clearTimeout(timeout); console.error('[WS] Error:', e); reject(new Error('WebSocket error')); };
    ws.onclose = () => console.log('[WS] Closed');
  });
}

// ─── SPEED ────────────────────────────────────────────────────────

function updateSpeed(bytes) {
  const now = Date.now();
  if (!state.lastSpeedTs) { state.lastSpeedTs=now; state.lastSpeedBytes=0; }
  state.lastSpeedBytes += bytes;
  const dt = now - state.lastSpeedTs;
  if (dt >= 500) {
    state.currentSpeed   = (state.lastSpeedBytes/dt)*1000;
    state.lastSpeedTs    = now;
    state.lastSpeedBytes = 0;
  }
}

// ─── UI ───────────────────────────────────────────────────────────

const UI = {
  status(msg, type='info') {
    const el=document.getElementById('status-message');
    if(!el) return;
    el.innerHTML=esc(msg); el.className=`status-msg status-${type}`; el.style.display='block';
  },
  setEncStatus(text) {
    const el=document.getElementById('enc-status');
    if(el){ el.textContent=text; el.classList.toggle('active',!!text); }
  },
  setConnType(text) { const el=document.getElementById('conn-type'); if(el) el.textContent=text; },
  setConnDot(s) {
    const dot=document.getElementById('conn-dot');
    if(!dot) return;
    dot.className='conn-dot '+(s==='connected'||s==='completed'?'green':s==='checking'||s==='new'?'yellow':'red');
  },
  setLockState(locked) {
    document.getElementById('lock-icon')?.classList.toggle('locked',locked);
    this.setEncStatus(locked?'AES-256-GCM ✓':'Not encrypted');
  },
  showCode(code) {
    const wrap=document.getElementById('code-display'),el=document.getElementById('session-code');
    if(!wrap||!el) return;
    el.textContent=code.slice(0,3)+' '+code.slice(3);
    wrap.classList.remove('hidden');
    renderQR(`${location.origin}${location.pathname}?receive=${code}`);
  },
  setSendProgressVisible(v) { document.getElementById('send-progress-wrap')?.classList.toggle('hidden',!v); },
  setSendProgress(pct,spd) {
    const p=Math.round(pct*100);
    const bar=document.getElementById('send-bar'),lbl=document.getElementById('send-pct'),s=document.getElementById('send-speed');
    if(bar){ bar.style.width=p+'%'; bar.setAttribute('aria-valuenow',p); }
    if(lbl) lbl.textContent=p+'%';
    if(s&&spd) s.textContent=fmtSpeed(spd);
  },
  showSendComplete() { document.getElementById('send-complete')?.classList.remove('hidden'); },
  showReceiveMeta(meta) {
    const el=document.getElementById('recv-meta');
    if(!el) return;
    el.innerHTML=`<span class="meta-name">${esc(meta.name)}</span><span class="meta-size">${fmt(meta.size)}</span>`;
    el.classList.remove('hidden');
    document.getElementById('recv-progress-wrap')?.classList.remove('hidden');
  },
  setRecvProgress(pct,spd) {
    const p=Math.round(pct*100);
    const bar=document.getElementById('recv-bar'),lbl=document.getElementById('recv-pct'),s=document.getElementById('recv-speed');
    if(bar){ bar.style.width=p+'%'; bar.setAttribute('aria-valuenow',p); }
    if(lbl) lbl.textContent=p+'%';
    if(s&&spd) s.textContent=fmtSpeed(spd);
  },
  showReceiveComplete(hash) {
    const el=document.getElementById('recv-complete');
    if(!el) return;
    el.innerHTML=`<div class="hash-label">SHA-256</div><div class="hash-value">${hash}</div>`;
    el.classList.remove('hidden');
    document.getElementById('recv-progress-wrap')?.classList.add('complete');
  },
};

// ─── QR ───────────────────────────────────────────────────────────

function renderQR(text) {
  const c=document.getElementById('qr-container');
  if(!c) return;
  c.innerHTML=''; c.classList.remove('hidden');
  if(typeof QRCode!=='undefined'){
    new QRCode(c,{text,width:152,height:152,colorDark:'#00e5ff',colorLight:'#0a0f1a',correctLevel:QRCode.CorrectLevel.M});
  } else {
    c.textContent=text;
  }
}

// ─── INIT ─────────────────────────────────────────────────────────

async function initSend()        { state.mode='send';    await connectSignaling(); }
async function initReceive(code) { state.mode='receive'; await connectSignaling(code); }

// ─── FILE QUEUE ───────────────────────────────────────────────────

const fileQueue=[]; let queueActive=false;

async function enqueueFile(f){ fileQueue.push(f); if(!queueActive) processQueue(); }

async function processQueue(){
  queueActive=true;
  while(fileQueue.length>0){
    state.file=fileQueue.shift();
    showFileSelected(state.file);
    if(state.keyReady) await startTransfer();
  }
  queueActive=false;
}

// ─── DOM ──────────────────────────────────────────────────────────

function showFileSelected(file){
  const el=document.getElementById('file-info');
  if(!el) return;
  el.innerHTML=`<div class="file-icon">${getFileIcon(file.name)}</div><div class="file-details"><div class="fn">${esc(file.name)}</div><div class="fs">${fmt(file.size)} · ${file.type||'unknown type'}</div></div>`;
  el.classList.remove('hidden');
  document.getElementById('send-btn').disabled=false;
}
UI.showFileSelected=showFileSelected;

function getFileIcon(name){
  const ext=name.split('.').pop().toLowerCase();
  return({pdf:'📄',zip:'🗜',rar:'🗜',gz:'🗜',tar:'🗜',mp4:'🎬',mov:'🎬',mkv:'🎬',avi:'🎬',mp3:'🎵',wav:'🎵',flac:'🎵',ogg:'🎵',jpg:'🖼',jpeg:'🖼',png:'🖼',gif:'🖼',webp:'🖼',svg:'🖼',doc:'📝',docx:'📝',txt:'📝',md:'📝',xls:'📊',xlsx:'📊',csv:'📊',exe:'⚙️',dmg:'⚙️',deb:'⚙️',apk:'⚙️'})[ext]||'📁';
}

function initDrop(){
  const zone=document.getElementById('drop-zone');
  if(!zone) return;
  ['dragenter','dragover'].forEach(ev=>zone.addEventListener(ev,e=>{e.preventDefault();zone.classList.add('drag-over');}));
  ['dragleave','drop'].forEach(ev=>zone.addEventListener(ev,e=>{
    e.preventDefault(); zone.classList.remove('drag-over');
    if(ev==='drop'&&e.dataTransfer.files.length){ Array.from(e.dataTransfer.files).forEach(enqueueFile); showFileSelected(e.dataTransfer.files[0]); }
  }));
  zone.addEventListener('click',()=>document.getElementById('file-input')?.click());
  document.addEventListener('dragover',e=>e.preventDefault());
  document.addEventListener('drop',e=>{
    e.preventDefault();
    if(e.dataTransfer.files.length&&state.mode!=='receive'){ Array.from(e.dataTransfer.files).forEach(enqueueFile); showFileSelected(e.dataTransfer.files[0]); }
  });
}

function initCodeInput(){
  const input=document.getElementById('receive-code-input');
  if(!input) return;
  input.addEventListener('input',()=>{ input.value=input.value.replace(/\D/g,'').slice(0,6); });
  input.addEventListener('keydown',e=>{ if(e.key==='Enter') document.getElementById('receive-btn')?.click(); });

  const urlCode=new URLSearchParams(location.search).get('receive');
  if(urlCode&&/^\d{6}$/.test(urlCode)){
    // Strip ?receive= from the URL immediately so that if the user navigates
    // back or reloads, clicking "Send File" doesn't re-trigger receive mode.
    // This is also why mobile was registering as the RECEIVER even when
    // clicking Send — the ?receive= param was still in the URL from the QR scan.
    history.replaceState(null,'',location.pathname);

    input.value=urlCode;
    document.getElementById('receive-panel')?.scrollIntoView({behavior:'smooth'});

    // Auto-connect as receiver when arriving via QR/link — no button needed.
    UI.status('Connecting to sender…','info');
    const btn=document.getElementById('receive-btn');
    if(btn){ btn.disabled=true; btn.textContent='Connecting…'; }
    initReceive(urlCode).catch(e=>{
      UI.status(`Connection failed: ${e.message}`,'error');
      if(btn){ btn.disabled=false; btn.textContent='Connect'; }
    });
  }
}

function togglePause(){
  if(!state.dc||state.dc.readyState!=='open') return;
  state.paused=!state.paused;
  state.dc.send(JSON.stringify({type:state.paused?'pause':'resume'}));
  const btn=document.getElementById('pause-btn');
  if(btn) btn.textContent=state.paused?'▶ Resume':'⏸ Pause';
}

async function init(){
  if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});
  initDrop(); initCodeInput();

  document.getElementById('file-input')?.addEventListener('change',e=>{
    const files=Array.from(e.target.files||[]);
    if(files.length){ files.forEach(enqueueFile); showFileSelected(files[0]); }
    e.target.value='';
  });

  document.getElementById('send-btn')?.addEventListener('click',async()=>{
    if(!state.file&&!fileQueue.length){ UI.status('Select a file first.','error'); return; }
    const btn=document.getElementById('send-btn');
    btn.disabled=true; btn.textContent='Connecting…';
    try{ await initSend(); }
    catch(e){ UI.status(`Connection failed: ${e.message}`,'error'); btn.disabled=false; btn.textContent='Send File'; }
  });

  document.getElementById('receive-btn')?.addEventListener('click',async()=>{
    const input=document.getElementById('receive-code-input');
    const code=(input?.value||'').replace(/\D/g,'');
    if(!/^\d{6}$/.test(code)){ UI.status('Enter a valid 6-digit code.','error'); input?.focus(); return; }
    const btn=document.getElementById('receive-btn');
    btn.disabled=true; btn.textContent='Connecting…';
    try{ await initReceive(code); }
    catch(e){ UI.status(`Connection failed: ${e.message}`,'error'); btn.disabled=false; btn.textContent='Connect'; }
  });

  document.getElementById('copy-code-btn')?.addEventListener('click',async()=>{
    if(!state.sessionCode) return;
    try{
      await navigator.clipboard.writeText(state.sessionCode);
      const btn=document.getElementById('copy-code-btn');
      btn.textContent='Copied!'; setTimeout(()=>{btn.textContent='Copy';},1500);
    }catch{ UI.status('Copy failed — copy manually.','error'); }
  });

  document.getElementById('copy-link-btn')?.addEventListener('click',async()=>{
    if(!state.sessionCode) return;
    const url=`${location.origin}${location.pathname}?receive=${state.sessionCode}`;
    try{
      await navigator.clipboard.writeText(url);
      const btn=document.getElementById('copy-link-btn');
      btn.textContent='Link Copied!'; setTimeout(()=>{btn.textContent='Copy Link';},1500);
    }catch{ UI.status('Could not copy link.','error'); }
  });

  document.getElementById('pause-btn')?.addEventListener('click',togglePause);
  document.getElementById('reset-btn')?.addEventListener('click',()=>{ state.reset(); location.href=location.pathname; });
}

document.addEventListener('DOMContentLoaded', init);