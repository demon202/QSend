/**
 * QSend — Secure Peer-to-Peer File Transfer
 * app.js
 *
 * THREE FIXES applied vs the version in the documents:
 *
 * FIX 1 — CHUNK SIZE (index.html fix too)
 *   CHUNK_SIZE was 256*1024. After AES-GCM overhead (4+12+16=32 bytes),
 *   encrypted size = 262,176 bytes which exceeds Chrome's hard DataChannel
 *   limit of 262,144 bytes. dc.send() threw TypeError silently → stuck at 0%.
 *   Fix: CHUNK_SIZE = 16*1024 (16 KB). Encrypted = 16,416 bytes. Safe on all browsers.
 *
 * FIX 2 — ICE SERVERS
 *   3 STUN + 3 TURN URLs = 6 entries. Chrome warns at ≥5 and slows gathering.
 *   The openrelay TURN server was also causing "ICE failed, TURN server broken".
 *   Fix: 1 STUN only. For most users on the same network or without strict NAT,
 *   direct P2P works fine. If you need TURN, use a reliable paid provider.
 *
 * FIX 3 — NULL ICE CANDIDATE
 *   Some browsers fire onicecandidate with candidate.candidate === "" (empty string)
 *   as an end-of-candidates sentinel. This passed the `if (candidate)` check and
 *   was relayed to the peer, printing "[ICE] Sending candidate: null null".
 *   Fix: guard with candidate.candidate !== ''
 */

'use strict';

const CONFIG = Object.freeze({
  SIGNAL_URL: (() => {
    const local = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    return local ? 'ws://localhost:8080' : 'wss://qsend-signal.qsend-test.workers.dev';
  })(),

  // FIX 1: 16 KB chunks → 16,416 bytes encrypted. Well under every browser's limit.
  CHUNK_SIZE:    16 * 1024,
  MAX_BUFFER:    4  * 1024 * 1024,
  RESUME_BUFFER: 256 * 1024,

  // FIX 2: Single STUN server. openrelay TURN was broken per console ("TURN server broken").
  // Add a reliable TURN here if you need to support symmetric NAT / strict firewalls.
  ICE_SERVERS: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
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
  mode:null, ws:null, pc:null, dc:null, pendingICE:[],
  keyPair:null, sharedKey:null, sessionCode:null,
  file:null, fileHasher:null, totalChunks:0, sentChunks:0, paused:false,
  fileMeta:null, chunks:[], rcvdChunks:0,
  startTime:null, bytesDone:0, lastSpeedTs:null, lastSpeedBytes:0, currentSpeed:0,
  keyReady:false, xferDone:false,

  reset() {
    try{this.ws?.close();}catch{}
    try{this.dc?.close();}catch{}
    try{this.pc?.close();}catch{}
    Object.assign(this,{
      mode:null,ws:null,pc:null,dc:null,pendingICE:[],
      keyPair:null,sharedKey:null,sessionCode:null,
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

// ─── WEBRTC ───────────────────────────────────────────────────────

function createPeerConnection() {
  const pc = new RTCPeerConnection({
    iceServers: CONFIG.ICE_SERVERS,
    iceCandidatePoolSize: 4,
  });

  pc.onicecandidate = ({ candidate }) => {
    // FIX 3: filter null candidates AND empty-string sentinel candidates
    if (candidate && candidate.candidate !== '' && state.ws?.readyState === WebSocket.OPEN) {
      console.log('[ICE] Sending candidate:', candidate.type, candidate.protocol);
      state.ws.send(JSON.stringify({ type:'ice', candidate }));
    }
  };

  pc.oniceconnectionstatechange = () => {
    console.log('[ICE] State:', pc.iceConnectionState);
    UI.setConnDot(pc.iceConnectionState);
    if (pc.iceConnectionState === 'failed') {
      UI.status('ICE failed — peers could not connect directly. Try on the same network or add a TURN server.', 'error');
      UI.setConnType('Failed');
    }
  };

  pc.onconnectionstatechange = () => {
    console.log('[PC] Connection:', pc.connectionState);
    if (pc.connectionState === 'connected') detectConnType(pc);
  };

  pc.onsignalingstatechange = () => {
    console.log('[PC] Signaling:', pc.signalingState);
  };

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
    state.keyPair = await Crypto.generateKeyPair();
    const pub = await Crypto.exportPublicKey(state.keyPair);
    dc.send(JSON.stringify({ type:'ecdh-key', pub }));
  };

  dc.onclose = () => { console.log('[DC] Closed'); if(!state.xferDone) UI.status('Channel closed.','info'); };
  dc.onerror = (e) => { console.error('[DC] Error:',e); UI.status(`Channel error: ${e.message||'unknown'}`,'error'); };

  dc.onmessage = async ({ data }) => {
    if (typeof data === 'string') {
      const msg = JSON.parse(data);
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
      console.log('[CRYPTO] Deriving shared key…');
      const peerPub   = await Crypto.importPublicKey(msg.pub);
      state.sharedKey = await Crypto.deriveSharedKey(state.keyPair, peerPub);
      state.keyReady  = true;
      console.log('[CRYPTO] AES-256-GCM key ready ✓');
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

    case 'verified':
      state.xferDone = true;
      if (msg.ok) { UI.status('✓ Verified — transfer complete!','success'); UI.showSendComplete(); }
      else        { UI.status('⚠ Remote integrity check failed!','error'); }
      state.ws?.send(JSON.stringify({ type:'done' }));
      break;

    case 'pause':  state.paused=true;  UI.status('Transfer paused.', 'info');  break;
    case 'resume': state.paused=false; UI.status('Transfer resumed.','info'); break;
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

  for (let i = 0; i < totalChunks; i++) {
    // Backpressure
    while (state.dc.bufferedAmount > CONFIG.MAX_BUFFER || state.paused) {
      await sleep(30);
      if (state.dc.readyState !== 'open') { UI.status('Transfer aborted.','error'); return; }
    }

    const start     = i * CONFIG.CHUNK_SIZE;
    const plain     = new Uint8Array(await file.slice(start, Math.min(start+CONFIG.CHUNK_SIZE, file.size)).arrayBuffer());
    state.fileHasher.update(plain);

    const encrypted = await Crypto.encryptChunk(state.sharedKey, i, plain);

    // Explicit size check — surface the error clearly if something is still wrong
    if (encrypted.byteLength > 65536) {
      console.warn('[SEND] Chunk', i, 'encrypted size:', encrypted.byteLength, '— may be too large');
    }

    try {
      state.dc.send(encrypted);
    } catch (e) {
      console.error('[SEND] dc.send failed chunk', i, 'size:', encrypted.byteLength, e);
      UI.status(`Send error on chunk ${i} (${encrypted.byteLength} bytes): ${e.message}`, 'error');
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
  catch(e) { UI.status('⚠ Decryption failed — possible tampering!','error'); console.error(e); return; }
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
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  state.chunks=[]; state.xferDone=true;
  state.dc.send(JSON.stringify({ type:'verified', ok:true }));
  UI.status('✓ File saved — SHA-256 verified.', 'success');
  UI.showReceiveComplete(actual);
}

// ─── SIGNALING ────────────────────────────────────────────────────

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
        // Create PC before sending — guarantees state.pc exists when peer-joined arrives
        console.log('[SEND] Creating PC+DC before create message');
        state.pc = createPeerConnection();
        state.dc = state.pc.createDataChannel('qsend', { ordered:true });
        setupDataChannel(state.dc);
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
          UI.showCode(msg.code);
          UI.status('Waiting for receiver — share the code or QR…', 'info');
          resolve();
          break;

        case 'joined':
          UI.status('Joined session — waiting for sender…', 'info');
          resolve();
          break;

        case 'peer-joined':
          console.log('[SEND] peer-joined. state.pc:', state.pc ? 'OK' : 'NULL←BUG');
          UI.status('Peer connected — negotiating…', 'info');
          try {
            const offer = await state.pc.createOffer();
            await state.pc.setLocalDescription(offer);
            console.log('[SEND] Offer →');
            ws.send(JSON.stringify({ type:'offer', sdp:state.pc.localDescription }));
          } catch(e) {
            console.error('[SEND] createOffer failed:', e);
            UI.status(`Offer failed: ${e.message}`, 'error');
          }
          break;

        case 'offer': {
          console.log('[RECV] offer ←, creating PC');
          state.pc = createPeerConnection();
          state.pc.ondatachannel = ({ channel }) => {
            console.log('[RECV] DataChannel:', channel.label);
            state.dc = channel;
            setupDataChannel(channel);
          };
          await state.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
          // Drain ICE buffer AFTER setRemoteDescription
          for (const c of state.pendingICE) {
            try { await state.pc.addIceCandidate(new RTCIceCandidate(c)); } catch {}
          }
          state.pendingICE = [];
          const answer = await state.pc.createAnswer();
          await state.pc.setLocalDescription(answer);
          console.log('[RECV] answer →');
          ws.send(JSON.stringify({ type:'answer', sdp:state.pc.localDescription }));
          break;
        }

        case 'answer':
          // Guard: only accept an answer when we're actually waiting for one.
          // Safari mobile (and some CF Worker replays) can send a duplicate answer
          // after the PC is already in 'stable' state, causing InvalidStateError.
          if (!state.pc || state.pc.signalingState !== 'have-local-offer') {
            console.warn('[SEND] Ignoring answer — signalingState is', state.pc?.signalingState, '(expected have-local-offer)');
            break;
          }
          console.log('[SEND] answer ←');
          await state.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
          for (const c of state.pendingICE) {
            try { await state.pc.addIceCandidate(new RTCIceCandidate(c)); } catch {}
          }
          state.pendingICE = [];
          break;

        case 'ice':
          if (msg.candidate) {
            if (state.pc && state.pc.remoteDescription) {
              try {
                await state.pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
                console.log('[ICE] Applied candidate (sdpMid:', msg.candidate.sdpMid, ')');
              } catch(e) { console.warn('[ICE] Failed:', e.message); }
            } else {
              console.log('[ICE] Buffered');
              state.pendingICE.push(msg.candidate);
            }
          }
          break;

        case 'error':
          console.error('[WS] Error:', msg.message);
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

    ws.onerror = (e) => { clearTimeout(timeout); console.error('[WS] Error:', e); reject(new Error('WebSocket error')); };
    ws.onclose = () => { console.log('[WS] Closed'); };
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

async function initSend() {
  state.mode='send';
  await connectSignaling();
}

async function initReceive(code) {
  state.mode='receive';
  await connectSignaling(code);
}

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
    input.value=urlCode;
    UI.status('Code pre-filled from link. Click Connect when ready.','info');
    document.getElementById('receive-panel')?.scrollIntoView({behavior:'smooth'});
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

  if(location.search.includes('share-target')){
    const title=new URLSearchParams(location.search).get('title')||'';
    UI.status(`Received share: "${esc(title)}" — select the file to send.`,'info');
  }
}

document.addEventListener('DOMContentLoaded', init);