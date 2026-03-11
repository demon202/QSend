# QSend: A Secure Peer-to-Peer File Transfer App

> Encrypted browser-to-browser file transfer. Files never touch any server.

[![Deploy Frontend](https://img.shields.io/badge/frontend-GitHub%20Pages-181717?logo=github)](https://pages.github.com)
[![Deploy Server](https://img.shields.io/badge/server-Fly.io-8B5CF6?logo=fly)](https://fly.io)

---

## How It Works

```
Sender                 Signaling Server              Receiver
  │                         │                            │
  ├─ create session ────────►│                            │
  │◄─ session code ──────────┤                            │
  │                         │◄─── join(code) ────────────┤
  ├─ SDP offer ─────────────►│                            │
  │                         ├──── SDP offer ─────────────►│
  │◄────────────────── SDP answer ──────────────────────--┤
  │◄────── ICE candidates (both ways) ─────────────────── ┤
  │                         │                            │
  │◄══════════ WebRTC DataChannel (P2P / DTLS) ══════════►│
  │                                                       │
  ├─ ECDH public key ─────────────────────────────────── ►│
  │◄──────────────────────────── ECDH public key ─────────┤
  │  [Both derive AES-256-GCM key — server never sees it] │
  │                                                       │
  ├─ encrypt(chunk₀) ─────────────────────────────────── ►│
  ├─ encrypt(chunk₁) ─────────────────────────────────── ►│
  │  ...                                                  │
  ├─ {sha256: "abc..."} ──────────────────────────────── ►│
  │◄────────────────────────── {verified: true} ──────────┤
  │                                                       │
         [Signaling session auto-destroyed]
```

**The signaling server only ever sees:** SDP negotiation blobs and ICE candidates — no file data, no encryption keys, no metadata.

---

## Security Architecture

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Signaling server compromise | Server never sees keys or file data (ECDH key exchange via DataChannel) |
| Network eavesdropping | WebRTC DTLS + AES-256-GCM double encryption |
| Chunk swap / reorder attack | Chunk index used as AES-GCM AAD (authenticated) |
| Man-in-the-middle on signaling | ECDH keys exchanged over DataChannel after DTLS handshake |
| File corruption in transit | SHA-256 of full file verified before download |
| Session hijacking | 6-digit ephemeral codes, 5-minute TTL, destroyed after transfer |
| Metadata leakage | Signaling server logs nothing; no cookies, no tracking |
| Replay attacks | Each transfer uses fresh ECDH keypair and per-chunk random IV |

### Encryption Stack

```
Application layer:  AES-256-GCM  (per-chunk, random 96-bit IV, chunk index as AAD)
Key exchange:       ECDH P-256   (ephemeral, private key never extractable from SubtleCrypto)
Transport layer:    WebRTC DTLS  (TLS 1.2/1.3 with forward secrecy)
Integrity check:    SHA-256      (full file, streaming computation, verified before save)
```

### Chunk Wire Format

```
[4 bytes: chunk index uint32]  ← authenticated (AAD in GCM)
[12 bytes: random IV]          ← unique per chunk
[N bytes: ciphertext]          ← AES-256-GCM encrypted plaintext
[16 bytes: GCM auth tag]       ← tamper detection (appended by SubtleCrypto)
```

Total overhead: **16 bytes per 256 KB chunk** (0.006%)

---

## Project Structure

```
qsend/
├── index.html              # Single-page app UI (deployable to GitHub Pages)
├── app.js                  # WebRTC, crypto, transfer, UI logic
├── sw.js                   # Service worker (PWA offline shell)
├── manifest.json           # PWA manifest (installable, share target)
│
├── server/
│   ├── index.js            # Node.js WebSocket signaling server (main)
│   ├── package.json        # Server dependencies (only: ws)
│   └── cloudflare-worker.js # Alternative: Cloudflare Workers + Durable Objects
│
├── .github/
│   └── workflows/
│       └── deploy.yml      # Auto-deploy frontend to GitHub Pages
│
├── fly.toml                # Fly.io deployment config for server
└── README.md               # This file
```

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/your-org/qsend.git
cd qsend
```

### 2. Run the signaling server locally

```bash
cd server
npm install
npm start
# Server running on ws://localhost:8080
```

### 3. Open the frontend

```bash
# Serve from project root (not server/)
cd ..
npx serve .
# Open http://localhost:3000
```

The `app.js` auto-detects `localhost` and uses `ws://localhost:8080`.

---

## Deployment

### Frontend → GitHub Pages

1. Push to your GitHub repository
2. Go to **Settings → Pages → Source: GitHub Actions**
3. The workflow in `.github/workflows/deploy.yml` deploys automatically on push to `main`

**Before deploying:** Edit `app.js` line ~20 and replace the `SIGNAL_URL`:
```javascript
return isLocal ? 'ws://localhost:8080' : 'wss://YOUR-APP.fly.dev';
//                                              ^^^^^^^^^^^^^^^^^^^^
```

### Signaling Server → Fly.io

```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Create and deploy
cd server
fly launch --name qsend-signal --region iad --no-deploy
# Edit fly.toml if needed, then:
fly deploy

# Check status
fly status
fly logs
```

Your server URL will be: `wss://qsend-signal.fly.dev`

### Signaling Server → Cloudflare Workers (alternative)

```bash
cd server
npm install -g wrangler
wrangler login

# Create wrangler.toml:
cat > wrangler.toml << 'EOF'
name = "qsend-signal"
main = "cloudflare-worker.js"
compatibility_date = "2024-01-01"

[[durable_objects.bindings]]
name = "SESSIONS"
class_name = "SessionStore"

[[migrations]]
tag = "v1"
new_classes = ["SessionStore"]
EOF

wrangler publish
```

Your server URL will be: `wss://qsend-signal.YOUR-ACCOUNT.workers.dev`

---

## Configuration Reference

All configuration is in `app.js` at the top:

```javascript
const CONFIG = Object.freeze({
  // WebSocket URL of your deployed signaling server
  SIGNAL_URL: 'wss://qsend-signal.fly.dev',

  // File chunking
  CHUNK_SIZE:    256 * 1024,      // 256 KB (good balance of latency vs overhead)
  MAX_BUFFER:    4 * 1024 * 1024, // Pause sending at 4 MB buffered

  // WebRTC ICE servers (STUN only — truly P2P)
  ICE_SERVERS: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ],
});
```

### Adding TURN servers (optional)

If you need to support symmetric NAT environments (corporate networks, etc.):

```javascript
ICE_SERVERS: [
  { urls: 'stun:stun.l.google.com:19302' },
  {
    urls:       'turn:your-turn-server.com:3478',
    username:   'your-username',
    credential: 'your-password',
  },
],
```

> ⚠️ TURN servers relay your WebRTC traffic. The data is still E2E encrypted,
> but it does route through the TURN server. Use a self-hosted TURN server
> (e.g., [coturn](https://github.com/coturn/coturn)) for maximum privacy.

---

## Browser Compatibility

| Browser | Minimum Version | Notes |
|---------|----------------|-------|
| Chrome  | 74+            | Full support |
| Firefox | 78+            | Full support |
| Safari  | 15+            | Full support (WebRTC improved in 15) |
| Edge    | 79+            | Full support (Chromium-based) |
| Mobile Chrome | 74+   | Full support |
| Mobile Safari | 15+   | Full support |

**Requires:** WebRTC DataChannels, Web Crypto API (SubtleCrypto), ES2020+

---

## Large File Support

QSend streams files in 256 KB chunks using `File.slice()` — the **sender never loads the full file into RAM**. A 10 GB file uses approximately 512 KB of sender-side RAM at any time.

**Receiver:** chunks are collected in an array of `Uint8Array` objects. For very large files, consider the memory implications:
- A 1 GB file uses ~1 GB of receiver RAM before the download is triggered
- For files > 2 GB, consider implementing `StreamSaver.js` or the `FileSystemAccessAPI` for direct disk writes

Transfer speeds are limited by WebRTC DataChannel throughput, which is typically:
- LAN: 100–500 MB/s
- Internet (same region): 10–50 MB/s  
- Internet (cross-region): 1–10 MB/s

---

## Privacy Guarantees

- ✅ Files **never** touch the signaling server
- ✅ Encryption keys **never** leave the browser
- ✅ No cookies, no localStorage, no sessionStorage
- ✅ No analytics, no tracking pixels, no third-party requests (except Google Fonts CDN + QR library CDN)
- ✅ Session codes are cryptographically random and expire after 5 minutes
- ✅ Sessions are destroyed immediately after transfer completes
- ✅ The signaling server has no database and stores nothing to disk

**To eliminate ALL third-party requests** (for maximum privacy):
1. Self-host or inline the Google Fonts (`Space Mono`, `Syne`)
2. Download and self-host `qrcode.min.js`
3. Update the CSP meta tag to remove external domains

---

## Building & Auditing

The entire frontend is **vanilla JavaScript with zero build steps**:

```bash
# Verify bundle size (should be well under 150 KB)
wc -c index.html app.js sw.js
du -sh index.html app.js sw.js

# Security audit: scan for hardcoded secrets (there should be none)
grep -rn "apikey\|password\|secret\|token" --include="*.js" --include="*.html" .

# Dependency audit
cd server && npm audit
```

---

## License

MIT — use freely, deploy anywhere.