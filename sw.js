/**
 * QSend Service Worker
 * Caches the app shell for offline use.
 * File transfers always require an active network connection
 * (WebRTC signaling + P2P data channel).
 */

'use strict';

const CACHE_NAME = 'qsend-v1';

// App shell — everything needed to render the UI offline
const SHELL_ASSETS = [
  './',
  './index.html',
  './app.js',
  './manifest.json',
];

// ── Install: cache app shell ──────────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL_ASSETS))
  );
  self.skipWaiting();
});

// ── Activate: clear old caches ────────────────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// ── Fetch: cache-first for shell, network-first for API ───────
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never intercept WebSocket or cross-origin requests
  if (
    event.request.url.startsWith('ws://') ||
    event.request.url.startsWith('wss://') ||
    url.origin !== self.location.origin
  ) {
    return;
  }

  // For navigation requests: serve cached shell, show offline UI if needed
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() =>
        caches.match('./index.html')
      )
    );
    return;
  }

  // Cache-first for known shell assets
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        // Cache successful responses for shell assets
        if (response.ok && SHELL_ASSETS.some(a => event.request.url.includes(a))) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(c => c.put(event.request, clone));
        }
        return response;
      });
    })
  );
});

// ── Share target (PWA share sheet integration) ────────────────
self.addEventListener('fetch', (event) => {
  if (
    event.request.method === 'POST' &&
    event.request.url.includes('share-target')
  ) {
    event.respondWith(
      (async () => {
        const formData = await event.request.formData();
        const files    = formData.getAll('files');
        const title    = formData.get('title') || '';

        // Forward to main page with context
        const url = new URL('./?share-target', self.location.origin);
        url.searchParams.set('title', title);

        // Store files in a temporary cache key for the page to pick up
        if (files.length > 0) {
          const cache = await caches.open('qsend-share-tmp');
          for (let i = 0; i < files.length; i++) {
            await cache.put(`share-file-${i}`, new Response(files[i]));
          }
          url.searchParams.set('share-count', files.length);
        }

        return Response.redirect(url.toString(), 303);
      })()
    );
  }
});