// Minimal service worker — required by Chrome/Android to treat this page as an
// installable PWA (not just a browser shortcut). No offline caching is
// implemented; this simply satisfies the installability criterion by
// registering a controlling fetch handler that passes requests straight
// through to the network.
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
