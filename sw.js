const RESERVED = new Set([
  '',
  'dashboard',
  'login',
  'signup',
  'pricing',
  'help',
  'terms',
  'privacy',
  'guidelines',
  'profile',
  'mourn.html',
  'index.html',
  'favicon.png',
  'mourn.png',
  'drake.jpg',
  'scrape',
]);

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.mode !== 'navigate') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length !== 1) return;

  const slug = parts[0].toLowerCase();
  if (RESERVED.has(slug)) return;

  event.respondWith(fetch('/profile/'));
});
