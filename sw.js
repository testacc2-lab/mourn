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
  const isSameOrigin = url.origin === self.location.origin;
  const isCustomDomain = url.hostname === 'mourn.wtf' || url.hostname === 'www.mourn.wtf';
  if (!isSameOrigin && !isCustomDomain) return;

  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length !== 1) return;

  const slug = parts[0].toLowerCase();
  if (RESERVED.has(slug)) return;

  const profileUrl = new URL('/profile/', self.location.origin);
  profileUrl.searchParams.set('u', parts[0]);

  event.respondWith(
    fetch(profileUrl.toString(), { credentials: 'same-origin' }).catch(() => fetch(req))
  );
});
