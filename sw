/* NaviOS Hub service worker — offline shell + attach notifications */
const CACHE = 'navios-v1';
const SHELL = [
  './',
  './NaviOS Hub App.dc.html',
  './NaviOS Hub.dc.html',
  './support.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(()=>{})).then(()=>self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Network-first for same-origin GETs, falling back to cache when offline.
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  e.respondWith(
    fetch(req).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(req, copy)).catch(()=>{});
      return res;
    }).catch(() => caches.match(req).then(r => r || caches.match('./NaviOS Hub App.dc.html')))
  );
});

/* The agent posts a Web Push when a device attaches to the computer.
   iOS 16.4+ delivers this to an installed (home-screen) PWA. */
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { body: e.data && e.data.text() }; }
  const title = d.title || 'iPhone connected';
  e.waitUntil(self.registration.showNotification(title, {
    body: d.body || 'Tap to run diagnostics.',
    icon: './icons/icon-192.png',
    badge: './icons/icon-192.png',
    tag: 'navios-attach',
    renotify: true,
    data: { url: d.url || './NaviOS Hub App.dc.html?autoscan=1' },
    actions: [
      { action: 'scan', title: 'Run full scan' },
      { action: 'open', title: 'Open' }
    ]
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = e.action === 'scan'
    ? './NaviOS Hub App.dc.html?autoscan=1'
    : (e.notification.data && e.notification.data.url) || './NaviOS Hub App.dc.html';
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) {
      if (c.url.includes('NaviOS Hub App') && 'focus' in c) {
        c.postMessage({ type: 'navios:attach', autoscan: e.action === 'scan' });
        return c.focus();
      }
    }
    return clients.openWindow(url);
  }));
});

// Lets the agent-connected page ask the SW to relay to other open windows.
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'navios:broadcast') {
    clients.matchAll({ type: 'window' }).then(list => list.forEach(c => c.postMessage(e.data.payload)));
  }
});
