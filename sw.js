const CACHE_NAME = 'jifeng-app-v19';
const STATIC_ASSETS = [
  '/app.html',
  '/console.html',
  '/console.css',
  '/console.js',
  '/index.html',
  '/app.js',
  '/style.css',
  '/appeal.html',
  '/avatar.png',
  '/favicon.png',
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.json'
];
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(STATIC_ASSETS).catch(function(){});
    }).then(function(){ return self.skipWaiting() })
  );
});
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(keys.filter(function(k){ return k !== CACHE_NAME }).map(function(k){ return caches.delete(k) }));
    }).then(function(){ return self.clients.claim() })
  );
});
self.addEventListener('fetch', function(e) {
  var url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/')) return;
  if (e.request.method !== 'GET') return;
  e.respondWith(
    caches.match(e.request).then(function(cached) {
      var fetchPromise = fetch(e.request).then(function(resp) {
        if (resp && resp.status === 200) {
          var clone = resp.clone();
          caches.open(CACHE_NAME).then(function(cache){ cache.put(e.request, clone) });
        }
        return resp;
      }).catch(function(){ return cached });
      return cached || fetchPromise;
    })
  );
});
// Push notification support
self.addEventListener('push', function(e) {
  var data = {};
  try { data = e.data.json() } catch(err) { data = { title: '极风控制', body: e.data ? e.data.text() : '' } }
  e.waitUntil(
    self.registration.showNotification(data.title || '极风控制', {
      body: data.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      vibrate: [200, 100, 200],
      tag: data.tag || 'jifeng',
      data: data
    })
  );
});
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window' }).then(function(clients) {
      if (clients.length > 0) return clients[0].focus();
      return self.clients.openWindow('/app.html');
    })
  );
});
