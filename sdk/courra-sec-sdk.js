/**
 * Courra-Sec Security SDK  v2.0.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Drop-in browser security telemetry — works like Sentry / Datadog RUM.
 *
 * ONE-LINE INSTALL:
 *   <script src="https://your-siem.com/courra-sec-sdk.js"
 *           data-api-key="YOUR_KEY"></script>
 *
 * Optional attributes:
 *   data-endpoint="https://your-siem.com"   override SIEM origin
 *   data-app="MyApp"                         application name tag
 *   data-debug="true"                        verbose console logs
 *   data-sample-rate="0.5"                   send 50 % of events
 *
 * Manual API (all optional — SDK works fully automatically):
 *   Courra-SecSDK.setUser({ id, username, role })
 *   Courra-SecSDK.captureEvent({ attackType, severity, payload, endpoint })
 *   Courra-SecSDK.captureError(error, context)
 *   Courra-SecSDK.flush()
 *
 * AUTO-COLLECTED EVENTS:
 *   JavaScript errors & unhandled promise rejections
 *   console.error calls
 *   Failed XHR / fetch requests (4xx / 5xx)
 *   Page navigations (hash, popstate, pushState / replaceState — SPA-aware)
 *   Login form submissions
 *   Suspicious input patterns (XSS, SQLi, path traversal, command injection)
 *   DOM script injection (MutationObserver)
 *   Clickjacking detection (iframe check)
 *   Performance anomalies (long tasks ≥ 200 ms, slow resources ≥ 3 s)
 *
 * TRANSPORT:
 *   Primary  — WebSocket  ws[s]://siem/ws/ingest  (persistent, ~0 overhead)
 *   Fallback — HTTP POST  http[s]://siem/ingest   (keepalive fetch → sendBeacon)
 *   Batched every 2 seconds, flushed on page unload.
 */
(function (root) {
  'use strict';

  var VERSION = '2.0.0';

  /* ── read config from the <script> tag ─────────────────────────────────── */
  var _el = document.currentScript || (function () {
    var s = document.getElementsByTagName('script');
    return s[s.length - 1];
  }());

  var _apiKey  = (_el && _el.getAttribute('data-api-key'))    || '';
  var _appName = (_el && _el.getAttribute('data-app'))        || 'unknown';
  var _dbg     = (_el && _el.getAttribute('data-debug'))      === 'true';
  var _rate    = parseFloat((_el && _el.getAttribute('data-sample-rate')) || '1');

  /* Derive SIEM origin: explicit attr → script src → localhost fallback */
  var _origin = (function () {
    var attr = _el && _el.getAttribute('data-endpoint');
    if (attr) return attr.replace(/\/$/, '');
    if (_el && _el.src) return _el.src.replace(/\/courra-sec-sdk\.js.*$/, '');
    return location.protocol + '//' + location.hostname + ':5001';
  }());

  var _httpURL = _origin + '/ingest';
  var _wsURL   = _origin.replace(/^http/, 'ws') + '/ws/ingest';

  /* ── state ──────────────────────────────────────────────────────────────── */
  var _queue  = [];
  var _dedup  = {};
  var _user   = null;
  var _sid    = _makeSession();
  var _ws     = null;
  var _wsOk   = false;
  var _wsDly  = 2000;   // reconnect backoff; doubles each attempt, caps at 60 s

  /* ── utilities ──────────────────────────────────────────────────────────── */
  function _log() {
    if (!_dbg) return;
    var a = Array.prototype.slice.call(arguments);
    a.unshift('[Courra-SecSDK]');
    console.log.apply(console, a);
  }

  function _now()     { return new Date().toISOString(); }
  function _trunc(s, n) {
    s = String(s == null ? '' : s);
    return s.length > n ? s.slice(0, n) + '\u2026' : s;
  }

  function _rand(bytes) {
    var a = new Uint8Array(bytes);
    (root.crypto || root.msCrypto).getRandomValues(a);
    return Array.prototype.map.call(a, function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  function _makeSession() {
    try {
      var s = sessionStorage.getItem('__qsid');
      if (s) return s;
      s = 'qs_' + _rand(16) + '_' + Date.now().toString(36);
      sessionStorage.setItem('__qsid', s);
      return s;
    } catch (e) { return 'qs_' + _rand(8); }
  }

  function _isDup(type, payload) {
    var k = type + '|' + _trunc(payload, 80), now = Date.now();
    if (_dedup[k] && now - _dedup[k] < 30000) return true;
    _dedup[k] = now;
    return false;
  }

  /* ── security pattern library ───────────────────────────────────────────── */
  var PATS = {
    'XSS Attempt': {
      sev: 'high',
      re: [/<script[\s>]/i, /javascript\s*:/i, /on\w+\s*=/i,
           /<iframe[\s>]/i, /data:\s*text\/html/i, /vbscript\s*:/i, /expression\s*\(/i],
    },
    'SQL Injection Attempt': {
      sev: 'critical',
      re: [/'\s*(or|and)\s*'?\d/i, /union\s+all?\s+select/i,
           /select\s+\S+\s+from\s/i, /1\s*=\s*1/, /--\s*(\r?\n|$)/,
           /xp_cmdshell/i, /exec\s*\(\s*xp_/i],
    },
    'Path Traversal Attempt': {
      sev: 'medium',
      re: [/\.\.[\/\\]/, /%2e%2e[%2f%5c]/i, /\.\.%2f/i, /%252e%252e/i],
    },
    'Command Injection Attempt': {
      sev: 'critical',
      re: [/[;&|`]\s*(ls|cat|rm|del|wget|curl|nc|bash|sh|cmd|python|perl)\b/i,
           /\$\([^)]+\)/, /`[^`]+`/],
    },
  };

  function _scan(str) {
    if (!str) return null;
    var s = _trunc(str, 2000), d = s;
    try { d = decodeURIComponent(s); } catch (e) {}
    for (var label in PATS) {
      var re = PATS[label].re;
      for (var i = 0; i < re.length; i++) {
        if (re[i].test(d)) return label;
      }
    }
    return null;
  }

  /* ── event envelope ─────────────────────────────────────────────────────── */
  function _evt(f) {
    return {
      timestamp:   _now(),
      appName:     _appName,
      sdkVersion:  VERSION,
      sessionId:   _sid,
      userId:      _user ? (_user.id || _user.username || null) : null,
      userRole:    _user ? (_user.role || null) : null,
      pageUrl:     location.href,
      userAgent:   navigator.userAgent,
      screenWidth:  root.screen ? root.screen.width  : null,
      screenHeight: root.screen ? root.screen.height : null,
      language:    navigator.language || null,
      referrer:    document.referrer || null,
      ipAddress:   'client',
      endpoint:    f.endpoint || (location.pathname + location.search),
      attackType:  f.attackType || 'unknown',
      severity:    f.severity  || 'info',
      payload:     _trunc(f.payload || '', 1000),
      statusCode:  f.statusCode || 0,
      tags:        f.tags || [],
    };
  }

  /* ── queue + flush ──────────────────────────────────────────────────────── */
  function _push(f) {
    if (Math.random() > _rate) return;
    if (_isDup(f.attackType || '', f.payload || '')) return;
    if (_queue.length >= 100) _queue.shift();
    _queue.push(_evt(f));
    _log('queued', f.attackType, '— queue:', _queue.length);
    if (_queue.length >= 20) _flush();
  }

  function _send(body) {
    /* If SDK not configured, discard silently */
    if (!_httpURL || !_apiKey) return;
    /* WebSocket — persistent, zero-overhead */
    if (_ws && _wsOk && _ws.readyState === 1 /* OPEN */) {
      try { _ws.send(body); return; } catch (e) { _wsOk = false; }
    }
    /* HTTP fallback */
    var h = {
      'Content-Type':               'application/json',
      'X-API-Key':                  _apiKey,
      'ngrok-skip-browser-warning': 'true',
    };
    try {
      fetch(_httpURL, { method: 'POST', headers: h, body: body, keepalive: true })
        .catch(function (e) { _log('HTTP send failed:', e.message); });
    } catch (e) {
      try {
        if (navigator.sendBeacon) navigator.sendBeacon(_httpURL, new Blob([body], {type:'application/json'}));
      } catch (e2) { /* silent */ }
    }
  }

  function _flush() {
    if (!_queue.length) return;
    var batch = _queue.splice(0);
    _log('flush', batch.length, 'event(s)');
    batch.forEach(function (e) { _send(JSON.stringify(e)); });
  }

  /* ── WebSocket transport ────────────────────────────────────────────────── */
  function _wsConnect() {
    if (!root.WebSocket) return;
    try {
      var url = _wsURL + (_apiKey ? '?key=' + encodeURIComponent(_apiKey) : '');
      _ws = new WebSocket(url);
      _ws.onopen  = function () {
        _wsOk = true; _wsDly = 2000;
        _log('WS connected →', _wsURL);
      };
      _ws.onclose = function () {
        _wsOk = false;
        _log('WS closed, reconnecting in', _wsDly, 'ms');
        setTimeout(_wsConnect, _wsDly);
        _wsDly = Math.min(_wsDly * 2, 60000);
      };
      _ws.onerror = function () { _wsOk = false; };
    } catch (e) { _log('WS init failed:', e.message); }
  }

  /* ── collectors ─────────────────────────────────────────────────────────── */

  function _collectErrors() {
    var prev = root.onerror;
    root.onerror = function (msg, src, line, col) {
      _push({ attackType: 'JavaScript Error', severity: 'low',
        payload: JSON.stringify({ message: _trunc(String(msg), 300), source: src, line: line, col: col }),
        endpoint: src || location.pathname, tags: ['js-error'] });
      if (typeof prev === 'function') prev.apply(root, arguments);
    };
    root.addEventListener('unhandledrejection', function (e) {
      _push({ attackType: 'Unhandled Promise Rejection', severity: 'low',
        payload: JSON.stringify({ reason: _trunc(String(e.reason && (e.reason.message || e.reason)), 300) }),
        endpoint: location.pathname, tags: ['js-error', 'promise'] });
    });
  }

  function _collectConsole() {
    if (!root.console || !console.error) return;
    var orig = console.error;
    console.error = function () {
      var msg = Array.prototype.slice.call(arguments).join(' ');
      _push({ attackType: 'Console Error', severity: 'low',
        payload: _trunc(msg, 300), endpoint: location.pathname, tags: ['console'] });
      orig.apply(console, arguments);
    };
  }

  function _collectFetch() {
    if (!root.fetch) return;
    var native = root.fetch;
    root.fetch = function (input, init) {
      var url    = typeof input === 'string' ? input : (input && input.url) || '';
      var method = (init && init.method) || 'GET';
      var body   = init && init.body ? _trunc(String(init.body), 500) : '';

      if (url.indexOf('/ingest') !== -1 || url.indexOf('/ws/ingest') !== -1) {
        return native.apply(root, arguments);      // never spy on our own traffic
      }

      var t = _scan(url);
      if (t) _push({ attackType: t, severity: PATS[t].sev,
        payload: _trunc(url, 500), endpoint: url.split('?')[0], tags: ['fetch', 'url'] });

      if (body) {
        var tb = _scan(body);
        if (tb) _push({ attackType: tb, severity: PATS[tb].sev,
          payload: body, endpoint: url.split('?')[0], tags: ['fetch', 'body'] });
      }

      return native.apply(root, arguments).then(function (res) {
        if (res.status >= 400)
          _push({ attackType: res.status >= 500 ? 'Server Error' : 'Client HTTP Error',
            severity: res.status >= 500 ? 'medium' : 'low',
            payload: JSON.stringify({ method: method, status: res.status, url: url }),
            endpoint: url.split('?')[0], statusCode: res.status, tags: ['fetch', 'http-error'] });
        return res;
      });
    };
  }

  function _collectXHR() {
    if (!root.XMLHttpRequest) return;
    var N = root.XMLHttpRequest;
    function P() {
      var x = new N(), _u = '', _m = '';
      var oo = x.open;
      x.open = function (m, u) {
        _u = String(u || ''); _m = String(m || '');
        var t = _scan(_u);
        if (t) _push({ attackType: t, severity: PATS[t].sev,
          payload: _trunc(_u, 500), endpoint: _u.split('?')[0], tags: ['xhr', 'url'] });
        return oo.apply(x, arguments);
      };
      var os = x.send;
      x.send = function (body) {
        if (body) {
          var b = typeof body === 'string' ? body : JSON.stringify(body), t = _scan(b);
          if (t) _push({ attackType: t, severity: PATS[t].sev,
            payload: _trunc(b, 500), endpoint: _u.split('?')[0], tags: ['xhr', 'body'] });
        }
        x.addEventListener('loadend', function () {
          if (x.status >= 400)
            _push({ attackType: x.status >= 500 ? 'Server Error' : 'Client HTTP Error',
              severity: x.status >= 500 ? 'medium' : 'low',
              payload: JSON.stringify({ method: _m, status: x.status, url: _u }),
              endpoint: _u.split('?')[0], statusCode: x.status, tags: ['xhr', 'http-error'] });
        });
        return os.apply(x, arguments);
      };
      return x;
    }
    P.prototype = N.prototype;
    root.XMLHttpRequest = P;
  }

  function _collectNavigation() {
    function _nav(from, to, trigger) {
      _push({ attackType: 'Page Navigation', severity: 'info',
        payload: JSON.stringify({ from: _trunc(from, 200), to: _trunc(to, 200), trigger: trigger }),
        endpoint: to.replace(location.origin, '').split('?')[0] || '/', tags: ['navigation'] });
    }
    root.addEventListener('hashchange', function (e) { _nav(e.oldURL, e.newURL, 'hashchange'); });
    root.addEventListener('popstate',   function ()  { _nav(document.referrer || '', location.href, 'popstate'); });
    ['pushState', 'replaceState'].forEach(function (fn) {
      var orig = history[fn];
      history[fn] = function (state, title, url) {
        var from = location.href;
        orig.apply(history, arguments);
        if (url) _nav(from, location.href, fn);
      };
    });
  }

  function _collectForms() {
    document.addEventListener('submit', function (e) {
      var form = e.target || e.srcElement;
      if (!form) return;
      var inputs = form.querySelectorAll('input, textarea, select');
      var isLogin = !!form.querySelector('input[type="password"]');
      for (var i = 0; i < inputs.length; i++) {
        var el = inputs[i], val = el.value || '', name = el.name || el.id || ('f' + i);
        var t = _scan(val);
        if (t) _push({ attackType: t, severity: PATS[t].sev,
          payload: JSON.stringify({ field: name, value: _trunc(val, 300) }),
          endpoint: location.pathname, tags: ['form', 'input-scan'] });
      }
      if (isLogin)
        _push({ attackType: 'Login Attempt', severity: 'info',
          payload: JSON.stringify({ action: form.action || location.pathname }),
          endpoint: location.pathname, tags: ['auth', 'login'] });
    }, true);
  }

  function _collectDOM() {
    if (!root.MutationObserver) return;
    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        m.addedNodes.forEach(function (node) {
          if (node.nodeName !== 'SCRIPT') return;
          var src = node.src || '';
          if (src.indexOf('courra-sec-sdk') !== -1) return;   // ignore self
          var t = src ? _scan(src) : _scan(node.textContent || '');
          if (t) _push({ attackType: 'Script Injection Detected', severity: 'critical',
            payload: _trunc(src || node.textContent || '', 300),
            endpoint: location.pathname, tags: ['dom', 'script-injection'] });
        });
      });
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

  function _collectPerformance() {
    if (!root.PerformanceObserver) return;
    var supported = PerformanceObserver.supportedEntryTypes || [];

    if (supported.indexOf('longtask') !== -1) {
      try {
        new PerformanceObserver(function (list) {
          list.getEntries().forEach(function (e) {
            if (e.duration >= 200)
              _push({ attackType: 'Long Task Detected', severity: 'low',
                payload: JSON.stringify({ duration_ms: Math.round(e.duration), name: e.name }),
                endpoint: location.pathname, tags: ['performance', 'long-task'] });
          });
        }).observe({ entryTypes: ['longtask'] });
      } catch (e) {}
    }

    if (supported.indexOf('resource') !== -1) {
      try {
        new PerformanceObserver(function (list) {
          list.getEntries().forEach(function (e) {
            if (e.name.indexOf('/ingest') !== -1) return;
            var dur = e.responseEnd - e.startTime;
            if (dur >= 3000)
              _push({ attackType: 'Slow Resource Detected', severity: 'low',
                payload: JSON.stringify({ url: _trunc(e.name, 200), duration_ms: Math.round(dur), type: e.initiatorType }),
                endpoint: e.name.split('?')[0], tags: ['performance', 'slow-resource'] });
          });
        }).observe({ entryTypes: ['resource'] });
      } catch (e) {}
    }
  }

  function _collectClickjacking() {
    try {
      if (root.self === root.top) return;
      _push({ attackType: 'Clickjacking Attempt', severity: 'high',
        payload: JSON.stringify({ referrer: document.referrer || 'unknown' }),
        endpoint: location.pathname, tags: ['clickjacking'] });
    } catch (e) {
      _push({ attackType: 'Clickjacking Attempt', severity: 'critical',
        payload: JSON.stringify({ note: 'cross-origin iframe' }),
        endpoint: location.pathname, tags: ['clickjacking', 'cross-origin'] });
    }
  }

  /* ── public API ─────────────────────────────────────────────────────────── */
  var SDK = {
    version: VERSION,

    /**
     * Initialise the SDK.
     * Supports both forms:
     *   Courra-SecSDK.init({ url: '...', apiKey: 'qrr_live_...' })   ← SaaS form
     *   Courra-SecSDK.init({ endpoint: '...', apiKey: '...' })        ← legacy form
     * @param {{ url?, endpoint?, apiKey?, appName?, debug?, sampleRate?, flushInterval?, maxQueueSize? }} cfg
     */
    init: function (cfg) {
      cfg = cfg || {};
      if (cfg.apiKey)     _apiKey  = cfg.apiKey;
      if (cfg.appName)    _appName = cfg.appName;
      if (cfg.debug  != null)      _dbg  = !!cfg.debug;
      if (cfg.sampleRate != null)  _rate = +cfg.sampleRate;

      /* Support both url (new) and endpoint (legacy) */
      var baseUrl = cfg.url || cfg.endpoint || null;
      if (baseUrl) {
        var o = baseUrl.replace(/\/$/, '');
        _origin  = o;
        _httpURL = o + '/ingest';
        _wsURL   = o.replace(/^http/, 'ws') + '/ws/ingest';
      }

      /* Warn and disable if no url configured */
      if (!_httpURL || !_apiKey) {
        if (typeof console !== 'undefined' && console.warn) {
          console.warn('[Courra-SecSDK] Not initialised — provide url and apiKey to Courra-SecSDK.init()');
        }
        return this;
      }

      _wsConnect();

      _collectErrors();
      _collectConsole();
      _collectFetch();
      _collectXHR();
      _collectNavigation();
      _collectForms();
      _collectDOM();
      _collectPerformance();
      _collectClickjacking();

      setInterval(_flush, 2000);
      root.addEventListener('beforeunload', _flush);
      root.addEventListener('pagehide',     _flush);

      var urlT = _scan(location.href);
      if (urlT) _push({ attackType: urlT, severity: PATS[urlT].sev,
        payload: _trunc(location.href, 500), endpoint: location.pathname, tags: ['url-scan'] });

      _log('ready — reporting to', _httpURL, '(WS:', _wsURL + ')');
      return this;
    },

    /** Tag all subsequent events with the logged-in user. */
    setUser: function (user) { _user = user || null; return this; },

    /** Manually capture a security event. */
    captureEvent: function (evt) {
      if (evt && typeof evt === 'object') _push(evt);
      return this;
    },

    /** Manually capture a JavaScript error. */
    captureError: function (err, ctx) {
      _push({ attackType: 'Application Error', severity: 'medium',
        payload: JSON.stringify({
          message: err ? _trunc(err.message || String(err), 300) : 'unknown',
          stack:   err && err.stack ? _trunc(err.stack, 500) : null,
          context: ctx || null,
        }),
        endpoint: location.pathname, tags: ['manual', 'error'] });
      return this;
    },

    /** Force-flush the event queue now. */
    flush: _flush,
  };

  /* ── auto-init from data attributes when DOM is ready ───────────────────── */
  function _autoInit() { if (_apiKey) SDK.init(); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _autoInit);
  } else {
    _autoInit();
  }

  root['Courra-SecSDK'] = SDK;

}(typeof globalThis !== 'undefined' ? globalThis
  : typeof window   !== 'undefined' ? window : this));
