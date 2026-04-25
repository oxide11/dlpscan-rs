// ─── siphon-shared.js ───────────────────────────────────────────
// Primitives used by every siphon console (siphon-c2 admin console,
// siphon-ir responder console). Loaded as a plain <script> tag
// AFTER react + react-dom + babel-standalone. Exposes everything on
// `window.` so both Babel-transpiled and plain-JS consumers pick it
// up without an import.
//
// Layered on purpose — keep this file limited to primitives that
// don't depend on console-specific UI. Adding surface-level
// components (Topbar, Sidenav, etc.) is a separate step once both
// consoles agree on their shape.
// ─────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  // ─── Endpoint config ────────────────────────────────────────────
  // localStorage keys keep the admin console and the responder
  // console pointed at the same pods without either needing to
  // duplicate state. The same `c2:*` prefix is reused so a user who
  // configured the admin console before the IR console existed has
  // zero migration work.

  window.SIPHON_API_URL = function () {
    try { return localStorage.getItem('c2:apiUrl') || 'http://127.0.0.1:8080'; }
    catch { return 'http://127.0.0.1:8080'; }
  };

  window.SIPHON_FS_URL = function () {
    try {
      const explicit = localStorage.getItem('c2:fsUrl');
      if (explicit) return explicit;
    } catch {}
    const api = window.SIPHON_API_URL();
    if (/\/api\/?$/.test(api)) return api.replace(/\/api\/?$/, '/fs');
    try {
      const u = new URL(api);
      if (u.port === '8080') { u.port = '8081'; return u.origin; }
    } catch {}
    return 'http://127.0.0.1:8081';
  };

  window.SIPHON_LAUNCHER_URL = function () {
    try {
      const v = localStorage.getItem('c2:launcherUrl');
      if (v) return v;
    } catch {}
    return 'http://127.0.0.1:8090';
  };

  window.SIPHON_API_KEY = function () {
    try { return localStorage.getItem('c2:apiKey') || null; }
    catch { return null; }
  };

  window.siphonAuthHeaders = function () {
    const k = window.SIPHON_API_KEY();
    return k ? { 'Authorization': 'Bearer ' + k } : {};
  };

  // Thin fetch wrapper — attaches Authorization when a key is saved.
  // Safe against any URL; pods ignore the header when SIPHON_API_KEY
  // isn't set. LocalLauncherPanel / direct-to-launcher code paths
  // deliberately stick with plain fetch (no auth on loopback).
  window.siphonFetch = function (url, options) {
    const opts = options || {};
    opts.headers = { ...(opts.headers || {}), ...window.siphonAuthHeaders() };
    return fetch(url, opts);
  };

  // ─── Pod registry ───────────────────────────────────────────────
  // Flat list of {url, label, role?, disabled?} persisted in
  // localStorage[c2:pods]. Both consoles fan out across this list.
  // Seeded on first read from SIPHON_API_URL + SIPHON_FS_URL so
  // existing users keep working.
  const POD_REGISTRY_KEY = 'c2:pods';
  window.__pod_registry_listeners = window.__pod_registry_listeners || new Set();

  function __podReadRaw() {
    try { return JSON.parse(localStorage.getItem(POD_REGISTRY_KEY) || '[]'); }
    catch { return []; }
  }
  function __podWriteRaw(list) {
    try { localStorage.setItem(POD_REGISTRY_KEY, JSON.stringify(list)); } catch {}
    window.__pod_registry_listeners.forEach(fn => { try { fn(); } catch {} });
  }
  function __podNormalise(url) {
    try {
      const u = new URL((url || '').trim());
      const path = u.pathname.replace(/\/$/, '');
      return u.origin + path;
    } catch {
      return (url || '').trim().replace(/\/$/, '');
    }
  }
  function __podSeedIfEmpty() {
    const list = __podReadRaw();
    if (list.length) return;
    const seed = [
      { url: __podNormalise(window.SIPHON_API_URL()), role: 'api', label: 'primary-api', added_at: new Date().toISOString() },
      { url: __podNormalise(window.SIPHON_FS_URL()),  role: 'fs',  label: 'primary-fs',  added_at: new Date().toISOString() },
    ].filter((p, i, arr) => p.url && arr.findIndex(q => q.url === p.url) === i);
    if (seed.length) __podWriteRaw(seed);
  }

  window.c2PodAdd = function (entry) {
    const list = __podReadRaw();
    const url = __podNormalise(entry.url);
    if (!url) return false;
    if (list.some(p => p.url === url)) return false;
    list.push({
      url,
      role: entry.role || 'auto',
      label: entry.label || '',
      disabled: !!entry.disabled,
      added_at: new Date().toISOString(),
    });
    __podWriteRaw(list);
    return true;
  };
  window.c2PodRemove = function (url) {
    const norm = __podNormalise(url);
    __podWriteRaw(__podReadRaw().filter(p => p.url !== norm));
  };
  window.c2PodUpdate = function (url, patch) {
    const norm = __podNormalise(url);
    const list = __podReadRaw().map(p => p.url === norm ? { ...p, ...patch } : p);
    __podWriteRaw(list);
  };

  // ─── React hooks ────────────────────────────────────────────────
  // Wired as window.* rather than ES exports so Babel-transpiled
  // scripts in either console can just reference them as globals.

  window.usePodRegistry = function () {
    const [, setTick] = React.useState(0);
    React.useEffect(() => {
      __podSeedIfEmpty();
      const fn = () => setTick(t => t + 1);
      window.__pod_registry_listeners.add(fn);
      const onStorage = (e) => { if (e.key === POD_REGISTRY_KEY) fn(); };
      window.addEventListener('storage', onStorage);
      return () => {
        window.__pod_registry_listeners.delete(fn);
        window.removeEventListener('storage', onStorage);
      };
    }, []);
    return __podReadRaw();
  };

  // GET /<path> against the primary siphon-api (SIPHON_API_URL).
  // Returns { loading, data, error, refetch, source }.
  window.useSiphonApi = function (path, deps) {
    const [tick, setTick] = React.useState(0);
    const [state, setState] = React.useState({ loading: true, data: null, error: null });
    React.useEffect(() => {
      let cancelled = false;
      setState(s => ({ ...s, loading: true, error: null }));
      const url = window.SIPHON_API_URL().replace(/\/$/, '') + path;
      window.siphonFetch(url, { method: 'GET' })
        .then(async r => {
          if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + (await r.text()).slice(0, 200));
          return r.json();
        })
        .then(data => { if (!cancelled) setState({ loading: false, data, error: null }); })
        .catch(e => { if (!cancelled) setState({ loading: false, data: null, error: String(e.message || e) }); });
      return () => { cancelled = true; };
    }, [...(deps || []), tick]);
    const source = state.loading ? 'loading' : state.error ? 'offline' : 'live';
    return { ...state, source, refetch: () => setTick(t => t + 1) };
  };

  // Fan-out across every enabled pod in the registry → union findings.
  // Same shape both consoles consume.
  window.useFindingsUnion = function (qs, deps) {
    const [tick, setTick] = React.useState(0);
    const [state, setState] = React.useState({
      loading: true, data: null, error: null, perPod: [],
    });
    const rawPods = window.usePodRegistry ? window.usePodRegistry() : null;
    const pods = rawPods ? rawPods.filter(p => !p.disabled) : null;
    const effectivePods = pods !== null
      ? pods
      : [
          { url: window.SIPHON_API_URL(), role: 'api', label: 'api' },
          { url: window.SIPHON_FS_URL(),  role: 'fs',  label: 'fs'  },
        ];
    const podsKey = effectivePods.map(p => p.url).join('|');

    React.useEffect(() => {
      let cancelled = false;
      setState(s => ({ ...s, loading: true, error: null }));

      const fetchFrom = (pod) => {
        const url = pod.url.replace(/\/$/, '') + '/v1/findings' + (qs || '');
        return window.siphonFetch(url, { method: 'GET' })
          .then(async r => {
            if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + (await r.text()).slice(0, 200));
            return r.json();
          })
          .then(data => ({ pod, ok: true, data, error: null }))
          .catch(e => ({ pod, ok: false, data: null, error: String(e.message || e) }));
      };

      Promise.all(effectivePods.map(fetchFrom)).then((results) => {
        if (cancelled) return;

        const findings = results
          .flatMap(r => (r.data && r.data.findings) || [])
          .sort((a, b) => (b.ts || '').localeCompare(a.ts || ''));

        const m = (qs || '').match(/[?&]limit=(\d+)/);
        const limit = m ? parseInt(m[1], 10) : findings.length;
        const trimmed = findings.slice(0, limit);

        const total    = results.reduce((a, r) => a + ((r.data && r.data.total)    || 0), 0);
        const capacity = results.reduce((a, r) => a + ((r.data && r.data.capacity) || 0), 0);

        const perPod = results.map(r => ({
          url: r.pod.url, label: r.pod.label || '', role: r.pod.role || 'auto',
          ok: r.ok, error: r.error, data: r.data,
        }));
        let source;
        if (perPod.length === 0) source = 'offline';
        else if (perPod.every(p => p.ok)) source = 'live';
        else if (perPod.some(p => p.ok)) source = 'partial';
        else source = 'offline';

        setState({
          loading: false,
          data: { total, returned: trimmed.length, capacity, findings: trimmed },
          error: source === 'offline'
            ? (perPod.length === 0 ? 'no pods in registry' : (perPod[0] && perPod[0].error) || 'no pods reachable')
            : null,
          perPod,
          source,
        });
      });

      return () => { cancelled = true; };
    }, [...(deps || []), qs, tick, podsKey]);

    const source = state.loading
      ? 'loading'
      : state.source || (state.data ? 'live' : 'offline');
    return { ...state, source, refetch: () => setTick(t => t + 1) };
  };

  // ─── LivePill ────────────────────────────────────────────────────
  // Status chip rendered in page-head actions. Written with
  // React.createElement rather than JSX so this file stays loadable
  // as a plain <script> without Babel re-parsing.
  window.LivePill = function LivePill({ source, onClick, title }) {
    const map = { live:'safe', offline:'red', loading:'warn', fixture:'ghost', partial:'warn' };
    const label = { live:'LIVE', offline:'OFFLINE', loading:'LOADING…', fixture:'FIXTURE', partial:'PARTIAL' }[source] || source;
    return React.createElement(
      'span',
      {
        className: 'chip chip--' + (map[source] || 'ghost'),
        onClick: onClick,
        title: title || '',
        style: { cursor: onClick ? 'pointer' : 'default' },
      },
      label,
    );
  };

  // ─── FixtureBadge ────────────────────────────────────────────────
  // Inline marker for surfaces (or sub-sections) that aren't wired
  // to real data. Both consoles use it: the admin one to flag
  // design-only surfaces, the responder one for fixture data
  // sections. Default `small=false` renders a chip with an explicit
  // FIXTURE label; `small` mode shrinks it for embedded use beside
  // tile titles.
  window.FixtureBadge = function FixtureBadge({ small, reason }) {
    return React.createElement(
      'span',
      {
        className: 'chip chip--warn',
        title: reason || 'No backing data in siphon-api yet — this surface is a design fixture.',
        style: {
          fontSize: small ? 9 : 10,
          letterSpacing: '0.14em',
          fontWeight: 700,
        },
      },
      'FIXTURE' + (reason ? ' · ' + reason : ''),
    );
  };

  // ─── Shared poll tick ────────────────────────────────────────────
  // The dashboards used to mount one setInterval per data hook —
  // five separate timers on the C2 home alone, each kicking off its
  // own pod fan-out. With a 5s cadence and ~4 pods that's 20 fetches
  // staggered every 5s, with overlap any time the network breathed
  // > 1s. useSharedPoll consolidates those into a single timer per
  // (intervalMs) bucket. Every consumer gets the same tick value;
  // hooks that depend on it via useEffect deps re-run together, in
  // lockstep, on a single setInterval.
  //
  // Returns the current tick (monotonically increasing). Pass it
  // into a `useEffect` deps array, or to refetch hooks that accept
  // a deps argument:
  //
  //   const tick = window.useSharedPoll(5000);
  //   const mx   = window.useSiphonApi('/v1/metrics', [tick]);
  //   const fx   = window.useSiphonApi('/v1/findings?limit=5', [tick]);
  //
  // Both fetches re-run on the same edge — no setInterval drift,
  // no fan-out duplication.
  const __sharedPollBuckets = new Map(); // intervalMs -> { tick, listeners:Set, timer }
  window.useSharedPoll = function (intervalMs) {
    const ms = intervalMs | 0;
    const [tick, setTick] = React.useState(0);
    React.useEffect(() => {
      let bucket = __sharedPollBuckets.get(ms);
      if (!bucket) {
        bucket = { tick: 0, listeners: new Set(), timer: null };
        bucket.timer = setInterval(() => {
          bucket.tick += 1;
          // Snapshot to avoid mutation-during-iteration if a
          // listener unsubscribes synchronously.
          const fns = Array.from(bucket.listeners);
          for (const fn of fns) { try { fn(bucket.tick); } catch {} }
        }, ms);
        __sharedPollBuckets.set(ms, bucket);
      }
      const fn = (t) => setTick(t);
      bucket.listeners.add(fn);
      // Sync the new subscriber to the current bucket tick so it
      // doesn't sit at 0 until the next interval fires.
      setTick(bucket.tick);
      return () => {
        bucket.listeners.delete(fn);
        if (bucket.listeners.size === 0) {
          clearInterval(bucket.timer);
          __sharedPollBuckets.delete(ms);
        }
      };
    }, [ms]);
    return tick;
  };
})();
