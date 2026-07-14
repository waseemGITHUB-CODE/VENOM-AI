/* ══════════════════════════════════════════════════════════════════════
   VENOM AI · auth.js
   Shared auth utilities — token storage, authFetch, refresh, redirects.
   ══════════════════════════════════════════════════════════════════════ */
(function () {
  const API_CANDIDATES = ['http://127.0.0.1:8000', 'http://localhost:8000'];
  // Best-effort detection — first one that responds to /api/health wins
  let API_BASE = API_CANDIDATES[0];

  const LS = {
    access:    'venom_access_token',
    refresh:   'venom_refresh_token',
    user:      'venom_user',
    lastUid:   'venom_last_user_id',   // tracks which user the cached app data belongs to
  };

  // Keys that hold user-specific APP data (chat history, scan results, settings).
  // These get wiped on "Clear Data" AND when a different user logs in.
  // Auth keys (LS.access/refresh/user/lastUid) are NEVER in this list.
  const APP_DATA_KEYS = [
    'venom_chat_sessions',
    'venom_active_session_id',
    'venom_notification_email',
    'venom_mon_notifs',
    'venom_dashboard_cache',
    'venom_scan_history',
  ];

  // ── Token + user helpers ───────────────────────────────────────────────
  function getAccessToken()  { return localStorage.getItem(LS.access)  || ''; }
  function getRefreshToken() { return localStorage.getItem(LS.refresh) || ''; }
  function getUser() {
    try { return JSON.parse(localStorage.getItem(LS.user) || 'null'); }
    catch { return null; }
  }
  function setSession({ access_token, refresh_token, user }) {
    if (access_token)  localStorage.setItem(LS.access,  access_token);
    if (refresh_token) localStorage.setItem(LS.refresh, refresh_token);
    if (user) {
      localStorage.setItem(LS.user, JSON.stringify(user));
      // If a different user just logged in, wipe the previous user's app data.
      const prevUid = localStorage.getItem(LS.lastUid);
      const curUid  = String(user.id || '');
      if (prevUid && prevUid !== curUid) {
        clearAppData();
      }
      if (curUid) localStorage.setItem(LS.lastUid, curUid);
    }
  }
  function clearSession() {
    localStorage.removeItem(LS.access);
    localStorage.removeItem(LS.refresh);
    localStorage.removeItem(LS.user);
    // NOTE: we keep LS.lastUid so if the same user logs back in we don't nuke their data
  }

  // ── Clear only APP data (chat, scans, prefs). Keeps auth tokens intact. ───
  function clearAppData() {
    APP_DATA_KEYS.forEach(k => localStorage.removeItem(k));
    sessionStorage.clear();
  }

  // VENOM is single-user (self-hosted) — every request is always authenticated
  // as the one local account, no login required. These stay `true`/no-op so
  // any legacy call sites keep working without a redirect to a login page.
  function isLoggedIn() { return true; }
  function requireAuth() { return true; }
  function redirectIfLoggedIn() {}

  // ── API base detection ─────────────────────────────────────────────────
  async function detectApiBase() {
    for (const base of API_CANDIDATES) {
      try {
        const r = await fetch(base + '/api/health', { mode: 'cors' });
        if (r.ok) { API_BASE = base; return base; }
      } catch {}
    }
    return API_BASE;
  }
  function getApiBase() { return API_BASE; }

  // ── authFetch — drop-in fetch() replacement that adds Authorization if we have one ─
  async function authFetch(url, opts = {}) {
    const full = url.startsWith('http') ? url : (API_BASE + url);
    const init = { ...opts, headers: { ...(opts.headers || {}) } };

    const at = getAccessToken();
    if (at) init.headers['Authorization'] = 'Bearer ' + at;

    return fetch(full, init);
  }

  function redirectToLogin() {
    // No login page in single-user mode — just clear any stale local session.
    clearSession();
  }

  // ── Logout ─────────────────────────────────────────────────────────────
  // No login system in single-user mode — "logout" just resets locally cached
  // app data so a fresh session starts clean.
  async function logout(redirect = true) {
    clearSession();
    clearAppData();
    if (redirect) location.href = '/';
  }

  // ── Refresh user profile from server (call after settings change) ─────
  async function refreshMe() {
    try {
      const r = await authFetch('/api/auth/me');
      if (r.ok) {
        const u = await r.json();
        localStorage.setItem(LS.user, JSON.stringify(u));
        return u;
      }
    } catch {}
    return null;
  }

  // ── Official VENOM AI brand logo — V monster mouth SVG ─────────────────
  // Identical to the one in nav of index.html, just resized for auth pages.
  const BRAND_LOGO_SVG = `
    <svg width="56" height="56" viewBox="0 0 100 100" fill="none"
         xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
      <defs>
        <filter id="vLogoGlow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="3" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id="vLogoAura" x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur stdDeviation="7"/>
        </filter>
        <linearGradient id="vLogoExtL" x1="5" y1="5" x2="-9" y2="-22" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stop-color="#39FF14" stop-opacity="0.9"/>
          <stop offset="100%" stop-color="#39FF14" stop-opacity="0"/>
        </linearGradient>
        <linearGradient id="vLogoExtR" x1="95" y1="5" x2="109" y2="-22" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stop-color="#39FF14" stop-opacity="0.9"/>
          <stop offset="100%" stop-color="#39FF14" stop-opacity="0"/>
        </linearGradient>
        <linearGradient id="vLogoExtB" x1="50" y1="92" x2="50" y2="114" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stop-color="#39FF14" stop-opacity="0.7"/>
          <stop offset="100%" stop-color="#39FF14" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <path fill-rule="evenodd"
            fill="rgba(57,255,20,0.22)" filter="url(#vLogoAura)"
            d="M 5 5 L 95 5 L 50 92 Z
               M 28 5 L 72 5 L 50 76 Z
               M 38 36 L 42 10 L 46 36 L 50 8 L 54 36 L 58 10 L 62 36 L 50 76 Z"/>
      <path fill-rule="evenodd"
            fill="#f0fff2" filter="url(#vLogoGlow)"
            d="M 5 5 L 95 5 L 50 92 Z
               M 28 5 L 72 5 L 50 76 Z
               M 38 36 L 42 10 L 46 36 L 50 8 L 54 36 L 58 10 L 62 36 L 50 76 Z"/>
      <path fill="none" stroke="rgba(57,255,20,0.75)" stroke-width="1.2"
            d="M 5 5 L 95 5 L 50 92 Z"/>
      <line x1="5" y1="5" x2="-9" y2="-22"
            stroke="url(#vLogoExtL)" stroke-width="2" stroke-linecap="round"/>
      <line x1="95" y1="5" x2="109" y2="-22"
            stroke="url(#vLogoExtR)" stroke-width="2" stroke-linecap="round"/>
      <line x1="50" y1="92" x2="50" y2="114"
            stroke="url(#vLogoExtB)" stroke-width="1.8" stroke-linecap="round"/>
    </svg>`;

  /** Insert the official VENOM AI logo into every element with class `.venom-logo` */
  function injectLogo() {
    document.querySelectorAll('.venom-logo').forEach(el => {
      el.innerHTML = BRAND_LOGO_SVG;
    });
  }
  // Auto-inject as soon as DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectLogo);
  } else {
    injectLogo();
  }

  // ── Expose ─────────────────────────────────────────────────────────────
  window.VenomAuth = {
    detectApiBase, getApiBase,
    getAccessToken, getRefreshToken, getUser,
    setSession, clearSession, clearAppData,
    isLoggedIn, requireAuth, redirectIfLoggedIn, redirectToLogin,
    authFetch, refreshMe,
    logout,
    BRAND_LOGO_SVG, injectLogo,
    APP_DATA_KEYS,
  };

  // Fire detection immediately
  detectApiBase();
})();
