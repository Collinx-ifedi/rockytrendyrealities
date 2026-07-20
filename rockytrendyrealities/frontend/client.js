/* ================================================================
   RTR STOREFRONT — client.js
   Rocky Trendy Realities · Vanilla JS Client Runtime (ES2022+)
   Single deployable file · no bundler · no framework
   Pages: index.html · products.html · product.html ·
          checkout.html · orders.html · authentication.html ·
          faq.html · contact.html
   Auto page detection via document.body.dataset.page
   ================================================================
   TABLE OF CONTENTS
   1.  Configuration
   2.  Constants
   3.  Structured Logging / Debug
   4.  DOM Helpers
   5.  Utility Functions
   6.  Security — XSS Prevention
   7.  Formatters
   8.  Validators
   9.  Event Bus
   10. Storage Manager
   11. State Manager
   12. API Client
   13. Authentication Manager (storefront customer auth)
   14. Notification Manager (toasts)
   15. Loading Overlay
   16. Modal Manager
   17. Drawer Manager (cart drawer + mobile nav)
   18. Dropdown Manager
   19. Tooltip Manager
   20. Site Header / Responsive Nav Module
   21. Tabs + Accordion (generic UI controllers)
   22. Cart Module (client-side cart, persisted in localStorage)
   23. Products Module (homepage teaser + full catalog)
   24. Product Detail Module (PDP)
   25. Auth Module (login / register / OTP verify)
   26. Checkout Module (Paystack + WhatsApp)
   27. Orders Module (customer order history)
   28. FAQ Module
   29. Contact Module
   30. Error Handling Module (global)
   31. Mobile Viewport Fix (responsive --vh custom property)
   32. Integrations Module (dynamic config, LiveChat, socials)
   33. Bootstrap + Initialization
   ================================================================ */
(() => {
  'use strict';

  /* ==============================================================
     1. CONFIGURATION
     ============================================================== */
  // NOTE: intentionally NOT Object.freeze()'d — IntegrationsModule.fetchConfig()
  // mutates WHATSAPP_NUMBER / LIVECHAT_LICENSE / SOCIAL_FACEBOOK / SOCIAL_INSTAGRAM
  // at runtime once /api/config/public resolves, so these stay live bindings
  // read by any module that references CONFIG.* after bootstrap.
  // Decoupled deployment: the storefront (static files) and the FastAPI
  // backend no longer share an origin, so API_BASE must be an absolute
  // URL rather than ''. Falls back to a local dev backend automatically
  // when running on localhost; update PRODUCTION_API_BASE to your real
  // API domain before deploying. main.py already has CORS enabled for
  // this (see "Permissive CORS for decoupled external storefront APIs").
  const PRODUCTION_API_BASE = 'https://rtr-rfqb.onrender.com';
  const LOCAL_API_BASE = 'http://localhost:8000';
  const isLocalDev = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);

  const CONFIG = {
    API_BASE: isLocalDev ? LOCAL_API_BASE : PRODUCTION_API_BASE, // absolute URL of the FastAPI backend
    REQUEST_TIMEOUT: 20000,
    MAX_RETRIES: 2,
    RETRY_DELAY: 600,
    TOKEN_KEY: 'rtr_token',
    USER_KEY: 'rtr_user',
    CART_KEY: 'rtr_cart',
    LOGIN_URL: '/authentication.html',
    HOME_URL: '/index.html',
    CURRENCY: 'NGN',
    DEBUG: /[?&]debug=1/.test(location.search),
    // WhatsApp business number RTR orders/enquiries are routed to.
    // Default below is a placeholder — overwritten at runtime from
    // /api/config/public; only used as a fallback if that request fails.
    WHATSAPP_NUMBER: '2340000000000',
    // Third-party integration keys — all default to '' and are populated
    // at runtime by IntegrationsModule.fetchConfig(). See main.py's
    // GET /api/config/public for the source of truth.
    LIVECHAT_LICENSE: '',
    SOCIAL_FACEBOOK: 'https://www.facebook.com/profile.php?id=61591459257810',
    SOCIAL_INSTAGRAM: 'https://www.instagram.com/rockytrendyfurnitures?igsh=dGwzMzY4aHBqYmpy',
  };

  /* ==============================================================
     2. CONSTANTS
     ============================================================== */
  const ORDER_STATUS_LABEL = Object.freeze({
    pending: 'Pending', paid: 'Paid', processing: 'Processing', shipped: 'Shipped',
    delivered: 'Delivered', cancelled: 'Cancelled', refunded: 'Refunded', failed: 'Failed',
  });


  const HOMEPAGE_PRODUCT_LIMIT = 3;

  /* ==============================================================
     3. STRUCTURED LOGGING / DEBUG
     ============================================================== */
  const Log = {
    info: (...a) => CONFIG.DEBUG && console.log('%c[RTR]', 'color:#C4956A', ...a),
    warn: (...a) => console.warn('[RTR]', ...a),
    error: (...a) => console.error('[RTR]', ...a),
  };

  /* ==============================================================
     4. DOM HELPERS
     ============================================================== */
  const $  = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const on = (el, evt, handler, opts) => el && el.addEventListener(evt, handler, opts);

  const el = (tag, props = {}, children = []) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') node.className = v;
      else if (k === 'dataset') Object.assign(node.dataset, v);
      else if (k === 'html') node.innerHTML = v;             // caller must pre-escape
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined) node.setAttribute(k, v);
    }
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c == null) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  };

  const clear = (node) => { while (node && node.firstChild) node.removeChild(node.firstChild); };
  const refreshIcons = () => {
    try {
      if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
    } catch (err) {
      Log.warn('refreshIcons: icon library unavailable or failed to run', err);
    }
  };
  const qsGet = (name) => new URLSearchParams(location.search).get(name);

  /* ==============================================================
     5. UTILITY FUNCTIONS
     ============================================================== */
  const debounce = (fn, wait = 250) => {
    let t; const d = (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), wait); };
    d.cancel = () => clearTimeout(t); return d;
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /* ==============================================================
     6. SECURITY — XSS PREVENTION / SANITIZATION / ESCAPING
     ============================================================== */
  const escapeHTML = (str) => String(str ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
  const sanitizeInput = (str, max = 2000) => String(str ?? '').replace(/[\u0000-\u001F\u007F]/g, '').slice(0, max).trim();

  /* ==============================================================
     7. FORMATTERS
     ============================================================== */
  const Fmt = {
    money: (n) => `\u20A6${Number(n || 0).toLocaleString('en-NG', { maximumFractionDigits: 0 })}`,
    number: (n) => Number(n || 0).toLocaleString('en-NG'),
    date: (d) => { const x = new Date(d); return isNaN(x) ? '—' : x.toLocaleDateString('en-NG', { year: 'numeric', month: 'short', day: 'numeric' }); },
    dateTime: (d) => { const x = new Date(d); return isNaN(x) ? '—' : x.toLocaleString('en-NG', { dateStyle: 'medium', timeStyle: 'short' }); },
    orderStatus: (s) => ORDER_STATUS_LABEL[s] || Fmt.titleCase(s),
    titleCase: (s = '') => String(s).replace(/[_-]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
  };

  /* ==============================================================
     8. VALIDATORS
     ============================================================== */
  const Validate = {
    required: (v) => String(v ?? '').trim().length > 0,
    email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || '').trim()),
    minLen: (v, n) => String(v ?? '').trim().length >= n,
    phone: (v) => /^[+\d][\d\s-]{6,}$/.test(String(v || '').trim()),
  };

  /* ==============================================================
     9. EVENT BUS
     ============================================================== */
  const EventBus = (() => {
    const map = new Map();
    return {
      on(evt, cb) { (map.get(evt) || map.set(evt, new Set()).get(evt)).add(cb); return () => EventBus.off(evt, cb); },
      off(evt, cb) { map.get(evt)?.delete(cb); },
      emit(evt, payload) { map.get(evt)?.forEach((cb) => { try { cb(payload); } catch (e) { Log.error('bus', evt, e); } }); },
    };
  })();

  /* ==============================================================
     10. STORAGE MANAGER
     ============================================================== */
  const Storage = {
    get(key, fallback = null) { try { const v = localStorage.getItem(key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; } },
    set(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) { Log.error('storage.set failed', e); } },
    remove(key) { try { localStorage.removeItem(key); } catch {} },
  };

  /* ==============================================================
     11. STATE MANAGER (lightweight reactive store)
     ============================================================== */
  const Store = (() => {
    const state = {
      auth: { token: null, user: null },
      cart: [],
      products: [],
      ui: { mobileNavOpen: false, cartOpen: false },
    };
    const subs = new Map();
    const notify = (key) => subs.get(key)?.forEach((cb) => { try { cb(state[key]); } catch (e) { Log.error(e); } });
    return {
      get: (key) => state[key],
      set(key, value) { state[key] = value; notify(key); EventBus.emit(`state:${key}`, value); },
      patch(key, partial) { state[key] = { ...state[key], ...partial }; notify(key); },
      subscribe(key, cb) { (subs.get(key) || subs.set(key, new Set()).get(key)).add(cb); return () => subs.get(key)?.delete(cb); },
    };
  })();

  /* ==============================================================
     12. API CLIENT
     ============================================================== */
  class APIError extends Error {
    constructor(message, status, data) { super(message); this.name = 'APIError'; this.status = status; this.data = data; }
  }

  const APIClient = (() => {
    const authHeaders = () => {
      const token = Auth.getToken();
      return token ? { Authorization: `Bearer ${token}` } : {};
    };

    async function request(method, url, { json, headers = {}, timeout = CONFIG.REQUEST_TIMEOUT, retries = CONFIG.MAX_RETRIES } = {}) {
      const full = CONFIG.API_BASE + url;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const opts = { method, headers: { ...authHeaders(), ...headers }, signal: controller.signal };
      if (json !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(json); }

      let attempt = 0, lastErr;
      while (attempt <= retries) {
        try {
          Log.info(`${method} ${url}`, attempt ? `(retry ${attempt})` : '');
          const res = await fetch(full, opts);
          clearTimeout(timer);

          if (res.status === 401 || res.status === 403) {
            Auth.handleUnauthorized(res.status);
            throw new APIError(res.status === 403 ? 'Forbidden' : 'Unauthorized', res.status);
          }
          const ct = res.headers.get('content-type') || '';
          let payload;
          if (ct.includes('application/json')) {
            try { payload = await res.json(); } catch { payload = null; }
          } else {
            payload = await res.text();
          }

          if (!res.ok) {
            const detail = (payload && payload.detail) || (typeof payload === 'string' ? payload : `Request failed (${res.status})`);
            throw new APIError(Array.isArray(detail) ? detail.map((d) => d.msg).join(', ') : detail, res.status, payload);
          }
          return payload;
        } catch (err) {
          lastErr = err;
          clearTimeout(timer);
          if (err.name === 'AbortError') throw new APIError('Request timed out', 0);
          if (err instanceof APIError && err.status && err.status < 500) throw err; // don't retry client errors
          if (attempt === retries) break;
          await sleep(CONFIG.RETRY_DELAY * (attempt + 1));
          attempt++;
        }
      }
      throw lastErr instanceof APIError ? lastErr : new APIError(lastErr?.message || 'Network error', 0);
    }

    return {
      get: (url, opts) => request('GET', url, opts),
      post: (url, json, opts) => request('POST', url, { json, ...opts }),
    };
  })();

  const qs = (params) => {
    const q = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    return q ? `?${q}` : '';
  };

  /* Domain-specific API surface mapped 1:1 to main.py's public routers.
     NOTE: /api/admin/* routes are intentionally not exposed here — this is the client bundle. */
  const API = {
    // Catalog
    products: (params = {}) => APIClient.get(`/api/products${qs(params)}`),
    product: (id) => APIClient.get(`/api/products/${id}`),
    banners: (active = true) => APIClient.get(`/api/banners?active=${active}`),
    // Auth
    register: (data) => APIClient.post('/api/auth/register', data),
    login: (email, password) => APIClient.post('/api/auth/login', { username: email, password }),
    me: () => APIClient.get('/api/auth/me'),
    verifyEmail: (email, otp) => APIClient.post('/api/auth/verify-email', { email, otp }),
    resendOtp: (email) => APIClient.post('/api/auth/resend-otp', { email }),
    // Orders & checkout
    checkout: (payload) => APIClient.post('/api/orders/checkout', payload, { retries: 0 }),
    myOrders: () => APIClient.get('/api/orders'),
    // Public runtime config (WhatsApp number, LiveChat license, social links)
    config: (opts) => APIClient.get('/api/config/public', opts),
    // AI Design Studio — maps to main.py's POST /api/ai/generate-customization.
    // Requires an authenticated customer (get_current_user). base_image_url is a
    // required field server-side (Flux-2-Pro is image-to-image and has no default
    // source image) — always pass the selected product's photo. Returns { image_url }.
    generateCustomization: (prompt, base_image_url, product_context) =>
      APIClient.post('/api/ai/generate-customization', { prompt, base_image_url, product_context }, { retries: 0, timeout: 60000 }),
  };

  /* ==============================================================
     13. AUTHENTICATION MANAGER (storefront customer)
     ============================================================== */
  const Auth = {
    getToken() { return Store.get('auth').token || Storage.get(CONFIG.TOKEN_KEY); },
    getUser() { return Store.get('auth').user || Storage.get(CONFIG.USER_KEY); },
    isAuthed() { return !!this.getToken(); },
    async login(email, password) {
      const res = await API.login(email, password);
      Storage.set(CONFIG.TOKEN_KEY, res.access_token);
      Storage.set(CONFIG.USER_KEY, res.user || null);
      Store.set('auth', { token: res.access_token, user: res.user || null });
      EventBus.emit('auth:login', res.user);
      return res;
    },
    // Evicts the locally-stored session without any notification/redirect
    // side effects — used by logout() and handleUnauthorized() below, and
    // callable on its own wherever just clearing the token is needed.
    clear() {
      Storage.remove(CONFIG.TOKEN_KEY); Storage.remove(CONFIG.USER_KEY);
      Store.set('auth', { token: null, user: null });
    },
    logout() {
      this.clear();
      EventBus.emit('auth:logout');
      location.href = CONFIG.HOME_URL;
    },
    // Called by the API client interceptor on 401/403. Evicts the expired
    // token, surfaces an error toast, and redirects to the auth page —
    // unless the user is already there, to avoid a redirect loop.
    handleUnauthorized(status = 401) {
      this.clear();
      EventBus.emit('auth:expired', status);
      Notify.error(status === 403 ? 'You don\u2019t have permission to do that. Please sign in again.' : 'Please sign in to continue.');
      const onAuthPage = /\/authentication\.html$/.test(location.pathname);
      if (!onAuthPage) {
        location.href = `${CONFIG.LOGIN_URL}?redirect=${encodeURIComponent(location.pathname)}`;
      }
    },
    requireAuth() {
      if (this.isAuthed()) return true;
      Notify.warning('Please sign in to continue.');
      location.href = `${CONFIG.LOGIN_URL}?redirect=${encodeURIComponent(location.pathname)}`;
      return false;
    },
    hydrate() {
      const token = Storage.get(CONFIG.TOKEN_KEY);
      const user = Storage.get(CONFIG.USER_KEY);
      Store.set('auth', { token, user });
      $$('.js-account-name').forEach((n) => (n.textContent = user?.full_name || user?.email || 'Account'));
      $$('[data-auth-only]').forEach((n) => (n.style.display = token ? '' : 'none'));
      $$('[data-guest-only]').forEach((n) => (n.style.display = token ? 'none' : ''));
    },
  };

  /* ==============================================================
     14. NOTIFICATION MANAGER (toasts)
     ============================================================== */
  const Notify = (() => {
    let stack;
    const icons = {
      success: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
      error: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
      warning: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      info: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };
    const ensure = () => { if (!stack) { stack = el('div', { class: 'toast-stack', 'aria-live': 'polite', role: 'status' }); document.body.appendChild(stack); } return stack; };
    const show = (msg, type = 'success', ms = 3200) => {
      const t = el('div', { class: `toast ${type}` });
      t.innerHTML = `<span class="ti">${icons[type] || icons.info}</span><span>${escapeHTML(msg)}</span>`;
      ensure().appendChild(t);
      requestAnimationFrame(() => t.classList.add('show'));
      const close = () => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); };
      const timer = setTimeout(close, ms);
      on(t, 'click', () => { clearTimeout(timer); close(); });
      return close;
    };
    return {
      show, success: (m, ms) => show(m, 'success', ms), error: (m, ms) => show(m, 'error', ms || 4500),
      warning: (m, ms) => show(m, 'warning', ms), info: (m, ms) => show(m, 'info', ms),
    };
  })();

  /* ==============================================================
     15. LOADING OVERLAY
     ============================================================== */
  const Loader = {
    _node: null,
    _ensure() { if (!this._node) { this._node = el('div', { class: 'loading-overlay', html: '<div class="spinner"></div><div class="loading-text">Loading…</div>' }); document.body.appendChild(this._node); } return this._node; },
    show(text = 'Loading…') { const n = this._ensure(); $('.loading-text', n).textContent = text; n.classList.add('on'); },
    hide() { this._node && this._node.classList.remove('on'); },
  };

  /* ==============================================================
     16. MODAL MANAGER (with focus trap + escape handling)
     ============================================================== */
  const Modal = (() => {
    let active = null, lastFocused = null;
    const focusable = 'a[href],button:not([disabled]),textarea,input,select,[tabindex]:not([tabindex="-1"])';
    const trap = (e) => {
      if (e.key !== 'Tab' || !active) return;
      const nodes = $$(focusable, active).filter((n) => n.offsetParent !== null);
      if (!nodes.length) return;
      const first = nodes[0], last = nodes[nodes.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    return {
      open(id) {
        const bg = typeof id === 'string' ? document.getElementById(id) : id;
        if (!bg) return;
        lastFocused = document.activeElement;
        bg.classList.add('on'); bg.setAttribute('aria-hidden', 'false');
        active = bg; document.body.style.overflow = 'hidden';
        setTimeout(() => { const f = $(focusable, bg); f && f.focus(); }, 40);
        document.addEventListener('keydown', trap);
      },
      close(id) {
        const bg = id ? (typeof id === 'string' ? document.getElementById(id) : id) : active;
        if (!bg) return;
        bg.classList.remove('on'); bg.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
        document.removeEventListener('keydown', trap);
        if (active === bg) active = null;
        lastFocused && lastFocused.focus?.();
      },
      init() {
        on(document, 'click', (e) => {
          if (e.target.classList?.contains('modal-bg')) this.close(e.target);
          const closer = e.target.closest('[data-modal-close]');
          if (closer) this.close(closer.closest('.modal-bg'));
          const opener = e.target.closest('[data-modal-open]');
          if (opener) this.open(opener.dataset.modalOpen);
        });
        on(document, 'keydown', (e) => { if (e.key === 'Escape' && active) this.close(); });
      },
    };
  })();

  /* ==============================================================
     17. DRAWER MANAGER (cart drawer + mobile nav)
     Expects markup: #<id> (panel) + #<id>-bg (backdrop), both toggle the
     shared ".on" class. e.g. #cart-drawer / #cart-drawer-bg,
     #mobile-nav / #mobile-nav-bg.
     ============================================================== */
  const Drawer = {
    open(id) { const d = document.getElementById(id); if (!d) return; d.classList.add('on'); const bg = document.getElementById(`${id}-bg`); bg && bg.classList.add('on'); document.body.style.overflow = 'hidden'; },
    close(id) { const d = document.getElementById(id); if (!d) return; d.classList.remove('on'); const bg = document.getElementById(`${id}-bg`); bg && bg.classList.remove('on'); document.body.style.overflow = ''; },
    init() {
      on(document, 'click', (e) => {
        const o = e.target.closest('[data-drawer-open]'); if (o) this.open(o.dataset.drawerOpen);
        const c = e.target.closest('[data-drawer-close]'); if (c) this.close(c.dataset.drawerClose || c.closest('[class*="-bg"]')?.id.replace('-bg', '') || c.closest('.cart-drawer,.mobile-nav')?.id);
        if (e.target.id?.endsWith('-bg')) this.close(e.target.id.replace('-bg', ''));
      });
      on(document, 'keydown', (e) => { if (e.key === 'Escape') { this.close('cart-drawer'); this.close('mobile-nav'); } });
    },
  };

  /* ==============================================================
     18. DROPDOWN MANAGER
     ============================================================== */
  const Dropdown = {
    init() {
      on(document, 'click', (e) => {
        const trigger = e.target.closest('[data-dropdown]');
        if (trigger) {
          const menu = document.getElementById(trigger.dataset.dropdown);
          const isOpen = menu?.classList.contains('open');
          $$('.dropdown-menu.open').forEach((m) => m.classList.remove('open'));
          if (menu && !isOpen) menu.classList.add('open');
          e.stopPropagation();
          return;
        }
        if (!e.target.closest('.dropdown-menu')) $$('.dropdown-menu.open').forEach((m) => m.classList.remove('open'));
      });
    },
  };

  /* ==============================================================
     19. TOOLTIP MANAGER
     ============================================================== */
  const Tooltip = { init() { $$('[data-tip]').forEach((n) => { if (!n.getAttribute('aria-label')) n.setAttribute('aria-label', n.dataset.tip); }); } };

  /* ==============================================================
     20. SITE HEADER / RESPONSIVE NAV MODULE
     ============================================================== */
  const SiteNav = {
    init() {
      const header = $('.site-header');
      const onScroll = () => header && header.classList.toggle('scrolled', window.scrollY > 12);
      on(window, 'scroll', onScroll, { passive: true }); onScroll();

      on($('.mob-toggle'), 'click', () => Drawer.open('mobile-nav'));
      $$('#mobile-nav .mobile-nav-link').forEach((l) => on(l, 'click', () => Drawer.close('mobile-nav')));

      // Active-link highlight based on current file
      const file = location.pathname.split('/').pop() || 'index.html';
      $$('.nav-link[data-href], .mobile-nav-link[data-href]').forEach((l) => { if (l.dataset.href === file) l.classList.add('active'); });
    },
  };

  /* ==============================================================
     21. TABS + ACCORDION (generic UI controllers)
     ============================================================== */
  const TabController = {
    init() {
      on(document, 'click', (e) => {
        const tab = e.target.closest('.tab[data-tab]'); if (!tab) return;
        const group = tab.closest('.tabs');
        if (!group) return; // malformed/partial tab markup — nothing to do
        $$('.tab', group).forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');
        const panelId = tab.dataset.tab;
        const scope = group.parentElement;
        if (!scope) return;
        $$('.tab-panel', scope).forEach((p) => p.classList.toggle('active', p.id === panelId));
      });
    },
  };
  const AccordionController = {
    init() {
      on(document, 'click', (e) => {
        const head = e.target.closest('.accordion-head');
        if (!head) return;
        const item = head.closest('.accordion-item');
        if (item) item.classList.toggle('open');
      });
    },
  };

  /* ==============================================================
     22. CART MODULE
     Cart lives entirely client-side (localStorage) until checkout —
     the backend has no "add to cart" concept, only /api/orders/checkout.
     ============================================================== */
  const Cart = {
    items: [],

    load() { this.items = Storage.get(CONFIG.CART_KEY, []); Store.set('cart', this.items); return this.items; },
    persist() { Storage.set(CONFIG.CART_KEY, this.items); Store.set('cart', this.items); this.renderBadge(); EventBus.emit('cart:change', this.items); },

    add(product, quantity = 1) {
      // Customized items never merge into a plain (non-customized) line for the
      // same product, and two distinct custom renders of the same product stay
      // separate too — only an exact re-add of the same render bumps quantity.
      const isCustom = Boolean(product.is_customized);
      const existing = this.items.find((i) =>
        i.product_id === product.id &&
        Boolean(i.is_customized) === isCustom &&
        (!isCustom || i.custom_image_url === product.custom_image_url)
      );
      if (existing) {
        existing.quantity = Math.min(existing.quantity + quantity, product.quantity ?? 999);
      } else {
        this.items.push({
          product_id: product.id,
          name: product.name,
          image: product.custom_image_url || product.optimized_url || product.image_url,
          price: product.price,
          quantity,
          max_quantity: product.quantity ?? 999,
          is_customized: isCustom,
          customization_notes: product.customization_notes || undefined,
          custom_image_url: product.custom_image_url || undefined,
        });
      }
      this.persist();
      this.renderDrawer(); this.renderPage();
      Notify.success(`${product.name} added to cart.`);
    },
    updateQty(productId, quantity) {
      const item = this.items.find((i) => i.product_id === productId);
      if (!item) return;
      item.quantity = Math.max(1, Math.min(quantity, item.max_quantity || 999));
      this.persist();
      this.renderDrawer(); this.renderPage();
    },
    remove(productId) {
      this.items = this.items.filter((i) => i.product_id !== productId);
      this.persist();
      this.renderDrawer(); this.renderPage();
    },
    clear() { this.items = []; this.persist(); this.renderDrawer(); this.renderPage(); },

    count() { return this.items.reduce((n, i) => n + i.quantity, 0); },
    subtotal() { return this.items.reduce((s, i) => s + i.price * i.quantity, 0); },

    renderBadge() {
      $$('.cart-count').forEach((b) => {
        const n = this.count();
        b.textContent = n > 99 ? '99+' : String(n);
        b.style.display = n > 0 ? 'grid' : 'none';
      });
    },

    _itemRowHTML(item, { removable = true } = {}) {
      return `
        <div class="cart-item" data-product-id="${item.product_id}">
          <div class="ci-img"><img src="${escapeHTML(item.image || '')}" alt="${escapeHTML(item.name)}" loading="lazy"></div>
          <div class="ci-info">
            <div class="ci-name">${escapeHTML(item.name)}</div>
            <div class="ci-foot-row">
              <div class="qty-stepper" data-qty-for="${item.product_id}">
                <button type="button" data-qty-dec aria-label="Decrease quantity">−</button>
                <input type="number" min="1" max="${item.max_quantity || 999}" value="${item.quantity}" inputmode="numeric" data-qty-input>
                <button type="button" data-qty-inc aria-label="Increase quantity">+</button>
              </div>
              <span class="ci-price">${Fmt.money(item.price * item.quantity)}</span>
            </div>
            ${removable ? `<button type="button" class="ci-remove" data-cart-remove="${item.product_id}">Remove</button>` : ''}
          </div>
        </div>`;
    },

    renderDrawer() {
      const body = $('#cart-drawer-body');
      const summary = $('#cart-drawer-summary');
      if (!body) return;
      if (!this.items.length) {
        body.innerHTML = UI.empty('shopping-bag', 'Your cart is empty', 'Browse the catalog and add something you love.');
      } else {
        body.innerHTML = this.items.map((i) => this._itemRowHTML(i)).join('');
      }
      if (summary) {
        summary.innerHTML = `
          <div class="cart-summary-row"><span>Subtotal</span><span>${Fmt.money(this.subtotal())}</span></div>
          <div class="cart-summary-row total"><span>Total</span><span class="val">${Fmt.money(this.subtotal())}</span></div>`;
      }
      refreshIcons();
    },

    renderPage() {
      const list = $('#cart-page-list');
      if (!list) return;
      if (!this.items.length) {
        list.innerHTML = UI.empty('shopping-bag', 'Your cart is empty', 'Browse the catalog and add something you love.');
      } else {
        list.innerHTML = this.items.map((i) => this._itemRowHTML(i)).join('');
      }
      const summary = $('#cart-page-summary');
      if (summary) {
        summary.innerHTML = `
          <div class="cart-summary-row"><span>Subtotal (${this.count()} items)</span><span>${Fmt.money(this.subtotal())}</span></div>
          <div class="cart-summary-row total"><span>Total</span><span class="val">${Fmt.money(this.subtotal())}</span></div>`;
      }
      const checkoutBtn = $('#cart-checkout-btn');
      if (checkoutBtn) checkoutBtn.disabled = this.items.length === 0;
      refreshIcons();
    },

    bindEvents() {
      on(document, 'click', (e) => {
        const addBtn = e.target.closest('[data-add-to-cart]');
        if (addBtn) {
          const productJSON = addBtn.dataset.addToCart;
          try { this.add(JSON.parse(productJSON)); } catch { Log.error('Bad product payload on add-to-cart button'); }
        }
        const removeBtn = e.target.closest('[data-cart-remove]');
        if (removeBtn) this.remove(Number(removeBtn.dataset.cartRemove));

        const dec = e.target.closest('[data-qty-dec]');
        if (dec) {
          const wrap = dec.closest('[data-qty-for]');
          if (wrap) {
            const id = Number(wrap.dataset.qtyFor);
            const item = this.items.find((i) => i.product_id === id);
            if (item) this.updateQty(id, item.quantity - 1);
          }
        }
        const inc = e.target.closest('[data-qty-inc]');
        if (inc) {
          const wrap = inc.closest('[data-qty-for]');
          if (wrap) {
            const id = Number(wrap.dataset.qtyFor);
            const item = this.items.find((i) => i.product_id === id);
            if (item) this.updateQty(id, item.quantity + 1);
          }
        }
      });
      on(document, 'change', (e) => {
        const input = e.target.closest('[data-qty-input]');
        if (input) {
          const wrap = input.closest('[data-qty-for]');
          if (wrap) this.updateQty(Number(wrap.dataset.qtyFor), Number(input.value) || 1);
        }
      });
    },

    // Re-renders every cart surface in one call — used on init and
    // whenever another tab mutates the cart out from under this one.
    updateUI() {
      this.renderBadge();
      this.renderDrawer();
      this.renderPage();
    },

    // Multi-tab sync: the storage event only fires in OTHER tabs/windows
    // when localStorage changes, never in the tab that made the change —
    // so this safely reloads from the now-authoritative localStorage value
    // and repaints without any risk of an update loop.
    _bindCrossTabSync() {
      on(window, 'storage', (e) => {
        if (e.key === CONFIG.CART_KEY) {
          this.load();
          this.updateUI();
        }
      });
    },

    init() {
      this.load();
      this.bindEvents();
      this._bindCrossTabSync();
      this.renderBadge();
      this.renderDrawer();
      this.renderPage();
    },
  };

  /* ==============================================================
     23. PRODUCTS MODULE (homepage teaser + full catalog)
     Deliberately category-free: no category filter UI anywhere,
     matching the storefront brief.
     ============================================================== */
  const ProductsModule = {
    _cardHTML(p) {
      const img = p.optimized_url || p.image_url || '';
      const cartPayload = escapeHTML(JSON.stringify({ id: p.id, name: p.name, price: p.price, image_url: img, quantity: p.quantity }));
      return `
        <div class="product-card">
          <a href="/product.html?id=${p.id}" class="pc-img-link">
            <div class="pc-img">
              <img src="${escapeHTML(img)}" alt="${escapeHTML(p.name)}" loading="lazy">
              <div class="pc-badges">
                ${p.badge ? `<span class="badge sale">${escapeHTML(p.badge)}</span>` : ''}
                ${!p.is_available ? `<span class="badge out">Out of stock</span>` : ''}
              </div>
            </div>
          </a>
          <div class="pc-body">
            <div class="pc-name"><a href="/product.html?id=${p.id}">${escapeHTML(p.name)}</a></div>
            <div class="pc-price">${Fmt.money(p.price)}${p.old_price ? `<span class="old">${Fmt.money(p.old_price)}</span>` : ''}</div>
            <div class="pc-foot">
              <button type="button" class="btn btn-primary btn-sm" ${p.is_available ? '' : 'disabled'} data-add-to-cart="${cartPayload}">
                <i data-lucide="shopping-bag"></i> Add to cart
              </button>
            </div>
          </div>
        </div>`;
    },

    async renderHomeTeaser() {
      const grid = $('#home-product-grid');
      if (!grid) return;
      grid.innerHTML = Array.from({ length: HOMEPAGE_PRODUCT_LIMIT }).map(() => '<div class="skeleton skeleton-card"></div>').join('');
      try {
        const products = await API.products({ limit: HOMEPAGE_PRODUCT_LIMIT });
        Store.set('products', products);
        grid.innerHTML = products.length
          ? products.slice(0, HOMEPAGE_PRODUCT_LIMIT).map((p) => this._cardHTML(p)).join('')
          : UI.empty('package', 'No products yet', 'Check back soon — new pieces are on the way.');
      } catch (err) {
        Log.error(err);
        grid.innerHTML = UI.empty('alert-triangle', 'Could not load products', err.message);
      }
      refreshIcons();
    },

    async renderCatalog() {
      const grid = $('#catalog-product-grid');
      if (!grid) return;
      grid.innerHTML = Array.from({ length: 6 }).map(() => '<div class="skeleton skeleton-card"></div>').join('');
      try {
        const products = await API.products({ limit: 100 });
        Store.set('products', products);
        grid.innerHTML = products.length
          ? products.map((p) => this._cardHTML(p)).join('')
          : UI.empty('package', 'No products yet', 'Check back soon — new pieces are on the way.');
        const countLabel = $('#catalog-count');
        if (countLabel) countLabel.textContent = `${products.length} product${products.length === 1 ? '' : 's'}`;
      } catch (err) {
        Log.error(err);
        grid.innerHTML = UI.empty('alert-triangle', 'Could not load products', err.message);
      }
      refreshIcons();
    },

    async init() {
      await Promise.all([this.renderHomeTeaser(), this.renderCatalog()]);
    },
  };

  /* ==============================================================
     24. PRODUCT DETAIL MODULE (PDP)
     ============================================================== */
  const ProductDetail = {
    product: null,

    async init() {
      const root = $('#pdp-root');
      if (!root) return;
      const id = qsGet('id');
      if (!id) { root.innerHTML = UI.empty('alert-triangle', 'Product not found', 'No product was specified.'); return; }

      Loader.show('Loading product…');
      try {
        this.product = await API.product(id);
        this.render();
      } catch (err) {
        Log.error(err);
        root.innerHTML = UI.empty('alert-triangle', 'Product not found', err.message);
      } finally {
        Loader.hide();
      }
    },

    render() {
      const p = this.product;
      const mainImg = $('#pdp-main-image');
      const img = p.optimized_url || p.image_url || '';
      if (mainImg) mainImg.src = img;

      const thumbs = $('#pdp-thumbs');
      const gallery = [img, ...(p.gallery_images || [])].filter(Boolean);
      if (thumbs) {
        thumbs.innerHTML = gallery.map((src, i) => `<div class="pdp-thumb ${i === 0 ? 'active' : ''}" data-src="${escapeHTML(src)}"><img src="${escapeHTML(src)}" alt="${escapeHTML(p.name)} view ${i + 1}"></div>`).join('');
      }

      $('#pdp-title') && ($('#pdp-title').textContent = p.name);
      $('#pdp-price') && ($('#pdp-price').innerHTML = `${Fmt.money(p.price)}${p.old_price ? `<span class="old">${Fmt.money(p.old_price)}</span>` : ''}`);
      $('#pdp-desc') && ($('#pdp-desc').textContent = p.description || '');
      document.title = `${p.name} · Rocky Trendy Realities`;

      const stock = $('#pdp-stock');
      if (stock) {
        stock.innerHTML = p.is_available
          ? `<span class="badge confirmed">In stock</span> <span class="text-muted fs-sm">${p.quantity} available${p.delivery_duration ? ` · ships in ${escapeHTML(p.delivery_duration)}` : ''}</span>`
          : `<span class="badge out">Out of stock</span>`;
      }

      const qtyInput = $('#pdp-qty');
      if (qtyInput) qtyInput.max = p.quantity || 1;

      const addBtn = $('#pdp-add-to-cart');
      if (addBtn) {
        addBtn.disabled = !p.is_available;
        addBtn.onclick = () => {
          const qty = Number(qtyInput?.value) || 1;
          Cart.add({ id: p.id, name: p.name, price: p.price, image_url: img, quantity: p.quantity }, qty);
        };
      }

      const waBtn = $('#pdp-whatsapp-enquire');
      if (waBtn) waBtn.href = Checkout.buildWhatsAppLink({ note: `Hi, I'd like to ask about "${p.name}" (${Fmt.money(p.price)}).` });

      this._bindGallery();
      refreshIcons();
    },

    _bindGallery() {
      on($('#pdp-thumbs'), 'click', (e) => {
        const thumb = e.target.closest('.pdp-thumb');
        if (!thumb) return;
        $$('.pdp-thumb').forEach((t) => t.classList.remove('active'));
        thumb.classList.add('active');
        const mainImg = $('#pdp-main-image');
        if (mainImg) mainImg.src = thumb.dataset.src;
      });
    },
  };

  /* ==============================================================
     25. AUTH MODULE (login / register / OTP verify)
     ============================================================== */
  const AuthModule = {
    init() {
      this._bindLogin();
      this._bindRegister();
      this._bindVerify();
      this._bindResend();
      this._bindLogout();
    },

    _formValue(form, name) { return sanitizeInput(form.elements[name]?.value); },

    _bindLogin() {
      const form = $('#login-form');
      if (!form) return;
      on(form, 'submit', async (e) => {
        e.preventDefault();
        const email = this._formValue(form, 'email');
        const password = form.elements['password']?.value || '';
        if (!Validate.email(email)) return Notify.error('Enter a valid email address.');
        if (!Validate.minLen(password, 1)) return Notify.error('Enter your password.');

        const btn = form.querySelector('[type="submit"]');
        btn && (btn.disabled = true);
        try {
          await Auth.login(email, password);
          Notify.success('Welcome back!');
          location.href = qsGet('redirect') || CONFIG.HOME_URL;
        } catch (err) {
          Notify.error(err.message || 'Login failed.');
        } finally {
          btn && (btn.disabled = false);
        }
      });
    },

    _bindRegister() {
      const form = $('#register-form');
      if (!form) return;
      on(form, 'submit', async (e) => {
        e.preventDefault();
        const email = this._formValue(form, 'email');
        const password = form.elements['password']?.value || '';
        const country = this._formValue(form, 'country');
        const full_name = this._formValue(form, 'full_name');

        if (!Validate.email(email)) return Notify.error('Enter a valid email address.');
        if (!Validate.minLen(password, 8)) return Notify.error('Password must be at least 8 characters.');
        if (!Validate.required(country)) return Notify.error('Please tell us your country.');

        const btn = form.querySelector('[type="submit"]');
        btn && (btn.disabled = true);
        try {
          const res = await API.register({ email, password, country, full_name: full_name || undefined });
          Notify.success(res.message || 'Account created. Check your email for a verification code.');
          location.href = `/authentication.html?mode=verify&email=${encodeURIComponent(email)}`;
        } catch (err) {
          if (err.status === 400) {
            // Duplicate email — including the race-condition path where two
            // signups for the same address land concurrently and the backend
            // resolves it as an IntegrityError on flush (see services.py's
            // create_user_service). Surface the backend's message as-is and
            // nudge the person toward signing in instead of retrying blindly.
            Notify.error(err.message || 'An account with this email address already exists. Please log in instead.');
          } else {
            Notify.error(err.message || 'Registration failed. Please try again.');
          }
        } finally {
          btn && (btn.disabled = false);
        }
      });
    },

    _bindVerify() {
      const form = $('#verify-form');
      if (!form) return;
      const emailField = form.elements['email'];
      if (emailField && qsGet('email')) emailField.value = qsGet('email');

      on(form, 'submit', async (e) => {
        e.preventDefault();
        const email = this._formValue(form, 'email');
        const otp = this._formValue(form, 'otp');
        if (!Validate.email(email)) return Notify.error('Enter a valid email address.');
        if (!Validate.required(otp)) return Notify.error('Enter the code sent to your email.');

        const btn = form.querySelector('[type="submit"]');
        btn && (btn.disabled = true);
        try {
          await API.verifyEmail(email, otp);
          Notify.success('Email verified — you can now log in.');
          location.href = `/authentication.html?mode=login&email=${encodeURIComponent(email)}`;
        } catch (err) {
          Notify.error(err.message || 'Verification failed.');
        } finally {
          btn && (btn.disabled = false);
        }
      });
    },

    _bindResend() {
      $$('[data-resend-otp]').forEach((btn) => on(btn, 'click', async () => {
        const email = $('#verify-form')?.elements['email']?.value || qsGet('email');
        if (!Validate.email(email)) return Notify.error('Enter your email above first.');
        btn.disabled = true;
        try {
          const res = await API.resendOtp(email);
          Notify.success(res.message || 'A new code has been sent.');
        } catch (err) {
          Notify.error(err.message || 'Could not resend code.');
        } finally {
          setTimeout(() => (btn.disabled = false), 15000); // basic resend cooldown
        }
      }));
    },

    _bindLogout() {
      $$('[data-logout]').forEach((b) => on(b, 'click', (e) => { e.preventDefault(); Auth.logout(); }));
    },
  };

  /* ==============================================================
     26. CHECKOUT MODULE (Paystack + WhatsApp)
     --------------------------------------------------------------
     Both payment methods now go through the same backend endpoint,
     POST /api/orders/checkout (see services.py's create_order_service).
     The request always includes payment_method, and the response
     shape tells us which redirect to follow:
       - payment_method: 'whatsapp' → server creates a real Order row,
         decrements stock, and returns { whatsapp_redirect: true,
         order_reference }. The frontend builds the prefilled wa.me
         link client-side (the backend has no WhatsApp API access
         itself) and opens it — the order is confirmed once someone
         on the RTR WhatsApp line follows up.
       - payment_method: 'paystack' → server initializes a Paystack
         transaction and returns { authorization_url, reference, ... }.
         The frontend redirects there for hosted checkout.
     Both paths require an authenticated customer (the endpoint sits
     behind get_current_user), so Auth.requireAuth() runs first either way.
     ============================================================== */
  const Checkout = {
    method: 'paystack',

    buildWhatsAppLink({ note, orderReference } = {}) {
      const lines = [];
      if (note) {
        lines.push(note);
      } else if (Cart.items.length) {
        lines.push('Hi! I would like to order:');
        Cart.items.forEach((i) => lines.push(`• ${i.name} × ${i.quantity} — ${Fmt.money(i.price * i.quantity)}`));
        lines.push(`Total: ${Fmt.money(Cart.subtotal())}`);
        const form = $('#checkout-form');
        if (form) {
          const name = form.elements['customer_name']?.value;
          const phone = form.elements['customer_phone']?.value;
          const address = form.elements['shipping_address']?.value;
          if (name) lines.push(`Name: ${name}`);
          if (phone) lines.push(`Phone: ${phone}`);
          if (address) lines.push(`Delivery address: ${address}`);
        }
      }
      if (orderReference) lines.push(`Order Ref: ${orderReference}`);
      const text = encodeURIComponent(lines.join('\n'));
      return `https://wa.me/${CONFIG.WHATSAPP_NUMBER}?text=${text}`;
    },

    renderSummary() {
      const box = $('#checkout-summary');
      if (!box) return;
      if (!Cart.items.length) {
        box.innerHTML = UI.empty('shopping-bag', 'Your cart is empty', 'Add products before checking out.');
        return;
      }
      box.innerHTML = `
        <div class="order-summary-mini">
          ${Cart.items.map((i) => `
            <div class="osm-item">
              <div class="ci-img"><img src="${escapeHTML(i.image || '')}" alt="${escapeHTML(i.name)}"></div>
              <div><div class="osm-name">${escapeHTML(i.name)}</div><div class="osm-qty">Qty ${i.quantity}</div></div>
              <span class="osm-price">${Fmt.money(i.price * i.quantity)}</span>
            </div>`).join('')}
        </div>
        <div class="cart-summary-row total mt-3"><span>Total</span><span class="val">${Fmt.money(Cart.subtotal())}</span></div>`;
    },

    bindMethodSwitch() {
      $$('.pay-method-card').forEach((card) => on(card, 'click', () => {
        $$('.pay-method-card').forEach((c) => c.classList.remove('selected'));
        card.classList.add('selected');
        this.method = card.dataset.payMethod;
        const paystackBtn = $('#checkout-pay-paystack');
        const whatsappBtn = $('#checkout-pay-whatsapp');
        if (paystackBtn) paystackBtn.classList.toggle('hidden', this.method !== 'paystack');
        if (whatsappBtn) whatsappBtn.classList.toggle('hidden', this.method !== 'whatsapp');
      }));
    },

    bindSubmit() {
      const form = $('#checkout-form');
      if (!form) return;

      on(form, 'submit', async (e) => {
        e.preventDefault();
        if (!Cart.items.length) return Notify.error('Your cart is empty.');

        const email = sanitizeInput(form.elements['customer_email']?.value);
        const phone = sanitizeInput(form.elements['customer_phone']?.value);
        const address = sanitizeInput(form.elements['shipping_address']?.value);

        if (!Validate.email(email)) return Notify.error('Enter a valid email address.');
        if (!Validate.phone(phone)) return Notify.error('Enter a valid phone number.');
        if (!Validate.required(address)) return Notify.error('Enter your delivery address.');

        // Both payment methods hit the same authenticated endpoint now.
        if (!Auth.requireAuth()) return;

        const isWhatsApp = this.method === 'whatsapp';
        const btn = form.querySelector(isWhatsApp ? '#checkout-pay-whatsapp' : '#checkout-pay-paystack') || form.querySelector('[type="submit"]');
        btn && (btn.disabled = true);
        Loader.show(isWhatsApp ? 'Placing your order…' : 'Setting up secure payment…');
        try {
          // Mirrors CartItemSchema in models_schemas.py exactly — product_id,
          // quantity, is_customized, customization_notes, custom_image_url —
          // so the payload matches CheckoutRequest regardless of which of
          // those optional fields a given cart item happens to carry.
          const payload = {
            items: Cart.items.map((i) => ({
              product_id: i.product_id,
              quantity: i.quantity,
              is_customized: Boolean(i.is_customized),
              customization_notes: i.customization_notes ? sanitizeInput(i.customization_notes, 2000) : undefined,
              custom_image_url: i.custom_image_url || undefined,
            })),
            customer_email: email,
            customer_phone: phone,
            shipping_address: address,
            payment_method: isWhatsApp ? 'whatsapp' : 'paystack',
          };
          const res = await API.checkout(payload);

          if (res && res.whatsapp_redirect) {
            const link = this.buildWhatsAppLink({ orderReference: res.order_reference });
            Cart.clear();
            window.open(link, '_blank', 'noopener');
            Notify.success('Order placed — we\u2019ve opened WhatsApp so you can confirm it.');
          } else if (res && res.authorization_url) {
            Cart.clear();
            window.location.href = res.authorization_url;
          } else {
            throw new Error('Checkout succeeded but no redirect target was returned.');
          }
        } catch (err) {
          Notify.error(err.message || 'Checkout failed. Please try again.');
        } finally {
          Loader.hide();
          btn && (btn.disabled = false);
        }
      });
    },

    init() {
      if (!$('#checkout-form') && !$('#checkout-summary')) return;
      this.renderSummary();
      this.bindMethodSwitch();
      this.bindSubmit();
    },
  };

  /* ==============================================================
     27. ORDERS MODULE (customer order history)
     ============================================================== */
  const OrdersModule = {
    orders: [],
    activeFilter: 'all',

    async init() {
      const root = $('#orders-list');
      if (!root) return;
      if (!Auth.requireAuth()) return;

      this._bindFilters();
      await this.load();
    },

    async load() {
      const root = $('#orders-list');
      root.innerHTML = Array.from({ length: 3 }).map(() => '<div class="skeleton skeleton-card mb-2"></div>').join('');
      try {
        this.orders = await API.myOrders();
        this.render();
      } catch (err) {
        Log.error(err);
        root.innerHTML = UI.empty('alert-triangle', 'Could not load your orders', err.message);
      }
    },

    _bindFilters() {
      $$('.orders-filter-tabs .ftab').forEach((tab) => on(tab, 'click', () => {
        $$('.orders-filter-tabs .ftab').forEach((t) => t.classList.remove('on'));
        tab.classList.add('on');
        this.activeFilter = tab.dataset.status || 'all';
        this.render();
      }));
    },

    _statusGroup(status) {
      if (['pending', 'paid', 'processing'].includes(status)) return 'pending';
      if (['shipped', 'delivered'].includes(status)) return 'fulfilled';
      return 'cancelled'; // cancelled, refunded, failed
    },

    render() {
      const root = $('#orders-list');
      const filtered = this.activeFilter === 'all'
        ? this.orders
        : this.orders.filter((o) => this._statusGroup(o.status) === this.activeFilter);

      if (!filtered.length) {
        root.innerHTML = UI.empty('package', 'No orders here', 'Orders matching this filter will show up here.');
        return;
      }

      root.innerHTML = filtered.map((o) => this._cardHTML(o)).join('');
      refreshIcons();
    },

    _paymentLabel(method) {
      const map = { paystack: 'Paystack', wallet: 'Wallet', whatsapp: 'WhatsApp' };
      return map[method] || Fmt.titleCase(method || 'Not specified');
    },

    _cardHTML(o) {
      const items = o.items || [];
      const thumbs = items.slice(0, 4).map((i) => `<img src="${escapeHTML(i.product_image_snapshot || '')}" alt="${escapeHTML(i.product_name_snapshot || 'Product image')}">`).join('');
      const lines = items.map((i) => `
        <div class="order-line">
          <span class="order-line-name">${escapeHTML(i.product_name_snapshot || 'Item')}${i.is_customized ? ' <span class="badge sale">Custom</span>' : ''}</span>
          <span class="order-line-qty">×${Number(i.quantity || 1)}</span>
          <span class="order-line-price">${Fmt.money(i.unit_price_at_purchase)}</span>
        </div>`).join('');
      return `
        <div class="order-card">
          <div class="order-card-head">
            <div>
              <div class="order-id">${escapeHTML(o.order_reference || `#${o.id}`)}</div>
              <div class="order-date">${Fmt.dateTime(o.created_at)}</div>
            </div>
            <span class="badge ${escapeHTML(o.status)}">${Fmt.orderStatus(o.status)}</span>
          </div>
          ${thumbs ? `<div class="order-items-preview">${thumbs}</div>` : ''}
          ${lines ? `<div class="order-lines mt-3">${lines}</div>` : ''}
          <div class="order-meta mt-3">
            <span class="order-meta-item"><i data-lucide="credit-card"></i> ${escapeHTML(this._paymentLabel(o.payment_method))}</span>
            ${o.shipping_address ? `<span class="order-meta-item"><i data-lucide="map-pin"></i> ${escapeHTML(o.shipping_address)}</span>` : ''}
          </div>
          <div class="order-card-foot mt-3">
            <span class="fs-sm text-muted">${items.length} item${items.length === 1 ? '' : 's'}</span>
            <span class="order-total">${Fmt.money(o.total_amount)}</span>
          </div>
        </div>`;
    },
  };

  /* ==============================================================
     28. FAQ MODULE
     FAQ is just the generic accordion controller — nothing page-specific
     beyond making sure the first item opens by default for orientation.
     ============================================================== */
  const FaqModule = {
    init() {
      const first = $('.faq-list .accordion-item');
      if (first) first.classList.add('open');
    },
  };

  /* ==============================================================
     29. CONTACT MODULE
     --------------------------------------------------------------
     NOTE: main.py has no /api/contact (or newsletter) endpoint, so
     this intentionally does not call the backend. It routes the
     message to the RTR WhatsApp line instead. Swap this for a real
     POST once a contact endpoint exists.
     ============================================================== */
  const ContactModule = {
    init() {
      const form = $('#contact-form');
      if (!form) return;
      on(form, 'submit', (e) => {
        e.preventDefault();
        const name = sanitizeInput(form.elements['name']?.value);
        const email = sanitizeInput(form.elements['email']?.value);
        const message = sanitizeInput(form.elements['message']?.value, 800);

        if (!Validate.required(name)) return Notify.error('Enter your name.');
        if (!Validate.email(email)) return Notify.error('Enter a valid email address.');
        if (!Validate.required(message)) return Notify.error('Enter a message.');

        const text = encodeURIComponent(`Hi RTR, my name is ${name} (${email}).\n\n${message}`);
        window.open(`https://wa.me/${CONFIG.WHATSAPP_NUMBER}?text=${text}`, '_blank', 'noopener');
        Notify.success('Opened WhatsApp with your message ready to send.');
        form.reset();
      });
    },
  };

  /* ==============================================================
     30. SHARED UI SNIPPETS
     ============================================================== */
  const UI = {
    empty(icon, title, sub) {
      return `<div class="empty-state"><span class="es-icon"><i data-lucide="${icon}"></i></span><h4>${escapeHTML(title)}</h4>${sub ? `<p>${escapeHTML(sub)}</p>` : ''}</div>`;
    },
  };

  /* ==============================================================
     ERROR HANDLING MODULE (global)
     ============================================================== */
  const ErrorHandler = {
    init() {
      window.addEventListener('unhandledrejection', (e) => {
        Log.error('Unhandled rejection', e.reason);
        if (e.reason instanceof APIError && e.reason.status !== 401 && e.reason.status !== 403) Notify.error(e.reason.message);
      });
      window.addEventListener('error', (e) => { Log.error('Global error', e.message); });
    },
  };

  /* ==============================================================
     31. MOBILE VIEWPORT FIX
     --------------------------------------------------------------
     Mobile browsers (iOS Safari, Chrome for Android, etc.) resize the
     visual viewport as their address bar / toolbars hide and show,
     which makes 100vh-based full-height layouts (Cart Drawer, Mobile
     Nav) jump or get clipped. Instead of trusting the vh unit, we
     compute 1% of the *actual* window.innerHeight and expose it as a
     --vh custom property; full-height panels should size with
     height: calc(var(--vh, 1vh) * 100) rather than height: 100vh.
     ============================================================== */
  function initMobileViewportFix() {
    const setVH = () => {
      const vh = window.innerHeight * 0.01;
      document.documentElement.style.setProperty('--vh', `${vh}px`);
    };
    setVH();
    on(window, 'resize', debounce(setVH, 120), { passive: true });
    on(window, 'orientationchange', setVH, { passive: true });
  }

  /* ==============================================================
     32. INTEGRATIONS MODULE
     --------------------------------------------------------------
     Decouples third-party integration keys (WhatsApp number, LiveChat
     license, social links) from the static CONFIG literal so ops can
     change them server-side (see main.py's GET /api/config/public)
     without a redeploy of this file. Every method fails soft — if the
     network is unavailable, the CONFIG defaults declared in section 1
     keep working exactly as before.
     ============================================================== */
  const IntegrationsModule = {
    async fetchConfig() {
      try {
        // Short timeout, no retries: this call sits on the critical
        // bootstrap path, so a slow/offline network should fall back
        // to CONFIG defaults quickly rather than stall the whole page.
        const cfg = await API.config({ retries: 0, timeout: 6000 });
        if (cfg && typeof cfg === 'object') {
          CONFIG.WHATSAPP_NUMBER = cfg.whatsapp_phone || CONFIG.WHATSAPP_NUMBER;
          CONFIG.LIVECHAT_LICENSE = cfg.livechat_license || '';
          CONFIG.SOCIAL_FACEBOOK = cfg.social_facebook || CONFIG.SOCIAL_FACEBOOK;
          CONFIG.SOCIAL_INSTAGRAM = cfg.social_instagram || CONFIG.SOCIAL_INSTAGRAM;
        }
      } catch (err) {
        Log.warn('IntegrationsModule.fetchConfig: falling back to local defaults (offline or request failed)', err);
      }
    },

    initLiveChat() {
      if (!CONFIG.LIVECHAT_LICENSE || document.getElementById('lc-tracking-script')) return;
      try {
        window.__lc = window.__lc || {};
        window.__lc.license = CONFIG.LIVECHAT_LICENSE;
        const script = document.createElement('script');
        script.id = 'lc-tracking-script';
        script.async = true;
        script.src = 'https://cdn.livechatinc.com/tracking.js';
        document.head.appendChild(script);
      } catch (err) {
        Log.error('IntegrationsModule.initLiveChat failed', err);
      }
    },

    initSocials() {
      try {
        if (CONFIG.SOCIAL_FACEBOOK) {
          $$('[data-social="facebook"], a[href*="facebook.com"]').forEach((a) => { a.href = CONFIG.SOCIAL_FACEBOOK; });
        }
        if (CONFIG.SOCIAL_INSTAGRAM) {
          $$('[data-social="instagram"], a[href*="instagram.com"]').forEach((a) => { a.href = CONFIG.SOCIAL_INSTAGRAM; });
        }
      } catch (err) {
        Log.error('IntegrationsModule.initSocials failed', err);
      }
    },
  };

  /* ==============================================================
     32b. BANNERS MODULE (dynamic hero + floating imagery)
     Populates the homepage hero background/title/subtitle and any
     active floating banner images from GET /api/banners. Falls back
     silently to the static markup in index.html when the request
     fails or returns no active banners.
     ============================================================== */
  const BannersModule = {
    async init() {
      const hero = $('#hero');
      if (!hero) return; // only present on the home page
      try {
        const banners = await API.banners(true);
        if (!Array.isArray(banners) || !banners.length) return; // keep static fallback
        this.applyHero(banners);
        this.applyFloating(banners);
      } catch (err) {
        Log.warn('BannersModule: keeping static hero fallback', err);
      }
      refreshIcons();
    },

    _src: (b) => b.optimized_url || b.image_url || '',

    applyHero(banners) {
      const heroes = banners
        .filter((b) => (b.section_type || 'hero') === 'hero' && this._src(b))
        .sort((a, b) => (a.display_order || 0) - (b.display_order || 0));
      const hero = heroes[0];
      if (!hero) return;

      const img = $('#hero-bg-img');
      const src = this._src(hero);
      if (img && src) { img.src = src; img.alt = hero.title || 'Featured collection'; }

      // Apply copy only when the banner actually provides it, so any missing
      // field keeps the designed static fallback rather than going blank.
      const setText = (sel, val) => { const n = $(sel); if (n && val) n.textContent = val; };
      setText('#hero-title', hero.title);
      setText('#hero-subtitle', hero.subtitle);
      setText('#hero-eyebrow', hero.eyebrow);

      const cta = $('#hero-cta');
      if (cta && hero.cta_label) cta.innerHTML = `<i data-lucide="shopping-bag"></i> ${escapeHTML(hero.cta_label)}`;
      if (cta && hero.target_url && /^(https?:\/\/|\/)/.test(hero.target_url)) cta.setAttribute('href', hero.target_url);
    },

    applyFloating(banners) {
      const wrap = $('#hero-floating');
      if (!wrap) return;
      const floats = banners
        .filter((b) => b.section_type === 'floating' && this._src(b))
        .sort((a, b) => (a.display_order || 0) - (b.display_order || 0))
        .slice(0, 4);
      if (!floats.length) return;
      wrap.innerHTML = floats.map((b, i) => {
        const src = this._src(b);
        return `<img class="hero-float hero-float-${i + 1}" src="${escapeHTML(src)}" alt="${escapeHTML(b.title || '')}" loading="lazy" onerror="this.remove()">`;
      }).join('');
    },
  };

  /* ==============================================================
     32c. AI DESIGN STUDIO MODULE
     Ports the AI customizer UX: category selection → product picking →
     chat-driven generation against POST /api/ai/generate-customization.
     ============================================================== */
  const AI_CATEGORIES = Object.freeze([
    { value: 'sofa', label: 'Sofas & Seating' },
    { value: 'table', label: 'Tables & Desks' },
    { value: 'dining', label: 'Dining' },
    { value: 'bedroom', label: 'Bedroom' },
    { value: 'office', label: 'Office' },
    { value: 'finish', label: 'Home Finishes' },
    { value: 'decor', label: 'Decor & Accents' },
  ]);

  const AIModule = {
    state: { category: null, product: null, busy: false },

    async init() {
      if (!$('#ai')) return; // only present on the home page
      this.renderCategories();
      this.bind();
    },

    renderCategories() {
      const wrap = $('#ai-category-tabs');
      if (!wrap) return;
      wrap.innerHTML = AI_CATEGORIES.map((c, i) =>
        `<button type="button" class="ai-cat-tab${i === 0 ? ' active' : ''}" role="tab" aria-selected="${i === 0}" data-cat="${escapeHTML(c.value)}">${escapeHTML(c.label)}</button>`
      ).join('');
      this.selectCategory(AI_CATEGORIES[0].value);
    },

    bind() {
      on($('#ai-category-tabs'), 'click', (e) => {
        const btn = e.target.closest('[data-cat]');
        if (!btn) return;
        $$('#ai-category-tabs .ai-cat-tab').forEach((x) => { x.classList.remove('active'); x.setAttribute('aria-selected', 'false'); });
        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');
        this.selectCategory(btn.dataset.cat);
      });

      on($('#ai-product-picker'), 'click', (e) => {
        const card = e.target.closest('[data-ai-product]');
        if (!card) return;
        try { this.selectProduct(JSON.parse(card.dataset.aiProduct), card); }
        catch (err) { Log.error('AI product parse', err); }
      });

      on($('#ai-form'), 'submit', (e) => { e.preventDefault(); this.generate(); });

      // Enter submits; Shift+Enter for newline. Guard against CJK IME composition.
      on($('#ai-prompt'), 'keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
          e.preventDefault();
          this.generate();
        }
      });
    },

    async selectCategory(cat) {
      this.state.category = cat;
      const picker = $('#ai-product-picker');
      if (!picker) return;
      picker.innerHTML = Array.from({ length: 3 }).map(() => '<div class="skeleton skeleton-card"></div>').join('');
      try {
        const products = await API.products({ category: cat, limit: 12 });
        picker.innerHTML = products.length
          ? products.map((p) => this._pickCard(p)).join('')
          : UI.empty('package', 'Nothing here yet', 'No products in this category right now.');
      } catch (err) {
        Log.error('AI category load', err);
        picker.innerHTML = UI.empty('alert-triangle', 'Could not load products', err.message);
      }
      refreshIcons();
    },

    _pickCard(p) {
      const img = p.optimized_url || p.image_url || '';
      const payload = escapeHTML(JSON.stringify({ id: p.id, name: p.name, image_url: img, price: p.price, quantity: p.quantity }));
      return `
        <button type="button" class="ai-pick-card" data-ai-product="${payload}">
          <img src="${escapeHTML(img)}" alt="${escapeHTML(p.name)}" loading="lazy" onerror="this.style.visibility='hidden'">
          <span class="ai-pick-name">${escapeHTML(p.name)}</span>
        </button>`;
    },

    selectProduct(data, card) {
      this.state.product = data;
      $$('#ai-product-picker .ai-pick-card').forEach((x) => x.classList.remove('selected'));
      if (card) card.classList.add('selected');
      const sel = $('#ai-selected-product');
      if (sel) sel.innerHTML = `<i data-lucide="check-circle"></i><span>Customizing: <strong>${escapeHTML(data.name)}</strong></span>`;
      refreshIcons();
    },

    async generate() {
      if (this.state.busy) return;
      const ta = $('#ai-prompt');
      const prompt = sanitizeInput(ta && ta.value, 1000);
      if (!prompt) { Notify.warning('Describe the customization you want first.'); return; }

      // base_image_url is a required field server-side — the AI model transforms
      // an existing product photo, it doesn't generate one from nothing — so a
      // product must be selected before we can call the endpoint at all.
      const baseImageUrl = this.state.product && this.state.product.image_url;
      if (!baseImageUrl) {
        Notify.warning('Please pick a product above before generating a customization.');
        return;
      }

      if (!Auth.isAuthed()) {
        Notify.warning('Please sign in to use the AI Design Studio.');
        location.href = `${CONFIG.LOGIN_URL}?redirect=${encodeURIComponent(location.pathname)}`;
        return;
      }

      const product_context = `Product: ${this.state.product.name} (ID ${this.state.product.id})`;

      this._addMessage('user', prompt);
      if (ta) ta.value = '';
      this._setBusy(true);
      try {
        const res = await API.generateCustomization(prompt, baseImageUrl, product_context);
        const url = res && res.image_url;
        if (url) {
          this._renderResult(url, prompt);
          this._addMessage('ai', 'Here is your custom render — tweak the prompt to explore more options.');
        } else {
          this._resetResult();
          this._addMessage('ai', 'Sorry, no image came back. Please try again with a bit more detail.');
        }
      } catch (err) {
        Log.error('AI generate', err);
        this._resetResult();
        this._addMessage('ai', err.message || 'Failed to generate customization.');
        Notify.error(err.message || 'AI generation failed. Please try again.');
      } finally {
        this._setBusy(false);
      }
    },

    _addMessage(role, text) {
      const box = $('#ai-chat-messages');
      if (!box) return;
      const bubble = el('div', { class: `ai-msg ai-msg-${role}`, text });
      box.appendChild(bubble);
      box.scrollTop = box.scrollHeight;
    },

    _renderResult(url, caption) {
      const box = $('#ai-result');
      if (!box) return;
      const safe = escapeHTML(url);
      const product = this.state.product || {};
      // Mirrors CartItemSchema fields (product_id, quantity, is_customized,
      // customization_notes, custom_image_url) so Checkout's payload mapping
      // picks this line up correctly alongside ordinary cart items.
      const cartPayload = escapeHTML(JSON.stringify({
        id: product.id,
        name: product.name,
        price: product.price,
        image_url: product.image_url,
        quantity: product.quantity,
        is_customized: true,
        custom_image_url: url,
        customization_notes: caption || '',
      }));
      box.innerHTML = `
        <figure class="ai-render">
          <img src="${safe}" alt="AI customization preview${caption ? ': ' + escapeHTML(caption) : ''}" loading="lazy">
          <figcaption><a href="${safe}" target="_blank" rel="noopener"><i data-lucide="external-link"></i> Open full size</a></figcaption>
          <button type="button" class="btn btn-primary btn-sm ai-order-btn" data-add-to-cart="${cartPayload}">
            <i data-lucide="shopping-bag"></i> Order Custom Design
          </button>
        </figure>`;
      refreshIcons();
    },

    _resetResult() {
      const box = $('#ai-result');
      if (box && !$('.ai-render', box)) {
        box.innerHTML = '<div class="ai-result-placeholder"><i data-lucide="sparkles"></i><p>Your custom render will appear here.</p></div>';
        refreshIcons();
      }
    },

    _setBusy(busy) {
      this.state.busy = busy;
      const btn = $('#ai-send');
      if (btn) {
        btn.disabled = busy;
        btn.innerHTML = busy ? '<span class="spinner spinner-sm"></span> Generating…' : '<i data-lucide="sparkles"></i> Generate';
      }
      if (busy) {
        const box = $('#ai-result');
        if (box) box.innerHTML = '<div class="ai-result-placeholder"><span class="spinner"></span><p>Rendering your custom design…</p></div>';
      }
      refreshIcons();
    },
  };

  /* ==============================================================
     33. BOOTSTRAP + INITIALIZATION
     ============================================================== */
  const PAGE_MODULES = {
    home: [ProductsModule, BannersModule, AIModule],
    products: [ProductsModule],
    product: [ProductDetail],
    cart: [],                 // Cart itself is core-initialized below (needed on every page for the badge)
    checkout: [Checkout],
    orders: [OrdersModule],
    authentication: [],
    faq: [FaqModule],
    contact: [ContactModule],
  };

  const App = {
    async init() {
      // 1. Integrations & environment adaptation — must run first: LiveChat
      //    and socials depend on remote config, and the viewport fix needs
      //    to be in place before drawers/nav below rely on --vh sizing.
      await IntegrationsModule.fetchConfig();
      IntegrationsModule.initLiveChat();
      IntegrationsModule.initSocials();
      initMobileViewportFix();

      // 2. Core UI modules (all pages): auth hydration, managers, event bus
      Auth.hydrate();
      Cart.init();
      Modal.init(); Drawer.init(); Dropdown.init(); Tooltip.init();
      SiteNav.init(); TabController.init(); AccordionController.init();
      ErrorHandler.init();
      AuthModule.init(); // login/register/verify forms + logout wiring live on any page
      refreshIcons();

      // 3. Page-specific route resolution
      const page = document.body.dataset.page || 'home';
      Log.info('Initializing page:', page);

      const modules = PAGE_MODULES[page] || [];
      for (const mod of modules) {
        try { await mod.init?.(); }
        catch (e) { Log.error(`Module init failed on ${page}`, e); }
      }

      refreshIcons();
      EventBus.emit('app:ready', page);
    },
  };

  // Expose a minimal namespace for debugging / inline hooks
  window.RTR = Object.freeze({ API, Store, Auth, Cart, Notify, Modal, Drawer, EventBus, Fmt, CONFIG, IntegrationsModule });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => App.init());
  else App.init();
})();
