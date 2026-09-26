/**
 * LOGVAULT — Operator sign-in.
 * Credentials are checked by the backend (PBKDF2-hashed passwords); it returns a session token that
 * js/api.js attaches to every API call. The operator's role comes from their account, not the browser.
 */

const AuthModule = {
  isAuthenticated: false,
  operator: null,

  // Quick-fill buttons for the evaluation accounts the backend creates on first start
  presets: {
    sahil: { email: 'sahil.soc@logvault.sih', pass: 'CyberSecurity2026!' },
    vikram: { email: 'vikram.hunt@logvault.sih', pass: 'ThreatHunter2026!' },
    rajesh: { email: 'rajesh.cmd@logvault.sih', pass: 'Command2026!' },
    sneha: { email: 'sneha.triage@logvault.sih', pass: 'TriageAnalyst2026!' }
  },

  getToken() {
    return sessionStorage.getItem('logvault_token') || localStorage.getItem('logvault_token');
  },

  storeSession(session, remember) {
    this.clearToken();
    (remember ? localStorage : sessionStorage).setItem('logvault_token', session.token);
    this.setOperator(session.operator);
  },

  clearToken() {
    sessionStorage.removeItem('logvault_token');
    localStorage.removeItem('logvault_token');
  },

  // Keep the profile keys other modules read for display
  setOperator(op) {
    this.operator = op;
    if (!op) return;
    localStorage.setItem('logvault_op_name', op.name);
    localStorage.setItem('logvault_op_role', op.role);
    localStorage.setItem('logvault_op_email', op.email);
    localStorage.setItem('logvault_op_callsign', op.callsign || '');
    localStorage.setItem('logvault_op_org', op.org || '');
  },

  async init() {
    this.bindEvents();
    const params = new URLSearchParams(window.location.search);
    const authParam = params.get('auth') || params.get('demo');

    // Drop the parameter so a reload does not repeat it
    if (authParam) {
      params.delete('auth');
      params.delete('demo');
      const qs = params.toString();
      history.replaceState(null, '', location.pathname + (qs ? `?${qs}` : '') + location.hash);
    }

    if (authParam === '0' || authParam === 'login') {
      await this.logout(false);
      return;
    }

    if (this.getToken()) {
      try {
        this.setOperator(await LogVaultAPI.me());
        this.isAuthenticated = true;
        this.renderAuthState();
        if (window.SettingsModule) SettingsModule.loadOperatorProfile();
        if (window.App) App.renderDashboardElements();
        return;
      } catch {
        this.clearToken();
      }
    }

    if (authParam === '1' || authParam === 'true' || authParam === 'demo') {
      await this.handleDemoLogin();
      return;
    }
    this.isAuthenticated = false;
    this.renderAuthState();
    this.loadAuthConfig();
  },

  async loadAuthConfig() {
    try {
      const cfg = await LogVaultAPI.getAuthConfig();
      const demoBtn = document.getElementById('btn-instant-demo-login');
      const divider = document.querySelector('.login-demo-divider');
      if (!cfg.demo_login) {
        if (demoBtn) demoBtn.style.display = 'none';
        if (divider) divider.style.display = 'none';
      }
    } catch {
      this.showError('Backend unreachable. Start the LOGVAULT server, then reload this page.');
    }
  },

  renderAuthState() {
    const loginOverlay = document.getElementById('logvault-login-overlay');
    const mainApp = document.querySelector('.logvault-app');
    if (!loginOverlay) return;

    if (this.isAuthenticated) {
      loginOverlay.classList.add('auth-hidden');
      if (mainApp) mainApp.classList.remove('blurred-state');
    } else {
      loginOverlay.classList.remove('auth-hidden');
      if (mainApp) mainApp.classList.add('blurred-state');
    }
    if (window.lucide) lucide.createIcons();
  },

  showError(msg) {
    const el = document.getElementById('login-error');
    if (!el) return;
    el.textContent = msg || '';
    el.style.display = msg ? 'block' : 'none';
  },

  bindEvents() {
    const form = document.getElementById('logvault-login-form');
    if (form) {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        this.handleLogin();
      });
    }

    const demoBtn = document.getElementById('btn-instant-demo-login');
    if (demoBtn) demoBtn.addEventListener('click', () => this.handleDemoLogin());

    const logoutBtn = document.getElementById('btn-operator-logout');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.logout();
      });
    }

    // Delegated: lucide replaces the <i> with an <svg>, which drops listeners bound to the original element
    document.addEventListener('click', (e) => {
      const toggle = e.target.closest('#login-toggle-pwd');
      const pwdInput = document.getElementById('login-operator-pwd');
      if (!toggle || !pwdInput) return;
      const show = pwdInput.type === 'password';
      pwdInput.type = show ? 'text' : 'password';
      const icon = document.createElement('i');
      icon.id = 'login-toggle-pwd';
      icon.className = 'login-field-icon-right';
      icon.title = show ? 'Hide password' : 'Show password';
      icon.setAttribute('data-lucide', show ? 'eye-off' : 'eye');
      toggle.replaceWith(icon);
      if (window.lucide) lucide.createIcons();
    });

    document.querySelectorAll('.login-preset-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        const p = this.presets[btn.getAttribute('data-preset')];
        if (!p) return;
        document.querySelectorAll('.login-preset-chip').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const emailInput = document.getElementById('login-operator-email');
        const pwdInput = document.getElementById('login-operator-pwd');
        if (emailInput) emailInput.value = p.email;
        if (pwdInput) pwdInput.value = p.pass;
        this.showError('');
      });
    });
  },

  async handleLogin() {
    const email = (document.getElementById('login-operator-email') || {}).value || '';
    const password = (document.getElementById('login-operator-pwd') || {}).value || '';
    const remember = !!(document.getElementById('login-remember-me') || {}).checked;
    const btn = document.getElementById('btn-submit-login');
    const original = btn ? btn.innerHTML : '';

    this.showError('');
    if (btn) {
      btn.innerHTML = '<span class="auth-spinner"></span> Checking credentials...';
      btn.disabled = true;
    }
    try {
      const session = await LogVaultAPI.login(email.trim(), password);
      this.storeSession(session, remember);
      this.loginSuccess();
    } catch (err) {
      this.showError(err.message === 'Failed to fetch' ? 'Backend unreachable.' : err.message);
      if (btn) {
        btn.innerHTML = original;
        btn.disabled = false;
      }
    }
  },

  async handleDemoLogin() {
    const demoBtn = document.getElementById('btn-instant-demo-login');
    if (demoBtn) demoBtn.disabled = true;
    try {
      const session = await LogVaultAPI.demoLogin();
      this.storeSession(session, false);
      this.loginSuccess();
    } catch (err) {
      this.isAuthenticated = false;
      this.renderAuthState();
      this.showError(err.message);
      if (demoBtn) demoBtn.disabled = false;
    }
  },

  // Reload so every screen fetches its data with the new session
  loginSuccess() {
    this.isAuthenticated = true;
    location.reload();
  },

  // Called by the fetch wrapper when the backend answers 401
  sessionExpired() {
    if (!this.isAuthenticated && !this.getToken()) {
      this.renderAuthState();
      return;
    }
    this.isAuthenticated = false;
    this.clearToken();
    this.renderAuthState();
    this.showError('Your session ended. Please sign in again.');
  },

  async logout(notify = true) {
    if (this.getToken()) await LogVaultAPI.logout();
    this.clearToken();
    this.isAuthenticated = false;
    this.operator = null;
    this.renderAuthState();
    this.loadAuthConfig();
    if (notify && window.Utils) Utils.showToast('Signed out.', 'info');
  },

  hasRank(minRank) {
    const ranks = { 'Tier-1 Security Analyst': 1, 'Tier-2 Senior Analyst': 2, 'Tier-3 SOC Lead': 3, 'Incident Commander': 3 };
    return !!this.operator && (ranks[this.operator.role] || 0) >= minRank;
  }
};

window.AuthModule = AuthModule;
