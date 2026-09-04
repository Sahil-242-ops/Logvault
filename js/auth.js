/**
 * LOGVAULT — Operator Authentication & Access Control Module (SIH26156)
 * Dual-Theme Authentication Portal with Session Persistence & Instant Demo Access
 */

const AuthModule = {
  isAuthenticated: false,

  init() {
    // Check persisted session
    const storedAuth = localStorage.getItem('logvault_authenticated');
    this.isAuthenticated = storedAuth === 'true';

    this.renderAuthState();
    this.bindEvents();
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

    if (window.lucide) {
      lucide.createIcons();
    }
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
    if (demoBtn) {
      demoBtn.addEventListener('click', () => {
        this.handleDemoLogin();
      });
    }

    const logoutBtn = document.getElementById('btn-operator-logout');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.logout();
      });
    }
  },

  handleLogin() {
    const emailInput = document.getElementById('login-operator-email');
    const roleSelect = document.getElementById('login-operator-tier');
    const btn = document.getElementById('btn-submit-login');

    const email = emailInput ? emailInput.value.trim() : 'amrita.soc@logvault.sih';
    const role = roleSelect ? roleSelect.value : 'Tier-3 SOC Lead';
    const name = email.split('@')[0].replace('.', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase());

    if (btn) {
      btn.innerHTML = `<span class="auth-spinner"></span> Authenticating Telemetry Node...`;
      btn.disabled = true;
    }

    setTimeout(() => {
      this.loginSuccess(name, role);
      if (btn) {
        btn.innerHTML = `<i data-lucide="shield-check"></i> Access Granted`;
        btn.disabled = false;
      }
    }, 600);
  },

  handleDemoLogin() {
    const demoBtn = document.getElementById('btn-instant-demo-login');
    if (demoBtn) {
      demoBtn.innerHTML = `⚡ Unlocking SOC Command Center...`;
    }

    setTimeout(() => {
      this.loginSuccess('Agent Amrita', 'Tier-3 SOC Lead');
      if (demoBtn) {
        demoBtn.innerHTML = `⚡ Instant Demo Access (Tier-3 SOC Lead)`;
      }
    }, 300);
  },

  loginSuccess(name, role) {
    this.isAuthenticated = true;
    localStorage.setItem('logvault_authenticated', 'true');
    localStorage.setItem('logvault_op_name', name);
    localStorage.setItem('logvault_op_role', role);

    if (window.SettingsModule) {
      SettingsModule.loadOperatorProfile();
    }

    this.renderAuthState();
    Utils.showToast(`✓ Access Granted: Session Authenticated for ${name} (${role})`, 'success');

    // Trigger chart resize & icon refresh
    setTimeout(() => {
      if (window.Charts && window.Navigation && Navigation.activeScreen === 'dashboard') {
        Charts.renderDashboardSpline();
        Charts.renderSparklines();
        Charts.renderEventDistributionDonut();
      }
      if (window.lucide) lucide.createIcons();
    }, 150);
  },

  logout() {
    this.isAuthenticated = false;
    localStorage.removeItem('logvault_authenticated');
    this.renderAuthState();
    Utils.showToast('🔒 Operator Session Locked. Please re-authenticate.', 'info');
  }
};

window.AuthModule = AuthModule;
