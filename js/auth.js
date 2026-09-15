/**
 * LOGVAULT — Operator Authentication & Access Control Module (SIH26156)
 * Dual-Theme Authentication Portal with Session Persistence, Clearance Presets & Instant Demo Access
 */

const AuthModule = {
  isAuthenticated: false,

  presets: {
    'amrita': {
      name: 'Agent Amrita',
      email: 'amrita.soc@logvault.sih',
      role: 'Tier-3 SOC Lead',
      tier: 'Tier-3 SOC Lead (Full Command Authority)',
      pass: 'CyberSecurity2026!'
    },
    'vikram': {
      name: 'Hunter Vikram',
      email: 'vikram.hunt@logvault.sih',
      role: 'Tier-2 Threat Hunter',
      tier: 'Tier-2 Senior Analyst (Triage & SOAR)',
      pass: 'ThreatHunter2026!'
    },
    'rajesh': {
      name: 'Commander Rajesh',
      email: 'rajesh.cmd@logvault.sih',
      role: 'Incident Commander',
      tier: 'Incident Commander (Executive Authority)',
      pass: 'Command2026!'
    },
    'sneha': {
      name: 'Analyst Sneha',
      email: 'sneha.triage@logvault.sih',
      role: 'Tier-1 Triage Analyst',
      tier: 'Tier-1 Security Analyst (Monitoring)',
      pass: 'TriageAnalyst2026!'
    }
  },

  init() {
    const urlParams = new URLSearchParams(window.location.search);
    const authParam = urlParams.get('auth') || urlParams.get('demo');
    const storedAuth = localStorage.getItem('logvault_authenticated');

    if (authParam === '1' || authParam === 'true' || authParam === 'demo') {
      this.isAuthenticated = true;
      localStorage.setItem('logvault_authenticated', 'true');
      localStorage.setItem('logvault_op_name', 'Agent Amrita');
      localStorage.setItem('logvault_op_role', 'Tier-3 SOC Lead');
    } else if (authParam === '0' || authParam === 'login') {
      this.isAuthenticated = false;
      localStorage.removeItem('logvault_authenticated');
    } else {
      this.isAuthenticated = storedAuth === 'true';
    }

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

    // Password visibility toggle
    const togglePwd = document.getElementById('login-toggle-pwd');
    if (togglePwd) {
      togglePwd.addEventListener('click', () => {
        const pwdInput = document.getElementById('login-operator-pwd');
        if (pwdInput) {
          const isPwd = pwdInput.type === 'password';
          pwdInput.type = isPwd ? 'text' : 'password';
          togglePwd.setAttribute('data-lucide', isPwd ? 'eye-off' : 'eye');
          if (window.lucide) lucide.createIcons();
        }
      });
    }

    // Clearance Preset Buttons
    document.querySelectorAll('.login-preset-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-preset');
        const p = this.presets[key];
        if (p) {
          document.querySelectorAll('.login-preset-chip').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');

          const emailInput = document.getElementById('login-operator-email');
          const pwdInput = document.getElementById('login-operator-pwd');
          const tierSelect = document.getElementById('login-operator-tier');

          if (emailInput) emailInput.value = p.email;
          if (pwdInput) pwdInput.value = p.pass;
          if (tierSelect) {
            for (let i = 0; i < tierSelect.options.length; i++) {
              if (tierSelect.options[i].text.includes(p.role) || tierSelect.options[i].value.includes(p.role.split(' ')[0])) {
                tierSelect.selectedIndex = i;
                break;
              }
            }
          }
          Utils.showToast(`Selected clearance preset: ${p.name} (${p.role})`, 'info');
        }
      });
    });
  },

  handleLogin() {
    const emailInput = document.getElementById('login-operator-email');
    const roleSelect = document.getElementById('login-operator-tier');
    const btn = document.getElementById('btn-submit-login');

    const email = emailInput ? emailInput.value.trim() : 'amrita.soc@logvault.sih';
    const role = roleSelect ? roleSelect.value : 'Tier-3 SOC Lead';
    const name = email.split('@')[0].replace('.', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase());

    if (btn) {
      btn.innerHTML = `<span class="auth-spinner"></span> Authenticating Air-Gapped Session...`;
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
