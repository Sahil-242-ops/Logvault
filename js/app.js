/**
 * LOGVAULT — Core Application Controller (Stage 3 Masterpiece)
 * Global State, Theme Management, Perfect Omni-Search & Operator Profile Sync
 */

const App = {
  theme: 'cream',
  selectedPaletteIndex: 0,
  currentPaletteResults: [],

  init() {
    const urlParams = new URLSearchParams(window.location.search);
    const themeParam = urlParams.get('theme');
    this.theme = themeParam || localStorage.getItem('logvault_theme') || 'cream';
    this.applyTheme(this.theme);
    this.startClock();
    this.bindGlobalEvents();

    // Initialize Submodules
    if (window.AuthModule) AuthModule.init();
    if (window.Navigation) Navigation.init();
    if (window.LogStream) LogStream.init();
    if (window.Normalizer) Normalizer.init();
    if (window.AiMapper) AiMapper.init();
    if (window.AnomalyModule) AnomalyModule.init();
    if (window.AnalyticsModule) AnalyticsModule.init();
    if (window.SourcesModule) SourcesModule.init();
    if (window.ParsersModule) ParsersModule.init();
    if (window.TopologyModule) TopologyModule.init();
    if (window.SettingsModule) SettingsModule.init();
    if (window.Charts) {
      Charts.renderDashboardSpline();
      Charts.renderSparklines();
      Charts.renderEventDistributionDonut();
    }

    // Populate Dashboard Data
    this.renderDashboardElements();

    // Sync Operator Profile in Topbar
    if (window.SettingsModule) {
      SettingsModule.loadOperatorProfile();
    }

    console.log('LOGVAULT Core Initialized — Autonomous Normalizer & Heuristic Security Fleet Active');
  },

  applyTheme(theme) {
    this.theme = theme;
    localStorage.setItem('logvault_theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    document.body.className = theme === 'dark' ? 'theme-dark' : 'theme-cream';

    const btnLight = document.getElementById('btn-mode-light');
    const btnDark = document.getElementById('btn-mode-dark');
    if (btnLight && btnDark) {
      btnLight.classList.toggle('active', theme === 'cream');
      btnDark.classList.toggle('active', theme === 'dark');
    }

    setTimeout(() => {
      if (window.Charts && Navigation.activeScreen === 'dashboard') {
        Charts.renderDashboardSpline();
      }
    }, 40);
  },

  toggleTheme() {
    const next = this.theme === 'cream' ? 'dark' : 'cream';
    this.applyTheme(next);
    Utils.showToast(`Switched to ${next === 'cream' ? 'Warm Cream & Cherry' : 'Obsidian Dark'} theme`);
  },

  startClock() {
    const timeEl = document.getElementById('clock-time');
    const dateEl = document.getElementById('clock-date');
    const update = () => {
      const now = new Date();
      if (timeEl) timeEl.innerText = now.toLocaleTimeString('en-US', { hour12: true });
      if (dateEl) dateEl.innerText = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    };
    update();
    setInterval(update, 1000);
  },

  renderDashboardElements() {
    const tbody = document.getElementById('dashboard-recent-tbody');
    if (tbody && window.initialLiveLogs) {
      const top5 = window.initialLiveLogs.slice(0, 5);
      tbody.innerHTML = top5.map(log => {
        let sevBadge = `<span class="badge-pill crit-pill">CRITICAL</span>`;
        if (log.sev === 'HIGH') sevBadge = `<span class="badge-pill high-pill">HIGH</span>`;
        if (log.sev === 'MEDIUM') sevBadge = `<span class="badge-pill warn-pill">MEDIUM</span>`;
        if (log.sev === 'LOW' || log.sev === 'INFO') sevBadge = `<span class="badge-pill green-pill">${log.sev}</span>`;

        return `
          <tr onclick="Navigation.navigateTo('live-logs')">
            <td class="cell-mono-muted">${log.time}</td>
            <td><strong>${log.source}</strong></td>
            <td><code>${log.ip}</code></td>
            <td class="cell-truncate">${Utils.escapeHtml(log.msg)}</td>
            <td>${sevBadge}</td>
          </tr>
        `;
      }).join('');
    }
  },

  bindGlobalEvents() {
    // Theme toggle capsule
    const themeBtn = document.getElementById('mode-switch-capsule');
    if (themeBtn) {
      themeBtn.addEventListener('click', () => this.toggleTheme());
    }

    // Command palette triggers
    const searchBar = document.getElementById('header-search-bar');
    if (searchBar) {
      searchBar.addEventListener('click', () => this.openCommandPalette());
    }

    // Keyboard shortcuts & Navigation
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        this.openCommandPalette();
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 't') {
        e.preventDefault();
        this.toggleTheme();
      }

      const modal = document.getElementById('command-palette');
      if (modal && !modal.classList.contains('hidden')) {
        if (e.key === 'Escape') {
          this.closeCommandPalette();
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          this.movePaletteSelection(1);
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          this.movePaletteSelection(-1);
        } else if (e.key === 'Enter') {
          e.preventDefault();
          this.executeSelectedCommand();
        }
      }
    });

    // Window resize handler for chart responsiveness
    window.addEventListener('resize', () => {
      if (window.Charts && Navigation.activeScreen === 'dashboard') {
        Charts.renderDashboardSpline();
        Charts.renderSparklines();
      }
    });

    // Close operator menu dropdown on outside click
    document.addEventListener('click', (e) => {
      const pill = document.getElementById('analyst-profile-pill');
      if (pill && !pill.contains(e.target)) {
        this.closeOperatorMenu();
      }
    });
  },

  toggleOperatorMenu(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('operator-menu-dropdown');
    if (dropdown) {
      dropdown.classList.toggle('hidden');
      if (window.lucide) lucide.createIcons();
    }
  },

  closeOperatorMenu() {
    const dropdown = document.getElementById('operator-menu-dropdown');
    if (dropdown) {
      dropdown.classList.add('hidden');
    }
  },

  openCommandPalette() {
    const modal = document.getElementById('command-palette');
    const input = document.getElementById('palette-search-input');
    if (modal) modal.classList.remove('hidden');
    if (input) {
      input.value = '';
      input.focus();
      this.selectedPaletteIndex = 0;
      this.renderPaletteResults('');
    }
  },

  closeCommandPalette() {
    const modal = document.getElementById('command-palette');
    if (modal) modal.classList.add('hidden');
  },

  handlePaletteInput(val) {
    this.selectedPaletteIndex = 0;
    this.renderPaletteResults(val.toLowerCase().trim());
  },

  // PERFECT OMNI-SEARCH ACROSS SYSTEM
  renderPaletteResults(query) {
    const resultsContainer = document.getElementById('palette-results');
    if (!resultsContainer) return;

    // Omnipresent Knowledge Base & Search Index
    const allSearchItems = [
      // 1. Screens & Navigation
      { cat: 'Screens & Navigation', icon: 'layout-grid', label: 'Command Dashboard (Overview)', badge: 'SCREEN', action: () => Navigation.navigateTo('dashboard') },
      { cat: 'Screens & Navigation', icon: 'activity', label: 'Live Log Stream & Filter Engine', badge: 'SCREEN', action: () => Navigation.navigateTo('live-logs') },
      { cat: 'Screens & Navigation', icon: 'arrow-right-left', label: 'Log Normalizer & OCSF 1.1 Refinery', badge: 'SCREEN', action: () => Navigation.navigateTo('normalizer') },
      { cat: 'Screens & Navigation', icon: 'sparkles', label: 'Unknown Logs AI Schema Mapper', badge: 'SCREEN', action: () => Navigation.navigateTo('ai-mapper') },
      { cat: 'Screens & Navigation', icon: 'alert-triangle', label: 'Threat Anomalies & 3D Elevation', badge: 'SCREEN', action: () => Navigation.navigateTo('anomalies') },
      { cat: 'Screens & Navigation', icon: 'bell', label: 'Alert Center & Incident Triage', badge: 'SCREEN', action: () => Navigation.navigateTo('alerts') },
      { cat: 'Screens & Navigation', icon: 'pie-chart', label: 'Security Analytics & Geo Radar', badge: 'SCREEN', action: () => Navigation.navigateTo('analytics') },
      { cat: 'Screens & Navigation', icon: 'server', label: 'Sources Health & 3D Topology', badge: 'SCREEN', action: () => Navigation.navigateTo('sources') },
      { cat: 'Screens & Navigation', icon: 'cpu', label: 'Parser Engine Registry & Lab', badge: 'SCREEN', action: () => Navigation.navigateTo('parsers') },
      { cat: 'Screens & Navigation', icon: 'network', label: 'Network Topology Flow Mesh', badge: 'SCREEN', action: () => Navigation.navigateTo('topology') },
      { cat: 'Screens & Navigation', icon: 'settings', label: 'Platform Settings & Operator Profile', badge: 'SCREEN', action: () => Navigation.navigateTo('settings') },

      // 2. IP Addresses & Assets
      { cat: 'IP Addresses & Endpoints', icon: 'globe', label: '192.168.1.105 (Host server-01 sshd PAM)', badge: 'IP / HOST', action: () => { Navigation.navigateTo('live-logs'); Utils.showToast('Filtering for IP 192.168.1.105'); } },
      { cat: 'IP Addresses & Endpoints', icon: 'globe', label: '185.220.101.5 (Palo Alto NGFW Dropped Ingress)', badge: 'THREAT IP', action: () => { Navigation.navigateTo('normalizer'); Utils.showToast('Inspecting Palo Alto CEF event from 185.220.101.5'); } },
      { cat: 'IP Addresses & Endpoints', icon: 'globe', label: '10.0.0.15 (Internal Core App Node)', badge: 'ASSET IP', action: () => { Navigation.navigateTo('topology'); Utils.showToast('Navigated to Core App Subnet 10.0.2.0/24'); } },
      { cat: 'IP Addresses & Endpoints', icon: 'globe', label: '203.0.113.19 (AWS CloudTrail ConsoleLogin)', badge: 'CLOUD IP', action: () => { Navigation.navigateTo('normalizer'); } },
      { cat: 'IP Addresses & Endpoints', icon: 'globe', label: '172.16.4.18 (SCADA PLC Valve Controller)', badge: 'OT / IOT', action: () => { Navigation.navigateTo('ai-mapper'); } },

      // 3. OCSF Schema Classes
      { cat: 'OCSF 1.1 Schema Classes', icon: 'box', label: 'Class 3002: Authentication Activity', badge: 'OCSF SCHEMA', action: () => { Navigation.navigateTo('normalizer'); Utils.showToast('Loaded OCSF Class 3002 Authentication'); } },
      { cat: 'OCSF 1.1 Schema Classes', icon: 'box', label: 'Class 4001: Network Activity', badge: 'OCSF SCHEMA', action: () => { Navigation.navigateTo('normalizer'); Utils.showToast('Loaded OCSF Class 4001 Network Activity'); } },
      { cat: 'OCSF 1.1 Schema Classes', icon: 'box', label: 'Class 2001: Security Finding / IDS Alert', badge: 'OCSF SCHEMA', action: () => { Navigation.navigateTo('anomalies'); } },
      { cat: 'OCSF 1.1 Schema Classes', icon: 'box', label: 'Class 3001: Account Change Event', badge: 'OCSF SCHEMA', action: () => { Navigation.navigateTo('normalizer'); } },

      // 4. Quick Actions
      { cat: 'Quick Actions & Tools', icon: 'sun-moon', label: 'Toggle Light / Dark Theme', badge: 'ACTION', action: () => this.toggleTheme() },
      { cat: 'Quick Actions & Tools', icon: 'play', label: 'Toggle Live Ingestion Stream (Play/Pause)', badge: 'ACTION', action: () => LogStream.togglePlayPause() },
      { cat: 'Quick Actions & Tools', icon: 'download', label: 'Export Encrypted Forensic Bundle (.lvault)', badge: 'ACTION', action: () => { Navigation.navigateTo('settings'); setTimeout(() => document.getElementById('btn-export-forensic-bundle')?.click(), 200); } },
      { cat: 'Quick Actions & Tools', icon: 'zap', label: 'Execute Parser Sandbox Benchmark', badge: 'ACTION', action: () => { Navigation.navigateTo('parsers'); setTimeout(() => document.getElementById('btn-run-sandbox-bench')?.click(), 200); } },
      { cat: 'Quick Actions & Tools', icon: 'user', label: 'Edit Operator Identity & Credentials', badge: 'PROFILE', action: () => { Navigation.navigateTo('settings'); document.getElementById('operator-input-name')?.focus(); } }
    ];

    let filtered = allSearchItems;
    if (query) {
      filtered = allSearchItems.filter(item =>
        item.label.toLowerCase().includes(query) ||
        item.cat.toLowerCase().includes(query) ||
        item.badge.toLowerCase().includes(query)
      );
    }

    this.currentPaletteResults = filtered;

    if (filtered.length === 0) {
      resultsContainer.innerHTML = `
        <div style="padding:24px; text-align:center; color:var(--text-muted); font-size:0.80rem; font-family:var(--font-mono);">
          No matching commands, logs, IPs, or schemas found for "<strong>${Utils.escapeHtml(query)}</strong>"
        </div>
      `;
      return;
    }

    // Group by category
    const groups = {};
    filtered.forEach(item => {
      if (!groups[item.cat]) groups[item.cat] = [];
      groups[item.cat].push(item);
    });

    let overallIdx = 0;
    let html = '';

    for (const [catName, items] of Object.entries(groups)) {
      html += `<div class="palette-category-header">${catName}</div>`;
      items.forEach(item => {
        const isSelected = overallIdx === this.selectedPaletteIndex;
        const currentIdx = overallIdx;
        html += `
          <div class="palette-item ${isSelected ? 'active' : ''}" onclick="App.executeCommand(${currentIdx})">
            <div class="palette-item-left">
              <i data-lucide="${item.icon}"></i>
              <span style="font-weight:600; font-size:0.82rem;">${item.label}</span>
            </div>
            <span class="palette-result-badge">${item.badge}</span>
          </div>
        `;
        overallIdx++;
      });
    }

    resultsContainer.innerHTML = html;
    if (window.lucide) lucide.createIcons();
  },

  movePaletteSelection(delta) {
    if (this.currentPaletteResults.length === 0) return;
    this.selectedPaletteIndex = (this.selectedPaletteIndex + delta + this.currentPaletteResults.length) % this.currentPaletteResults.length;
    this.updatePaletteSelectionVisuals();
  },

  updatePaletteSelectionVisuals() {
    const items = document.querySelectorAll('.palette-item');
    items.forEach((el, idx) => {
      el.classList.toggle('active', idx === this.selectedPaletteIndex);
      if (idx === this.selectedPaletteIndex) {
        el.scrollIntoView({ block: 'nearest' });
      }
    });
  },

  executeSelectedCommand() {
    if (this.currentPaletteResults[this.selectedPaletteIndex]) {
      this.executeCommand(this.selectedPaletteIndex);
    }
  },

  executeCommand(idx) {
    const cmd = this.currentPaletteResults[idx];
    if (cmd && cmd.action) {
      this.closeCommandPalette();
      cmd.action();
    }
  }
};

window.App = App;

// Bootstrap application on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
