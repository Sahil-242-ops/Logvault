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
    // Populate Dashboard Data (KPIs + charts), refreshed while the dashboard is open
    this.renderDashboardElements();
    setInterval(() => {
      if (window.Navigation && Navigation.activeScreen === 'dashboard' && window.AuthModule && AuthModule.isAuthenticated
          && !document.hidden) {
        this.renderDashboardElements();
      }
    }, 10000);

    // Sync Operator Profile in Topbar
    if (window.SettingsModule) {
      SettingsModule.loadOperatorProfile();
    }

    // Probe backend API & Local AI status
    this.probeBackend();

    console.log('LOGVAULT SOC Engine Initialized — Ingestion Pipeline & Normalization Fleet Active');
  },

  async probeBackend(retriesLeft = 24) {
    if (!window.LogVaultAPI) return;
    const isRetry = retriesLeft < 24;

    const health = await LogVaultAPI.checkBackend();
    const statusEl = document.getElementById('lv-system-status-badge');

    if (health) {
      // Update AI status indicator
      if (statusEl) {
        const aiMode = health.ai_status_message || 'LOCAL AI OFFLINE';
        const modelInfo = health.model || 'NONE';
        statusEl.innerHTML = `<span class="pulse-dot"></span> ${aiMode} · ${modelInfo}`;
        statusEl.className = health.local_ai ? 'badge-pill green-pill' : 'badge-pill warn-pill';
        statusEl.title = `Status: ${aiMode} | Provider: ${health.ai_provider || 'NONE'} | Model: ${health.model || 'NONE'} | Network: ${health.network_mode.toUpperCase()}`;
      }
      if (!isRetry || health.local_ai) {
        Utils.showToast(`✓ Backend online — ${health.ai_status_message || 'AI OFFLINE'} · Network: AIR-GAPPED`, 'success');
      }
      // Model warms up in the background; keep re-checking (every 5s, ~2 min) until it's ready
      if (!health.local_ai && retriesLeft > 0) {
        setTimeout(() => this.probeBackend(retriesLeft - 1), 5000);
      }
    } else if (isRetry) {
      return;
    } else {
      if (statusEl) {
        statusEl.innerHTML = `<span class="pulse-dot"></span> OFFLINE`;
        statusEl.className = 'badge-pill crit-pill';
        statusEl.title = 'Python Backend Offline.';
      }
      Utils.showToast('⚠ Python Backend Offline. Start FastAPI on port 8000.', 'error');
    }
  },

  applyTheme(theme) {
    this.theme = theme;
    localStorage.setItem('logvault_theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    document.body.className = theme === 'dark' ? 'theme-dark' : 'theme-cream';

    const btnLight = document.getElementById('btn-mode-light');
    const btnDark = document.getElementById('btn-mode-dark');
    if (btnLight) btnLight.classList.toggle('active', theme === 'cream');
    if (btnDark) btnDark.classList.toggle('active', theme === 'dark');

    // Universal Screen Re-render upon Theme Change
    setTimeout(() => {
      const active = window.Navigation ? Navigation.activeScreen : 'dashboard';
      if (active === 'dashboard' && window.Charts) {
        Charts.renderDashboardSpline();
        Charts.renderSparklines();
        Charts.renderEventDistributionDonut();
      } else if (active === 'analytics' && window.AnalyticsModule) {
        AnalyticsModule.onScreenOpen();
      } else if (active === 'sources' && window.SourcesModule) {
        SourcesModule.onScreenOpen();
      } else if (active === 'parsers' && window.ParsersModule) {
        ParsersModule.onScreenOpen();
      } else if (active === 'topology' && window.TopologyModule) {
        TopologyModule.onScreenOpen();
      } else if (active === 'anomalies' && window.AnomalyModule) {
        AnomalyModule.onScreenOpen('anomalies');
      } else if (active === 'alerts' && window.AnomalyModule) {
        AnomalyModule.onScreenOpen('alerts');
      } else if (active === 'normalizer' && window.Normalizer) {
        Normalizer.onScreenOpen();
      } else if (active === 'ai-mapper' && window.AiMapper) {
        AiMapper.onScreenOpen();
      } else if (active === 'settings' && window.SettingsModule) {
        SettingsModule.onScreenOpen();
      }
    }, 50);
  },

  setTheme(theme) {
    this.applyTheme(theme);
    if (window.Utils && Utils.showToast) {
      Utils.showToast(`Theme: ${theme === 'cream' ? 'Warm Cream & Cherry' : 'Obsidian Dark'}`);
    }
  },

  toggleTheme() {
    const next = this.theme === 'cream' ? 'dark' : 'cream';
    this.setTheme(next);
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

  async renderDashboardElements() {
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

    // Greeting by local time and signed-in operator
    const hour = new Date().getHours();
    const part = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
    const opName = (window.AuthModule && AuthModule.operator && AuthModule.operator.name) || localStorage.getItem('logvault_op_name');
    set('dash-greeting', `${part}, ${Utils.escapeHtml(opName || 'Security Team')}`);

    // 1. KPIs, charts, format split and threat feed from /api/dashboard
    const d = window.LogVaultAPI ? await LogVaultAPI.getDashboard() : null;
    if (window.Charts) {
      Charts.data = d;
      Charts.renderAll();
    }
    if (d) {
      const total = d.total_events;
      set('kpi-logs-processed', total.toLocaleString());
      set('kpi-norm-rate', `${d.parsed_rate}%`);
      set('kpi-norm-caption', `<i data-lucide="check-circle-2"></i> ${d.parsed_events.toLocaleString()} of ${total.toLocaleString()} matched a parser`);
      set('kpi-suspicious-count', d.anomalous_events.toLocaleString());
      set('kpi-anomalies-count', d.critical_anomalies.toLocaleString());
      set('kpi-logs-caption', total
        ? `<i data-lucide="gauge"></i> Avg ${d.avg_latency_ms} ms per record`
        : '<i data-lucide="trending-up"></i> Stored this session');
      set('hdr-throughput', total ? `${total.toLocaleString()} logs processed` : 'No events processed');

      const tl = d.timeline || {};
      const bucketMin = tl.bucket_seconds ? Math.round(tl.bucket_seconds / 60) : 0;
      set('dash-activity-sub', bucketMin
        ? `Events per ${bucketMin >= 60 ? `${bucketMin / 60} h` : `${bucketMin} min`} (solid) and anomalies (dashed)`
        : 'Events stored over time (solid) and anomalies (dashed)');
      const lastBucket = (tl.buckets || []).slice(-1)[0];
      set('dash-ingest-badge', `<span class="badge-dot cherry" style="width:5px;height:5px;"></span>${
        !total ? 'No events yet' : lastBucket && lastBucket.events ? 'Ingestion active' : 'Idle'}`);
      set('dash-parsed-badge', `<span class="badge-dot green" style="width:5px;height:5px;"></span>Parsed ${d.parsed_rate}%`);

      const segments = Charts.formatSegments();
      set('donut-center-count', String(d.formats.filter(f => f.format !== 'unknown').length));
      set('format-dist-legend', segments.length ? segments.map(seg => `
        <div class="event-legend-row" title="${seg.count.toLocaleString()} events">
          <div class="legend-label-group">
            <span class="legend-color-dot" style="background-color: ${seg.color};"></span>
            <span>${Utils.escapeHtml(seg.label)}</span>
          </div>
          <strong>${seg.pct}%</strong>
        </div>`).join('') : '<div class="event-legend-row"><span style="color:var(--text-muted);">No events yet</span></div>');

      const sevClass = { CRITICAL: 'crit-pill', HIGH: 'high-pill', MEDIUM: 'warn-pill' };
      this.recentThreats = d.recent_threats;
      set('dash-threat-feed', d.recent_threats.length ? d.recent_threats.map((t, i) => {
        const who = [t.source_ip, t.host, t.user].filter(v => v && !['unknown', 'none', '-'].includes(String(v).toLowerCase()));
        return `
        <div class="threat-card-item" onclick="App.openThreat(${i})">
          <div class="threat-card-head">
            <span class="threat-card-title">${Utils.escapeHtml(t.title)}</span>
            <span class="badge-pill ${sevClass[t.severity] || 'green-pill'}">${Utils.escapeHtml(t.severity || 'INFO')}</span>
          </div>
          <div class="threat-card-ip">${Utils.escapeHtml(who.join(' • ') || 'No source identified')}</div>
          <div class="threat-card-time">Threat score ${t.threat_score ?? 0} &bull; ${Utils.escapeHtml(t.status)} &bull; ${this.timeAgo(t.received_at)}</div>
        </div>`;
      }).join('') : '<div class="threat-card-item"><div class="threat-card-time">No anomalies detected yet</div></div>');
      if (window.lucide) lucide.createIcons();
    }

    // 2. Recent events table
    const tbody = document.getElementById('dashboard-recent-tbody');
    if (!tbody) return;

    if (window.LogVaultAPI) {
      try {
        const res = await LogVaultAPI.getEvents(5, 0);
        if (res && res.events && res.events.length > 0) {
          tbody.innerHTML = res.events.map(log => {
            let sevBadge = `<span class="badge-pill crit-pill">CRITICAL</span>`;
            const sev = (log.severity || 'INFO').toUpperCase();
            if (sev === 'HIGH') sevBadge = `<span class="badge-pill high-pill">HIGH</span>`;
            if (sev === 'MEDIUM') sevBadge = `<span class="badge-pill warn-pill">MEDIUM</span>`;
            if (sev === 'LOW' || sev === 'INFO') sevBadge = `<span class="badge-pill green-pill">${sev}</span>`;

            return `
              <tr onclick="Navigation.navigateTo('live-logs')">
                <td class="cell-mono-muted">${Utils.escapeHtml(log.timestamp || '-')}</td>
                <td><strong>${Utils.escapeHtml(log.parser_name || 'SYSTEM')}</strong></td>
                <td><code>${Utils.escapeHtml(log.source_ip || '-')}</code></td>
                <td class="cell-truncate">${Utils.escapeHtml(log.message || log.raw_log || '')}</td>
                <td>${sevBadge}</td>
              </tr>
            `;
          }).join('');
          return;
        }
      } catch (e) {
        console.error('Error fetching recent events:', e);
      }
    }
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 24px; color: var(--text-muted);">No events processed</td></tr>';
  },

  openThreat(i) {
    const t = (this.recentThreats || [])[i];
    if (!t) return;
    AnomalyModule.activeIncidentId = t.id;
    Navigation.navigateTo('anomalies');
  },

  timeAgo(iso) {
    if (!iso) return 'unknown time';
    const sec = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.round(sec / 60)} min ago`;
    if (sec < 86400) return `${Math.round(sec / 3600)} h ago`;
    return `${Math.round(sec / 86400)} d ago`;
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
    // Refresh the IP list in the background, then re-render with the current query
    if (window.LogVaultAPI) {
      LogVaultAPI.getSources().then(res => {
        this.paletteSources = (res.sources || [])
          .sort((x, y) => (y.anomaly_count - x.anomaly_count) || (y.event_count - x.event_count))
          .slice(0, 8);
        if (modal && !modal.classList.contains('hidden')) {
          this.renderPaletteResults((input ? input.value : '').toLowerCase().trim());
        }
      });
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

      // 2. Source IPs seen in stored events (loaded when the palette opens)
      ...(this.paletteSources || []).map(src => ({
        cat: 'Source IPs In Your Data', icon: 'globe',
        label: `${src.source_ip} (${src.event_count.toLocaleString()} events, ${src.anomaly_count} anomalies)`,
        badge: src.anomaly_count ? 'THREAT IP' : 'IP',
        action: () => LogStream.filterByIp(src.source_ip)
      })),

      // 3. OCSF schema
      { cat: 'OCSF 1.1 Schema Classes', icon: 'download', label: 'Download OCSF 1.1 definitions used by LOGVAULT', badge: 'DOWNLOAD', action: () => LogVaultAPI.download('/api/export/ocsf', 'logvault-ocsf.json').catch(e => Utils.showToast(e.message, 'error')) },

      // 4. Quick Actions
      { cat: 'Quick Actions & Tools', icon: 'sun-moon', label: 'Toggle Light / Dark Theme', badge: 'ACTION', action: () => this.toggleTheme() },
      { cat: 'Quick Actions & Tools', icon: 'play', label: 'Toggle Live Ingestion Stream (Play/Pause)', badge: 'ACTION', action: () => LogStream.togglePlayPause() },
      { cat: 'Quick Actions & Tools', icon: 'download', label: 'Export Forensic Evidence Bundle (.zip + SHA-256 manifest)', badge: 'ACTION', action: () => { Navigation.navigateTo('settings'); setTimeout(() => document.getElementById('btn-export-forensic-bundle')?.click(), 200); } },
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
