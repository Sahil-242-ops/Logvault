/**
 * LOGVAULT — Live Log Stream Module
 * High-performance real-time telemetry streaming simulation & filtering
 */

const LogStream = {
  logs: [],
  filteredLogs: [],
  isPlaying: true,
  streamSpeed: 1000, // ms per tick
  timerId: null,
  selectedLogId: null,
  filters: {
    source: 'ALL',
    severity: 'ALL',
    timeRange: '1h',
    searchQuery: ''
  },
  totalProcessedCount: 1284,

  // Stream generator templates for realistic SIEM telemetry
  templates: [
    { source: 'FIREWALL', action: 'BLOCKED', ip: '192.168.1.20', user: 'system', sev: 'HIGH', msg: 'Port scan probe blocked on perimeter interface eth0' },
    { source: 'SSH', action: 'LOGIN_FAIL', ip: '10.24.8.12', user: 'root', sev: 'MEDIUM', msg: 'Failed password for root via SSH port 58921 (attempt 4/5)' },
    { source: 'WINDOWS', action: 'PROCESS', ip: '10.0.3.14', user: 'workstation-04', sev: 'LOW', msg: 'Process spawned: powershell.exe -NonInteractive -ExecutionPolicy Bypass' },
    { source: 'AWS', action: 'AUTH_SUCCESS', ip: '198.51.100.4', user: 'user@company.com', sev: 'INFO', msg: 'ConsoleLogin: MFA verification successful from trusted origin' },
    { source: 'SSH', action: 'LOGIN_FAIL', ip: '10.24.8.12', user: 'admin', sev: 'MEDIUM', msg: 'Failed password for admin via SSH port 58920 (attempt 3/5)' },
    { source: 'LINUX', action: 'LOGIN', ip: '192.168.1.20', user: 'john', sev: 'INFO', msg: 'Accepted publickey for john from 192.168.1.20 port 54210 ssh2' },
    { source: 'APACHE', action: 'HTTP_401', ip: '192.168.1.45', user: 'apache-admin2', sev: 'HIGH', msg: 'POST /api/v1/auth/login returned HTTP 401 Unauthorized (invalid JWT)' },
    { source: 'OKTA', action: 'SSO_CHALLENGE', ip: '203.0.113.78', user: 'amrita.lead', sev: 'LOW', msg: 'FIDO2 WebAuthn authentication challenge completed' },
    { source: 'FIREWALL', action: 'DROP', ip: '185.220.101.5', user: 'anonymous', sev: 'CRITICAL', msg: 'ACL Drop: Tor Exit Relay IP attempting ingress on port 3389' },
    { source: 'SURICATA', action: 'ALERT', ip: '192.168.1.45', user: 'Server01', sev: 'CRITICAL', msg: 'ET SCAN Potential SSH Brute Force Attack detected (4,821 attempts)' },
    { source: 'KUBERNETES', action: 'POD_EXEC', ip: '10.244.0.15', user: 'kube-admin', sev: 'MEDIUM', msg: 'kubectl exec session opened on pod payment-gateway-7b9f' },
    { source: 'DNS', action: 'QUERY_DGA', ip: '192.168.1.88', user: 'finance-host', sev: 'HIGH', msg: 'Anomalous high-entropy DNS query: xk92jfnso821b.corp-cdn.net' }
  ],

  init() {
    this.logs = [...window.initialLiveLogs];
    this.applyFilters();
    this.bindEvents();
    this.startStreaming();
  },

  onScreenOpen() {
    this.render();
  },

  bindEvents() {
    // Play / Pause
    const playPauseBtn = document.getElementById('btn-stream-playpause');
    if (playPauseBtn) {
      playPauseBtn.addEventListener('click', () => this.togglePlayPause());
    }

    // Speed selector
    const speedSelect = document.getElementById('stream-speed-select');
    if (speedSelect) {
      speedSelect.addEventListener('change', (e) => {
        this.streamSpeed = parseInt(e.target.value, 10);
        this.restartStreaming();
        Utils.showToast(`Stream rate set to ${e.target.options[e.target.selectedIndex].text}`);
      });
    }

    // Filter by Source
    const sourceFilter = document.getElementById('stream-filter-source');
    if (sourceFilter) {
      sourceFilter.addEventListener('change', (e) => {
        this.filters.source = e.target.value;
        this.applyFilters();
      });
    }

    // Filter by Severity
    const sevFilter = document.getElementById('stream-filter-severity');
    if (sevFilter) {
      sevFilter.addEventListener('change', (e) => {
        this.filters.severity = e.target.value;
        this.applyFilters();
      });
    }

    // Filter by Time Range
    const timeFilter = document.getElementById('stream-filter-timerange');
    if (timeFilter) {
      timeFilter.addEventListener('change', (e) => {
        this.filters.timeRange = e.target.value;
        this.applyFilters();
      });
    }

    // Search query input
    const searchInput = document.getElementById('stream-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.filters.searchQuery = e.target.value.toLowerCase().trim();
        this.applyFilters();
      });
    }

    // Clear buffer button
    const clearBtn = document.getElementById('btn-clear-stream');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        this.logs = [];
        this.applyFilters();
        Utils.showToast('Live stream buffer cleared.');
      });
    }
  },

  togglePlayPause() {
    this.isPlaying = !this.isPlaying;
    const btn = document.getElementById('btn-stream-playpause');
    const badge = document.getElementById('stream-live-badge');

    if (btn) {
      btn.innerHTML = this.isPlaying
        ? `<i data-lucide="pause"></i><span>Pause Stream</span>`
        : `<i data-lucide="play"></i><span>Resume Stream</span>`;
    }

    if (badge) {
      badge.className = this.isPlaying ? 'live-indicator-badge live' : 'live-indicator-badge paused';
      badge.innerHTML = this.isPlaying ? '<span class="pulse-dot"></span> LIVE STREAM' : '<span class="paused-dot"></span> STREAM PAUSED';
    }

    if (this.isPlaying) {
      this.startStreaming();
      Utils.showToast('Resumed live log telemetry stream.');
    } else {
      this.stopStreaming();
      Utils.showToast('Live log telemetry stream paused.');
    }

    if (window.lucide) lucide.createIcons();
  },

  startStreaming() {
    this.stopStreaming();
    this.timerId = setInterval(() => {
      this.generateLiveLog();
    }, this.streamSpeed);
  },

  stopStreaming() {
    if (this.timerId) {
      clearInterval(this.timerId);
      this.timerId = null;
    }
  },

  restartStreaming() {
    if (this.isPlaying) {
      this.startStreaming();
    }
  },

  generateLiveLog() {
    const template = this.templates[Math.floor(Math.random() * this.templates.length)];
    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

    const newLog = {
      id: Date.now() + Math.floor(Math.random() * 100),
      time: timeStr,
      source: template.source,
      action: template.action,
      ip: template.ip,
      user: template.user,
      sev: template.sev,
      msg: template.msg,
      isNew: true
    };

    this.logs.unshift(newLog);
    this.totalProcessedCount++;

    // Limit buffer to latest 100 logs in memory
    if (this.logs.length > 100) {
      this.logs.pop();
    }

    this.applyFilters();
  },

  applyFilters() {
    this.filteredLogs = this.logs.filter(log => {
      if (this.filters.source !== 'ALL' && log.source !== this.filters.source) return false;
      if (this.filters.severity !== 'ALL' && log.sev !== this.filters.severity) return false;
      if (this.filters.searchQuery) {
        const text = `${log.time} ${log.source} ${log.action} ${log.ip} ${log.user} ${log.sev} ${log.msg}`.toLowerCase();
        if (!text.includes(this.filters.searchQuery)) return false;
      }
      return true;
    });

    this.render();
  },

  render() {
    const tbody = document.getElementById('live-stream-tbody');
    const countEl = document.getElementById('stream-showing-count');
    const totalEl = document.getElementById('stream-total-count');

    if (countEl) countEl.innerText = this.filteredLogs.length;
    if (totalEl) totalEl.innerText = this.totalProcessedCount.toLocaleString();

    if (!tbody) return;

    if (this.filteredLogs.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-table-state">
            <i data-lucide="filter-x"></i>
            <p>No log events match your current filter criteria.</p>
            <button class="btn-sm btn-outline-cherry" onclick="LogStream.resetFilters()">Reset Filters</button>
          </td>
        </tr>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    tbody.innerHTML = this.filteredLogs.map(log => {
      let sevClass = 'sev-info';
      if (log.sev === 'CRITICAL') sevClass = 'sev-critical';
      else if (log.sev === 'HIGH') sevClass = 'sev-high';
      else if (log.sev === 'MEDIUM') sevClass = 'sev-medium';
      else if (log.sev === 'LOW') sevClass = 'sev-low';

      const isSelected = log.id === this.selectedLogId;

      return `
        <tr class="log-row ${isSelected ? 'selected' : ''} ${log.isNew ? 'row-just-added' : ''}" onclick="LogStream.selectRow(${log.id})">
          <td class="cell-time">${log.time}</td>
          <td class="cell-source"><span class="source-tag">${log.source}</span></td>
          <td class="cell-action"><code>${log.action}</code></td>
          <td class="cell-ip"><code>${log.ip}</code></td>
          <td class="cell-user">${log.user}</td>
          <td class="cell-sev"><span class="sev-badge ${sevClass}">${log.sev}</span></td>
          <td class="cell-msg">
            <div class="msg-content-flex">
              <span class="msg-text">${Utils.escapeHtml(log.msg)}</span>
              <button class="btn-micro-normalize" title="Send to Visual Normalizer" onclick="event.stopPropagation(); LogStream.sendToNormalizer(${log.id})">
                <i data-lucide="arrow-right-left"></i> Normalize
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Remove isNew animation flag
    setTimeout(() => {
      this.logs.forEach(l => l.isNew = false);
    }, 400);

    this.renderTerminalView();
    this.renderLiveSparkline();

    if (window.lucide) lucide.createIcons();
  },

  renderTerminalView() {
    const termBody = document.getElementById('log-terminal-stream-body');
    if (!termBody) return;
    const lines = this.logs.slice(0, 15).map(log => {
      let cls = 'info';
      if (['CRITICAL', 'HIGH'].includes(log.sev)) cls = 'error';
      else if (log.sev === 'MEDIUM') cls = 'warn';
      const label = cls === 'error' ? 'Error' : (cls === 'warn' ? 'Warn ' : 'INFO ');
      return `<div class="term-line ${cls}">${label} | 2026-09-02:${log.time} - ${Utils.escapeHtml(log.source)}:${Utils.escapeHtml(log.action)} from ${Utils.escapeHtml(log.ip)} - ${Utils.escapeHtml(log.msg)}</div>`;
    }).join('');
    termBody.innerHTML = lines;
  },

  renderLiveSparkline() {
    const canvas = document.getElementById('liveSpeedSparkCanvas');
    if (!canvas) return;

    const scaled = Utils.setupHiDPICanvas(canvas, 42);
    if (!scaled) return;
    const { ctx, width: w, height: h } = scaled;

    ctx.clearRect(0, 0, w, h);

    const pts = [h*0.75, h*0.5, h*0.8, h*0.35, h*0.65, h*0.25, h*0.55, h*0.3, h*0.6, h*0.15];
    ctx.beginPath();
    ctx.moveTo(0, pts[0]);
    pts.forEach((y, i) => {
      ctx.lineTo((w / (pts.length - 1)) * i, y);
    });
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();

    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(180, 35, 60, 0.35)');
    grad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(0, pts[0]);
    pts.forEach((y, i) => {
      ctx.lineTo((w / (pts.length - 1)) * i, y);
    });
    ctx.strokeStyle = '#B4233C';
    ctx.lineWidth = 2.2;
    ctx.stroke();

    const lastX = w - 4;
    const lastY = pts[pts.length - 1];
    ctx.beginPath();
    ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#B4233C';
    ctx.fill();
    ctx.strokeStyle = '#FFF8F0';
    ctx.lineWidth = 1.8;
    ctx.stroke();
  },

  selectRow(id) {
    this.selectedLogId = id;
    this.render();
  },

  resetFilters() {
    this.filters.source = 'ALL';
    this.filters.severity = 'ALL';
    this.filters.searchQuery = '';
    const srcSelect = document.getElementById('stream-filter-source');
    const sevSelect = document.getElementById('stream-filter-severity');
    const searchInput = document.getElementById('stream-search-input');
    if (srcSelect) srcSelect.value = 'ALL';
    if (sevSelect) sevSelect.value = 'ALL';
    if (searchInput) searchInput.value = '';
    this.applyFilters();
    Utils.showToast('Reset all stream filters.');
  },

  sendToNormalizer(logId) {
    const log = this.logs.find(l => l.id === logId);
    if (!log) return;

    // Switch to normalizer screen with raw log loaded
    const rawString = `${log.time} ${log.source} [pid:1042] ${log.action} user=${log.user} src=${log.ip} msg="${log.msg}"`;
    Navigation.navigateTo('normalizer');
    if (window.Normalizer) {
      Normalizer.loadRawCustomInput(rawString);
    }
    Utils.showToast(`Ingested log #${logId} into Visual Normalizer.`);
  }
};

window.LogStream = LogStream;
