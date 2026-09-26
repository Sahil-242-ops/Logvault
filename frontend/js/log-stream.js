/**
 * LOGVAULT — Live Log Stream Module
 * Polls stored events from the backend and filters them by format, severity, time, IP and text
 */

const LogStream = {
  logs: [],
  filteredLogs: [],
  isPlaying: true,
  streamSpeed: 2000, // poll interval (ms)
  timerId: null,
  selectedLogId: null,
  filters: {
    source: 'ALL',
    severity: 'ALL',
    timeRange: 'all',
    searchQuery: '',
    sourceIp: ''
  },
  totalProcessedCount: 0,
  sparkHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  lastFetchTime: Date.now(),
  lastProcessedCount: 0,
  currentEps: 0,

  async init() {
    this.logs = [];
    this.bindEvents();
    if (window.LogVaultAPI && LogVaultAPI._backendAvailable === null) {
      await LogVaultAPI.checkBackend();
    }
    await this.fetchRealEvents();
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
        Utils.showToast(e.target.options[e.target.selectedIndex].text);
      });
    }

    // Filter by Source
    const sourceFilter = document.getElementById('stream-filter-source');
    if (sourceFilter) {
      sourceFilter.addEventListener('change', (e) => {
        this.filters.source = e.target.value;
        this.fetchRealEvents();
      });
    }

    // Filter by Severity
    const sevFilter = document.getElementById('stream-filter-severity');
    if (sevFilter) {
      sevFilter.addEventListener('change', (e) => {
        this.filters.severity = e.target.value;
        this.fetchRealEvents();
      });
    }

    // Filter by Time Range
    const timeFilter = document.getElementById('stream-filter-timerange');
    if (timeFilter) {
      timeFilter.addEventListener('change', (e) => {
        this.filters.timeRange = e.target.value;
        this.fetchRealEvents();
      });
    }

    // Search query input
    const searchInput = document.getElementById('stream-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.filters.searchQuery = e.target.value.toLowerCase().trim();
        this.fetchRealEvents();
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

  // Source filter lists the formats actually present in stored events
  async loadFormatOptions() {
    const now = Date.now();
    if (this._formatsLoadedAt && now - this._formatsLoadedAt < 15000) return;
    this._formatsLoadedAt = now;
    const d = await LogVaultAPI.getDashboard();
    const select = document.getElementById('stream-filter-source');
    if (!d || !select) return;
    const current = this.filters.source;
    select.innerHTML = '<option value="ALL">All Formats</option>' + d.formats.map(f =>
      `<option value="${Utils.escapeHtml(f.format)}">${Utils.escapeHtml(window.Charts ? Charts.formatLabel(f.format) : f.format)} (${f.count.toLocaleString()})</option>`
    ).join('');
    select.value = d.formats.some(f => f.format === current) ? current : 'ALL';
  },

  // Show only events from one source IP (used by alerts, sources and the command palette)
  filterByIp(ip) {
    this.filters.sourceIp = ip || '';
    const input = document.getElementById('stream-search-input');
    if (input) input.value = '';
    this.filters.searchQuery = '';
    const badge = document.getElementById('stream-ip-filter-badge');
    if (badge) {
      badge.style.display = ip ? 'inline-flex' : 'none';
      badge.innerHTML = ip ? `IP ${Utils.escapeHtml(ip)} <span style="cursor:pointer; margin-left:6px;" onclick="LogStream.filterByIp('')">&times;</span>` : '';
    }
    if (window.Navigation) Navigation.navigateTo('live-logs');
    this.fetchRealEvents();
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
    this.fetchRealEvents();
    // Default max speed is 2000ms minimum to not hammer the backend
    const pollSpeed = Math.max(2000, this.streamSpeed);
    this.timerId = setInterval(() => {
      this.fetchRealEvents();
    }, pollSpeed);
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

  async fetchRealEvents() {
    if (!window.LogVaultAPI) return;
    if (LogVaultAPI._backendAvailable === null) {
      await LogVaultAPI.checkBackend();
    }
    if (!LogVaultAPI.isBackendAvailable()) return;
    
    const since = { '15m': 15, '1h': 60, '24h': 1440 }[this.filters.timeRange] || null;
    const result = await LogVaultAPI.getEvents(100, 0, this.filters.searchQuery, this.filters.severity,
      this.filters.source, this.filters.sourceIp, since);
    this.loadFormatOptions();
    
    const backendBadge = document.getElementById('stream-backend-badge');
    if (backendBadge) {
      backendBadge.className = LogVaultAPI.isBackendAvailable() ? 'badge-pill green-pill' : 'badge-pill crit-pill';
      backendBadge.textContent = LogVaultAPI.isBackendAvailable() ? 'Online' : 'Offline';
    }
    if (result && result.events) {
      const lat = result.events.map(e => e.processing_latency_ms).filter(v => typeof v === 'number');
      const latEl = document.getElementById('stream-latency');
      if (latEl) latEl.textContent = lat.length ? `${(lat.reduce((a, v) => a + v, 0) / lat.length).toFixed(2)} ms / record` : '—';
      const existingIds = new Set(this.logs.map(l => l.id));
      let newCount = 0;
      
      const mappedEvents = result.events.map(evt => {
        const isNew = !existingIds.has(evt.id);
        if (isNew) newCount++;

        let formattedTime = new Date().toLocaleTimeString();
        if (evt.timestamp) {
          if (evt.timestamp.includes('T')) {
            const parts = evt.timestamp.split('T');
            formattedTime = `${parts[0]} ${(parts[1] || '').split('.')[0]}`;
          } else {
            formattedTime = evt.timestamp;
          }
        }

        return {
          id: evt.id,
          time: formattedTime,
          source: evt.detected_format || 'unknown',
          action: evt.event_type || 'EVENT',
          ip: evt.source_ip || evt.destination_ip || 'N/A',
          user: evt.user || 'N/A',
          sev: evt.severity || 'INFO',
          msg: evt.message || evt.raw_log || '',
          isNew: isNew,
          raw: evt.raw_log
        };
      });

      this.logs = mappedEvents;
      const newTotal = result.total !== undefined ? result.total : mappedEvents.length;

      // Calculate real throughput (EPS) based on actual events arriving
      const now = Date.now();
      const elapsedSec = Math.max(1, (now - this.lastFetchTime) / 1000);
      const deltaLogs = Math.max(0, newTotal - (this.lastProcessedCount || 0));
      if (this.lastProcessedCount > 0 && deltaLogs > 0) {
        this.currentEps = Math.round((deltaLogs / elapsedSec) * 10) / 10;
      } else if (newTotal === 0) {
        this.currentEps = 0;
      }

      this.totalProcessedCount = newTotal;
      this.lastProcessedCount = newTotal;
      this.lastFetchTime = now;

      // Push real rate to sparkline history
      this.sparkHistory.push(this.currentEps);
      if (this.sparkHistory.length > 12) this.sparkHistory.shift();

      this.applyFilters();
    }
  },

  applyFilters() {
    this.filteredLogs = this.logs.filter(log => {
      if (this.filters.source !== 'ALL' && log.source !== this.filters.source) return false;
      if (this.filters.sourceIp && log.ip !== this.filters.sourceIp) return false;
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
    const processedCountEl = document.getElementById('stream-processed-count');
    const processedLabelEl = document.getElementById('stream-processed-label');
    const liveEpsValEl = document.getElementById('stream-live-eps-val');
    const liveEpsBadgeEl = document.getElementById('stream-live-eps-badge');
    const cardIngestedEl = document.getElementById('stream-card-ingested');
    const throughputEl = document.getElementById('stream-throughput');
    const hdrThroughputEl = document.getElementById('hdr-throughput');

    if (countEl) countEl.innerText = this.filteredLogs.length;
    if (totalEl) totalEl.innerText = this.totalProcessedCount.toLocaleString();

    // Image 1: Show proper real count of logs processed (no random numbers)
    if (processedCountEl) {
      processedCountEl.innerText = this.totalProcessedCount.toLocaleString();
    }
    if (processedLabelEl) {
      processedLabelEl.innerText = this.totalProcessedCount === 1 ? 'log processed' : 'logs processed';
    }

    const epsStr = this.currentEps > 0 ? this.currentEps.toFixed(1) : '0.0';
    if (liveEpsValEl) liveEpsValEl.innerText = epsStr;
    if (liveEpsBadgeEl) {
      if (this.currentEps > 0) {
        liveEpsBadgeEl.className = 'badge-pill green-pill';
        liveEpsBadgeEl.innerHTML = `<span class="pulse-dot"></span> <span>${epsStr}</span> EPS`;
      } else {
        liveEpsBadgeEl.className = 'badge-pill';
        liveEpsBadgeEl.innerHTML = `<span class="paused-dot"></span> <span>0.0</span> EPS`;
      }
    }

    // Image 2: update Stream Details card INGESTED metric cleanly
    if (cardIngestedEl) {
      cardIngestedEl.innerText = `${this.totalProcessedCount.toLocaleString()} logs (Session)`;
    }

    if (throughputEl) {
      throughputEl.innerText = this.currentEps > 0 ? `${epsStr} logs/sec` : `${this.totalProcessedCount} total`;
    }
    if (hdrThroughputEl) {
      hdrThroughputEl.innerText = this.totalProcessedCount > 0 ? `${this.totalProcessedCount} logs` : '0 logs (Idle)';
    }

    // Correlated alerts badge & count
    const alertsCountEl = document.getElementById('stream-correlated-alerts-count');
    const alertsBadgeEl = document.getElementById('stream-correlated-alerts-badge');
    const critLogs = this.logs.filter(l => l.sev === 'CRITICAL' || l.sev === 'HIGH').length;
    if (alertsCountEl) alertsCountEl.innerText = critLogs.toString();
    if (alertsBadgeEl) {
      alertsBadgeEl.innerText = `${critLogs} Active`;
      alertsBadgeEl.className = critLogs > 0 ? 'badge-pill crit-pill' : 'badge-pill green-pill';
    }

    if (!tbody) return;

    if (this.filteredLogs.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-table-state">
            <div class="empty-state-box">
              <i data-lucide="filter" style="width:28px; height:28px; color:var(--text-muted); margin-bottom:8px;"></i>
              <div style="font-weight:700; font-size:0.88rem; color:var(--text-ink); margin-bottom:4px;">No Log Events Found</div>
              <p style="font-size:0.75rem; color:var(--text-muted); margin-bottom:10px;">No events currently match your filter criteria.</p>
              <button class="btn-sm btn-outline-cherry" onclick="LogStream.resetFilters()">Reset Filters</button>
            </div>
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
      return `<div class="term-line ${cls}">${label} | ${log.time} - ${Utils.escapeHtml(log.source)}:${Utils.escapeHtml(log.action)} from ${Utils.escapeHtml(log.ip)} - ${Utils.escapeHtml(log.msg)}</div>`;
    }).join('');
    termBody.innerHTML = lines;
  },

  renderLiveSparkline() {
    const container = document.getElementById('liveSpeedSparkContainer');
    const canvas = document.getElementById('liveSpeedSparkCanvas');

    const history = this.sparkHistory && this.sparkHistory.length > 0 ? this.sparkHistory : [0, 0, 0, 0, 0, 0, 0, 0];
    const maxVal = Math.max(1, ...history);
    const hasActivity = maxVal > 0 && history.some(v => v > 0);
    const w = 240;
    const h = 42;

    // Map history to Y coordinates
    const pts = history.map((v, i) => {
      const x = Math.round((w / Math.max(1, history.length - 1)) * i);
      const normalized = hasActivity ? Math.min(1, v / maxVal) : 0;
      const y = Math.round(hasActivity ? ((h - 8) - (normalized * (h - 18))) : (h - 6));
      return { x, y };
    });

    const pathD = pts.map((p, i) => (i === 0 ? `M ${p.x} ${p.y}` : `L ${p.x} ${p.y}`)).join(' ');
    const areaD = `${pathD} L ${w} ${h} L 0 ${h} Z`;
    const lastPt = pts[pts.length - 1];

    const strokeColor = hasActivity ? '#B4233C' : '#8A7A7D';
    const gradStart = hasActivity ? 'rgba(180, 35, 60, 0.35)' : 'rgba(180, 35, 60, 0.08)';

    if (container) {
      container.innerHTML = `
        <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%; height:100%; display:block;">
          <defs>
            <linearGradient id="liveSpeedSparkGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="${gradStart}" />
              <stop offset="100%" stop-color="rgba(180, 35, 60, 0.0)" />
            </linearGradient>
          </defs>
          <path d="${areaD}" fill="url(#liveSpeedSparkGrad)" />
          <path d="${pathD}" fill="none" stroke="${strokeColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          <circle cx="${lastPt.x - 2}" cy="${lastPt.y}" r="3.5" fill="${strokeColor}" stroke="#FFF8F0" stroke-width="1.5" />
        </svg>
      `;
      return;
    }

    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 42);
    if (!scaled) return;
    const { ctx, width: cw, height: ch } = scaled;
    ctx.clearRect(0, 0, cw, ch);
  },

  selectRow(id) {
    this.selectedLogId = id;
    this.render();
  },

  resetFilters() {
    this.filters.source = 'ALL';
    this.filters.severity = 'ALL';
    this.filters.searchQuery = '';
    this.filters.sourceIp = '';
    this.filters.timeRange = 'all';
    const tr = document.getElementById('stream-filter-timerange');
    if (tr) tr.value = 'all';
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
