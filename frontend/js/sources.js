/**
 * LOGVAULT — Log Sources screen.
 * Built from /api/collectors (one row per host-or-IP and format) and /api/dashboard (timeline, formats).
 */

const SOURCE_COLORS = ['#74152A', '#9C1A30', '#C47A16', '#E09F3E', '#6E1B3E', '#B4233C', '#756568'];

const SourcesModule = {
  data: null,
  dash: null,
  pollTimer: null,

  init() {
    this.refresh();
  },

  onScreenOpen() {
    this.refresh();
    clearInterval(this.pollTimer);
    this.pollTimer = setInterval(() => {
      if (Navigation.activeScreen !== 'sources') {
        clearInterval(this.pollTimer);
        return;
      }
      if (!document.hidden) this.refresh();
    }, 10000);
  },

  async refresh(notify = false) {
    if (!window.LogVaultAPI) return;
    const [data, dash] = await Promise.all([LogVaultAPI.getCollectors(), LogVaultAPI.getDashboard()]);
    this.data = data;
    this.dash = dash;
    this.render();
    if (notify) Utils.showToast(data ? 'Sources refreshed.' : 'Backend unavailable.', data ? 'success' : 'error');
  },

  set(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  },

  render() {
    const d = this.data;
    if (!d) {
      this.set('sources-status-badge', '<span class="badge-dot"></span><span>Backend offline</span>');
      return;
    }
    const rows = d.collectors;
    const silent = rows.filter(r => r.status === 'SILENT').length;

    this.set('sources-status-badge', `<span class="badge-dot ${d.active_collectors ? 'green' : ''}"></span><span>${
      !rows.length ? 'No sources yet' : d.active_collectors ? `${d.active_collectors} sending now` : 'All sources quiet'}</span>`);
    this.set('src-kpi-sources', rows.length.toLocaleString());
    this.set('src-kpi-sources-sub', `<i data-lucide="layers"></i> ${d.formats.length} format${d.formats.length === 1 ? '' : 's'} &bull; ${d.total_events.toLocaleString()} events`);
    this.set('src-kpi-active', d.active_collectors.toLocaleString());
    this.set('src-kpi-active-sub', `<i data-lucide="clock"></i> ${rows.length - d.active_collectors - silent} idle &bull; ${silent} silent &gt;1 h`);
    this.set('src-kpi-rate', d.events_last_minute.toLocaleString());
    this.set('src-kpi-rate-sub', `<i data-lucide="database"></i> ${(d.events_last_minute / 60).toFixed(1)} events/sec average`);
    this.set('src-kpi-latency', d.avg_latency_ms < 10 ? d.avg_latency_ms.toFixed(3) : d.avg_latency_ms.toFixed(0));

    this.renderTimeline();
    this.renderFormatDonut();
    this.renderSourceBars();
    this.renderPipeline();
    this.renderLatencyBars();
    this.renderAnomalyBars();
    this.renderTable();
    if (window.lucide) lucide.createIcons();
  },

  // Events per time bucket (same buckets as the dashboard)
  renderTimeline() {
    const canvas = document.getElementById('sourcesThroughputCanvas');
    const tl = this.dash && this.dash.timeline;
    const buckets = (tl && tl.buckets) || [];
    const max = Math.max(0, ...buckets.map(b => b.events));
    const mins = tl && tl.bucket_seconds ? tl.bucket_seconds / 60 : 0;
    this.set('src-timeline-peak', max.toLocaleString());
    this.set('src-timeline-sub', mins ? `peak per ${mins >= 60 ? mins / 60 + ' h' : mins + ' min'}` : 'no events yet');
    this.set('src-timeline-badge', buckets.length ? `${buckets.length} buckets` : '&mdash;');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 75);
    if (!scaled) return;
    const { ctx, width: w, height: h } = scaled;
    ctx.clearRect(0, 0, w, h);
    if (!max) return;
    const pts = buckets.map((b, i) => ({ x: buckets.length === 1 ? w / 2 : i / (buckets.length - 1) * w, y: h - 4 - (b.events / max) * (h - 10) }));
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(180, 35, 60, 0.30)');
    grad.addColorStop(1, 'rgba(180, 35, 60, 0)');
    ctx.beginPath();
    Charts.smoothPath(ctx, pts);
    ctx.lineTo(pts[pts.length - 1].x, h);
    ctx.lineTo(pts[0].x, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.beginPath();
    Charts.smoothPath(ctx, pts);
    ctx.strokeStyle = '#B4233C';
    ctx.lineWidth = 2;
    ctx.stroke();
  },

  renderFormatDonut() {
    const formats = (this.dash && this.dash.formats) || [];
    this.set('src-format-count', `${formats.length} FORMAT${formats.length === 1 ? '' : 'S'}`);
    this.set('src-format-legend', formats.length ? formats.slice(0, 5).map((f, i) =>
      `<div><span style="color:${SOURCE_COLORS[i]}; font-weight:800;">●</span> ${Utils.escapeHtml(Charts.formatLabel(f.format))} (${f.pct}%)</div>`
    ).join('') + (formats.length > 5 ? `<div style="color:var(--text-muted);">+${formats.length - 5} more</div>` : '')
      : '<div style="color:var(--text-muted);">No events yet</div>');

    const canvas = document.getElementById('sourcesProtocolDonutCanvas');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 75);
    if (!scaled) return;
    const { ctx, width, height } = scaled;
    ctx.clearRect(0, 0, width, height);
    const total = formats.reduce((a, f) => a + f.count, 0);
    const cx = width / 2, cy = height / 2, r = Math.min(width, height) * 0.46, inner = r * 0.58;
    if (!total) return;
    let angle = -Math.PI / 2;
    formats.forEach((f, i) => {
      const slice = f.count / total * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.arc(cx, cy, inner, angle + slice, angle, true);
      ctx.closePath();
      ctx.fillStyle = SOURCE_COLORS[Math.min(i, SOURCE_COLORS.length - 1)];
      ctx.fill();
      angle += slice;
    });
  },

  // Events per origin (top 7), merged across formats
  topOrigins() {
    const byOrigin = {};
    (this.data ? this.data.collectors : []).forEach(r => {
      const o = byOrigin[r.origin] || (byOrigin[r.origin] = { origin: r.origin, events: 0, anomalies: 0 });
      o.events += r.events;
      o.anomalies += r.anomalies;
    });
    return Object.values(byOrigin).sort((a, b) => b.events - a.events);
  },

  renderSourceBars() {
    const top = this.topOrigins().slice(0, 7);
    this.set('src-bars-top', top.length ? top[0].events.toLocaleString() : '0');
    this.set('src-bars-top-name', top.length ? Utils.escapeHtml(top[0].origin) : '&mdash;');
    const canvas = document.getElementById('sourcesEpsBarsCanvas');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 75);
    if (!scaled) return;
    const { ctx, width: w, height: h } = scaled;
    ctx.clearRect(0, 0, w, h);
    if (!top.length) return;
    const max = top[0].events;
    const slot = w / top.length;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    ctx.font = '9px "JetBrains Mono", monospace';
    top.forEach((o, i) => {
      const bh = Math.max(2, (o.events / max) * (h - 18));
      ctx.fillStyle = o.anomalies ? '#B4233C' : (isDark ? '#E8A0AA' : '#74152A');
      ctx.fillRect(i * slot + slot * 0.18, h - 12 - bh, slot * 0.64, bh);
      ctx.fillStyle = isDark ? '#A89094' : '#756568';
      const label = o.origin.length > 8 ? o.origin.slice(0, 7) + '…' : o.origin;
      ctx.fillText(label, i * slot + 2, h - 2);
    });
  },

  renderPipeline() {
    const d = this.data, dash = this.dash;
    if (!d || !dash) return;
    const total = dash.total_events;
    const node = (title, sub, badge, cls, onclick) => `
      <div class="flowchart-node-card"${onclick ? ` onclick="${onclick}"` : ''}>
        <div class="flowchart-node-info">
          <span class="flowchart-node-title">${Utils.escapeHtml(title)}</span>
          <span class="flowchart-node-sub">${Utils.escapeHtml(sub)}</span>
        </div>
        <span class="flowchart-node-badge ${cls}">${Utils.escapeHtml(badge)}</span>
      </div>`;
    const stage = (title, badge, body) => `
      <div class="flowchart-stage-col">
        <div class="flowchart-stage-header"><span>${title}</span><span class="badge-pill green-pill" style="font-size:0.6rem;">${badge}</span></div>
        ${body || '<div class="flowchart-node-sub" style="padding:8px;">Nothing yet</div>'}
      </div>`;

    const origins = this.topOrigins();
    this._origins = origins;
    const s1 = origins.slice(0, 5).map((o, i) => node(o.origin, `${o.anomalies} anomalies`, o.events.toLocaleString(), o.anomalies ? 'cherry' : 'green',
      `SourcesModule.viewLogs(SourcesModule._origins[${i}].origin)`)).join('')
      + (origins.length > 5 ? `<div class="flowchart-node-sub" style="padding:4px 8px;">+${origins.length - 5} more</div>` : '');

    const detected = dash.formats.filter(f => f.format !== 'unknown');
    const unknown = dash.formats.find(f => f.format === 'unknown');
    const s2 = detected.slice(0, 5).map(f => node(Charts.formatLabel(f.format), `${f.pct}% of events`, f.count.toLocaleString(), 'green')).join('')
      + (unknown ? node('Not recognised', 'Map it in the AI Schema Mapper', unknown.count.toLocaleString(), 'gold', "Navigation.navigateTo('ai-mapper')") : '');

    const conf = dash.confidence;
    const s3 = node('Parsed', 'matched a parser', `${dash.parsed_rate}%`, 'green')
      + node('Mapped to OCSF class', 'class_uid assigned', `${conf.schema_mapping}%`, 'green')
      + node('Fields extracted', 'IP, user or host found', `${conf.field_extraction}%`, 'green')
      + node('Parser confidence', 'average', `${conf.parser}%`, 'green');

    const sev = dash.severities || {};
    const s4 = node('Anomalous', 'rule, entropy or AI finding', dash.anomalous_events.toLocaleString(), dash.anomalous_events ? 'cherry' : 'green', "Navigation.navigateTo('anomalies')")
      + node('Critical', 'threat score 80+ or CRITICAL', dash.critical_anomalies.toLocaleString(), dash.critical_anomalies ? 'cherry' : 'green', "Navigation.navigateTo('alerts')")
      + node('High severity', 'events', (sev.HIGH || 0).toLocaleString(), 'gold');

    const s5 = node('SQLite event store', 'normalized JSON + raw log', total.toLocaleString(), 'green', "Navigation.navigateTo('settings')")
      + node('Alert queue', 'anomalies awaiting triage', dash.anomalous_events.toLocaleString(), 'cherry', "Navigation.navigateTo('alerts')");

    this.set('sources-pipeline',
      stage('1. Sources', `${origins.length}`, s1)
      + stage('2. Format Detection', `${detected.length} formats`, s2)
      + stage('3. Parsing &amp; OCSF', `${dash.parsed_rate}%`, total ? s3 : '')
      + stage('4. Threat Detection', `${dash.anomalous_events}`, total ? s4 : '')
      + stage('5. Local Storage', 'SQLite', total ? s5 : ''));
  },

  barRow(name, detail, pct, value, color) {
    return `
      <div class="latency-bench-item" style="margin-bottom:10px;">
        <div style="min-width: 150px;">
          <span style="font-weight:800; color:var(--text-ink); display:block; font-size:0.74rem;">${Utils.escapeHtml(name)}</span>
          <span style="font-size:0.65rem; color:var(--text-muted); font-family:var(--font-mono);">${Utils.escapeHtml(detail)}</span>
        </div>
        <div class="latency-bench-bar-track" style="height:9px; background:var(--border-card);">
          <div class="latency-bench-bar-fill" style="width:${Math.max(1, Math.min(100, pct)).toFixed(1)}%; background-color:${color}; border-radius:4px;"></div>
        </div>
        <div style="min-width: 70px; text-align:right;">
          <span style="font-family:var(--font-mono); font-weight:800; color:${color}; font-size:0.75rem;">${value}</span>
        </div>
      </div>`;
  },

  renderLatencyBars() {
    const byFormat = {};
    (this.data ? this.data.collectors : []).forEach(r => {
      const f = byFormat[r.format] || (byFormat[r.format] = { format: r.format, events: 0, total: 0 });
      f.events += r.events;
      f.total += r.avg_latency_ms * r.events;
    });
    const list = Object.values(byFormat).map(f => ({ ...f, avg: f.events ? f.total / f.events : 0 })).sort((a, b) => b.avg - a.avg);
    const max = Math.max(0, ...list.map(f => f.avg));
    this.set('latency-benchmarks-container', list.length ? list.map(f =>
      this.barRow(Charts.formatLabel(f.format), `${f.events.toLocaleString()} records`, max ? f.avg / max * 100 : 0,
        `${f.avg < 10 ? f.avg.toFixed(3) : f.avg.toFixed(0)} ms`, f.avg > 1000 ? 'var(--status-amber)' : 'var(--status-green)')
    ).join('') + '<div class="storage-footnote">Records analysed by the local AI take seconds; rule-only records take well under a millisecond.</div>'
      : '<div class="analytics-empty">No events yet.</div>');
  },

  renderAnomalyBars() {
    const list = this.topOrigins().filter(o => o.events).sort((a, b) => (b.anomalies / b.events) - (a.anomalies / a.events) || b.anomalies - a.anomalies).slice(0, 7);
    this.set('buffer-saturation-container', list.length ? list.map(o => {
      const pct = o.anomalies / o.events * 100;
      return this.barRow(o.origin, `${o.anomalies} of ${o.events.toLocaleString()} events`, pct, `${pct.toFixed(1)}%`,
        pct >= 50 ? 'var(--cherry-primary)' : pct > 0 ? 'var(--status-amber)' : 'var(--status-green)');
    }).join('') : '<div class="analytics-empty">No events yet.</div>');
  },

  renderTable() {
    const tbody = document.getElementById('sources-fleet-tbody');
    if (!tbody) return;
    const rows = this.data ? this.data.collectors : [];
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:24px; color:var(--text-muted);">
        No logs received yet. Upload a file or paste a log in the Normalizer.</td></tr>`;
      return;
    }
    const statusPill = { ACTIVE: 'green-pill', IDLE: 'gold-pill', SILENT: 'warn-pill' };
    const isIp = v => /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.includes(':');
    tbody.innerHTML = rows.map((r, i) => {
      const origin = Utils.escapeHtml(r.origin);
      const kind = isIp(r.origin) ? 'ip' : 'host';
      const ref = `SourcesModule.data.collectors[${i}].origin`;
      const canContain = r.origin !== 'unattributed' && !r.contained;
      return `
        <tr>
          <td><strong>${origin}</strong>${r.contained ? ' <span class="badge-pill crit-pill" style="font-size:0.55rem;">CONTAINED</span>' : ''}
            <div style="font-size:0.62rem; color:var(--text-muted);">${r.distinct_source_ips} source IP${r.distinct_source_ips === 1 ? '' : 's'}</div></td>
          <td>${Utils.escapeHtml(Charts.formatLabel(r.format))}</td>
          <td style="font-family:var(--font-mono);">${r.events.toLocaleString()}</td>
          <td style="font-family:var(--font-mono);">${r.events_per_minute.toLocaleString()} / min</td>
          <td style="font-family:var(--font-mono); color:${r.anomalies ? 'var(--cherry-primary)' : 'inherit'};">${r.anomalies.toLocaleString()}</td>
          <td style="font-family:var(--font-mono);">${r.max_threat}</td>
          <td style="font-family:var(--font-mono); font-size:0.7rem;">${App.timeAgo(r.last_seen)}</td>
          <td><span class="badge-pill ${statusPill[r.status]}">${r.status}</span></td>
          <td style="white-space:nowrap;">
            <button class="btn-outline-cherry btn-sm" onclick="SourcesModule.viewLogs(${ref})">Logs</button>
            ${canContain ? `<button class="btn-cream-action btn-sm" onclick="SourcesModule.contain('${kind}', ${ref})">Contain</button>` : ''}
          </td>
        </tr>`;
    }).join('');
  },

  viewLogs(origin) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(origin)) {
      LogStream.filterByIp(origin);
      return;
    }
    const input = document.getElementById('stream-search-input');
    if (input) input.value = origin;
    LogStream.filters.searchQuery = origin.toLowerCase();
    LogStream.filterByIp('');
  },

  async contain(kind, value) {
    const reason = window.prompt(`Contain ${kind === 'ip' ? 'IP' : 'host'} ${value}?\n\nNew logs involving it will raise CRITICAL alerts, and it is added to the firewall export. Reason:`);
    if (reason === null) return;
    try {
      await LogVaultAPI.contain(kind, value, reason);
      Utils.showToast(`${value} contained.`, 'success');
      this.refresh();
    } catch (err) {
      Utils.showToast(`Could not contain: ${err.message}`, 'error');
    }
  }
};

window.SourcesModule = SourcesModule;
