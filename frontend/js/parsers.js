/**
 * LOGVAULT — Parser Registry & Test Lab.
 * Catalog and usage from /api/parsers; speeds measured by /api/parsers/benchmark on the backend.
 */

const ParsersModule = {
  currentCategory: 'all',
  searchQuery: '',
  parsers: [],
  usage: null,
  speeds: {},        // parser id -> benchmark result on its own sample
  measuring: false,

  init() {
    this.bindEvents();
  },

  onScreenOpen() {
    this.refresh(false);
  },

  bindEvents() {
    document.querySelectorAll('.parser-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.parser-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentCategory = btn.getAttribute('data-cat');
        this.renderCatalog();
      });
    });
    const search = document.getElementById('parser-catalog-search');
    if (search) {
      search.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.renderCatalog();
      });
    }
    const runBtn = document.getElementById('btn-run-sandbox-bench');
    if (runBtn) runBtn.addEventListener('click', () => this.runSandboxBenchmark());
  },

  async refresh(remeasure) {
    const res = await LogVaultAPI.getParsers();
    if (!res) {
      Utils.showToast('Backend unavailable: parser registry not loaded.', 'error');
      return;
    }
    this.parsers = res.parsers;
    this.usage = res;
    if (remeasure) this.speeds = {};
    this.renderKpis();
    this.renderUsageBars();
    this.renderSandboxControls();
    this.renderCatalog();
    this.measureAll();
  },

  renderKpis() {
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    const builtin = this.parsers.filter(p => p.kind === 'BUILT-IN').length;
    const rules = this.parsers.length - builtin;
    set('parsers-count-badge', `${this.parsers.length} PARSERS`);
    set('parsers-kpi-count', String(this.parsers.length));
    set('parsers-kpi-count-sub', `<i data-lucide="check"></i> ${builtin} built-in &bull; ${rules} mapping rule${rules === 1 ? '' : 's'}`);
    const total = this.usage.total_events;
    const parsed = total - this.usage.unparsed_events;
    set('parsers-kpi-parsed', total ? `${(parsed / total * 100).toFixed(1)}%` : '&mdash;');
    set('parsers-kpi-parsed-sub', `<i data-lucide="database"></i> ${parsed.toLocaleString()} of ${total.toLocaleString()} events`);
    LogVaultAPI.getDashboard().then(d => {
      if (d) set('parsers-kpi-ocsf', d.total_events ? `${d.confidence.schema_mapping}%` : '&mdash;');
    });
    if (window.lucide) lucide.createIcons();
  },

  barRow(name, detail, pct, value, color) {
    return `
      <div class="latency-bench-item" style="margin-bottom:10px;">
        <div style="min-width: 170px;">
          <span style="font-weight:800; color:var(--text-ink); display:block; font-size:0.74rem;">${Utils.escapeHtml(name)}</span>
          <span style="font-size:0.65rem; color:var(--text-muted); font-family:var(--font-mono);">${detail}</span>
        </div>
        <div class="latency-bench-bar-track" style="height:9px; background:var(--border-card);">
          <div class="latency-bench-bar-fill" style="width:${Math.max(1, Math.min(100, pct)).toFixed(1)}%; background-color:${color}; border-radius:4px;"></div>
        </div>
        <div style="min-width: 90px; text-align:right;">
          <span style="font-family:var(--font-mono); font-weight:800; color:${color}; font-size:0.75rem;">${value}</span>
        </div>
      </div>`;
  },

  // Benchmark every parser on its own sample record, one after another
  async measureAll() {
    if (this.measuring) return;
    this.measuring = true;
    try {
      for (const p of this.parsers) {
        if (this.speeds[p.id] || !p.sample) continue;
        try {
          this.speeds[p.id] = await LogVaultAPI.benchmarkParser(p.sample, p.id);
        } catch {
          this.speeds[p.id] = null;
        }
        this.renderSpeedBars();
      }
    } finally {
      this.measuring = false;
    }
    this.renderSpeedBars();
    this.renderCatalog();
  },

  renderSpeedBars() {
    const el = document.getElementById('parsers-speed-bars');
    if (!el) return;
    const measured = this.parsers.map(p => ({ p, r: this.speeds[p.id] })).filter(x => x.r && x.r.matched)
      .sort((a, b) => b.r.records_per_second - a.r.records_per_second);
    if (!measured.length) {
      el.innerHTML = '<div class="analytics-empty">Measuring&hellip;</div>';
      return;
    }
    const max = measured[0].r.records_per_second;
    el.innerHTML = measured.map(({ p, r }) => this.barRow(p.name,
      `${r.median_us.toLocaleString()} µs median &bull; p95 ${r.p95_us.toLocaleString()} µs`,
      r.records_per_second / max * 100, `${Charts.compact(r.records_per_second)}/s`,
      p.kind === 'BUILT-IN' ? 'var(--status-green)' : 'var(--cherry-primary)')).join('');

    const fastest = measured[0];
    const set = (id, html) => { const e = document.getElementById(id); if (e) e.innerHTML = html; };
    set('parsers-kpi-fastest', `${fastest.r.median_us} <small style="font-size:0.75rem;">µs</small>`);
    set('parsers-kpi-fastest-sub', `<i data-lucide="gauge"></i> ${Utils.escapeHtml(fastest.p.name)} &bull; ${Charts.compact(fastest.r.records_per_second)} records/s`);
    if (window.lucide) lucide.createIcons();
  },

  renderUsageBars() {
    const el = document.getElementById('parsers-usage-bars');
    if (!el) return;
    const rows = this.parsers.filter(p => p.events).sort((a, b) => b.events - a.events);
    if (this.usage.unparsed_events) {
      rows.push({ name: 'Not recognised', events: this.usage.unparsed_events, avg_latency_ms: 0, unparsed: true });
    }
    if (!rows.length) {
      el.innerHTML = '<div class="analytics-empty">No events yet. Upload logs in the Normalizer.</div>';
      return;
    }
    const total = this.usage.total_events || 1;
    el.innerHTML = rows.map(p => this.barRow(p.name,
      p.unparsed ? 'map these in the AI Schema Mapper' : `avg ${p.avg_latency_ms} ms full pipeline`,
      p.events / total * 100, `${p.events.toLocaleString()} (${(p.events / total * 100).toFixed(1)}%)`,
      p.unparsed ? 'var(--status-amber)' : 'var(--cherry-primary)')).join('');
  },

  renderSandboxControls() {
    const select = document.getElementById('parser-sandbox-engine-select');
    if (select) {
      const current = select.value;
      select.innerHTML = '<option value="">Automatic detection (as ingestion does)</option>' + this.parsers.map(p =>
        `<option value="${Utils.escapeHtml(p.id)}">${Utils.escapeHtml(p.name)} (${Utils.escapeHtml(p.kind.toLowerCase())})</option>`).join('');
      select.value = this.parsers.some(p => p.id === current) ? current : '';
    }
    const presets = document.getElementById('parser-sandbox-presets');
    if (presets) {
      presets.innerHTML = '<span style="font-size:0.70rem; font-weight:800; color:var(--text-muted); font-family:var(--font-mono);">SAMPLES:</span>'
        + this.parsers.filter(p => p.sample).map((p, i) =>
          `<button class="btn-cream-action btn-sm" style="font-size:0.68rem; padding:3px 8px;" onclick="ParsersModule.testEngine(ParsersModule.parsers[${i}].id)">${Utils.escapeHtml(p.name)}</button>`
        ).join('');
    }
  },

  async runSandboxBenchmark() {
    const raw = (document.getElementById('parser-sandbox-input') || {}).value || '';
    const parser = (document.getElementById('parser-sandbox-engine-select') || {}).value || '';
    const set = (id, html) => { const e = document.getElementById(id); if (e) e.innerHTML = html; };
    if (!raw.trim()) {
      Utils.showToast('Paste a log record first.', 'warning');
      return;
    }
    set('sandbox-speed-val', 'Running&hellip;');
    try {
      const r = await LogVaultAPI.benchmarkParser(raw, parser);
      set('sandbox-speed-val', `${r.median_us} µs median`);
      set('sandbox-ops-val', `${Charts.compact(r.records_per_second)} records/s`);
      set('sandbox-result-label', r.matched
        ? `MATCHED BY <strong>${Utils.escapeHtml(Charts.formatLabel(r.parser))}</strong> &bull; ${r.field_count} FIELDS &bull; ${r.runs.toLocaleString()} TIMED RUNS`
        : 'NO PARSER MATCHED THIS RECORD');
      set('sandbox-tokens-wrap', Object.entries(r.fields).map(([k, v]) =>
        `<span class="parser-token-chip green"><i data-lucide="tag"></i> [${Utils.escapeHtml(k.toUpperCase())}] ${Utils.escapeHtml(String(typeof v === 'object' ? JSON.stringify(v) : v).slice(0, 60))}</span>`
      ).join('') || '<span style="color:var(--text-muted); font-size:0.72rem;">No fields extracted. Try the AI Schema Mapper.</span>');
      const out = document.getElementById('sandbox-ocsf-json');
      if (out) out.textContent = JSON.stringify(r.fields, null, 2);
      if (window.lucide) lucide.createIcons();
    } catch (err) {
      set('sandbox-speed-val', 'Error');
      Utils.showToast(`Parser test failed: ${err.message}`, 'error');
    }
  },

  testEngine(parserId) {
    const p = this.parsers.find(x => x.id === parserId);
    if (!p) return;
    const textarea = document.getElementById('parser-sandbox-input');
    if (textarea) textarea.value = p.sample;
    const select = document.getElementById('parser-sandbox-engine-select');
    if (select) select.value = p.id;
    this.runSandboxBenchmark();
  },

  openInMapper() {
    const raw = (document.getElementById('parser-sandbox-input') || {}).value || '';
    Navigation.navigateTo('ai-mapper');
    if (window.AiMapper && raw.trim()) AiMapper.analyze(raw.trim());
  },

  renderCatalog() {
    const grid = document.getElementById('parser-catalog-grid');
    if (!grid) return;
    let list = this.parsers.map((p, i) => ({ ...p, _i: i }));
    if (this.currentCategory !== 'all') list = list.filter(p => p.category === this.currentCategory);
    if (this.searchQuery) {
      list = list.filter(p => [p.name, p.formats, p.ocsf_class, p.kind].join(' ').toLowerCase().includes(this.searchQuery));
    }
    if (!list.length) {
      grid.innerHTML = '<div class="analytics-empty">No parsers match.</div>';
      return;
    }
    const cell = (label, value, color) => `
      <div style="background:var(--bg-app); padding:6px 8px; border-radius:4px; border:1px solid var(--border-card);">
        <span style="color:var(--text-muted); font-size:0.60rem; display:block; text-transform:uppercase; font-weight:700;">${label}</span>
        <strong style="color:${color}; font-size:0.75rem;">${value}</strong>
      </div>`;
    grid.innerHTML = list.map(p => {
      const s = this.speeds[p.id];
      const speed = s && s.matched ? `${Charts.compact(s.records_per_second)}/s` : (s === undefined ? 'measuring' : 'n/a');
      return `
      <div class="parser-engine-card">
        <div>
          <div class="d-flex justify-between align-center mb-2">
            <span style="font-family:var(--font-mono); font-size:0.68rem; font-weight:800; color:var(--cherry-primary);">${Utils.escapeHtml(p.kind)}</span>
            <span class="badge-pill ${p.events ? 'green' : 'gold'}-pill" style="font-size:0.58rem;">${p.events ? 'IN USE' : 'NOT USED YET'}</span>
          </div>
          <h4 style="font-family:var(--font-heading); font-size:0.88rem; font-weight:800; color:var(--text-ink); margin-bottom:4px;">${Utils.escapeHtml(p.name)}</h4>
          <span style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-muted); display:block; margin-bottom:12px;">${Utils.escapeHtml(p.formats)}</span>
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; font-family:var(--font-mono); font-size:0.68rem; margin-bottom:12px;">
            ${cell('Parse speed', speed, 'var(--status-green)')}
            ${cell('Records matched', (p.events || 0).toLocaleString(), 'var(--cherry-primary)')}
            ${cell('Avg pipeline time', p.events ? `${p.avg_latency_ms} ms` : '&mdash;', 'var(--text-ink)')}
            ${cell('OCSF class', Utils.escapeHtml(p.ocsf_class), 'var(--text-ink)')}
          </div>
        </div>
        <div class="d-flex justify-between align-center pt-2" style="border-top:1px solid var(--border-subtle);">
          <span style="font-size:0.65rem; font-family:var(--font-mono); color:var(--text-muted);">${p.last_used ? `last match ${App.timeAgo(p.last_used)}` : 'no matches yet'}${p.created_by ? ` &bull; by ${Utils.escapeHtml(p.created_by)}` : ''}</span>
          <button class="btn-cream-action btn-sm" onclick="ParsersModule.testEngine(ParsersModule.parsers[${p._i}].id)" style="font-size:0.68rem; padding:4px 10px; font-weight:700;">
            <i data-lucide="play"></i> Test
          </button>
        </div>
      </div>`;
    }).join('');
    if (window.lucide) lucide.createIcons();
  }
};

window.ParsersModule = ParsersModule;
