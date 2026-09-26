/**
 * LOGVAULT — Schema Mapper.
 * Proposals come from /api/mapper/infer (key names and value shapes, optionally the local AI's
 * classification); saved rules go to /api/mapper/rules and are used by the backend parser.
 */

const AiMapper = {
  // Sample records of formats the built-in parsers do not cover
  samples: {
    kv_custom: 'USR=john ACT=LOGIN RES=FAIL SRC=10.2.4.5 DEV=web01 LOC=mumbai PROT=SSH PORT=22',
    cisco_asa: '%ASA-4-106023: Deny tcp src outside:192.168.1.45/54210 dst inside:10.0.4.92/22 by access-group OUTSIDE_IN [0x0, 0x0]',
    iot_sensor: 'NODE_ID=plc_substation_04 SENS=temp_core VAL=89.4C STAT=ALARM_OVERTEMP TS=1724838662',
    iso_8583: 'MTI=0200 PAN=4111********1111 PROC=000000 AMT=000000045000 STAN=492102 RRN=992182749102 RESP=05 MCC=5411',
    grpc_trace: 'trace_id=4bf92f3577b34da6a3ce929d0e0e4736 span_id=00f067aa0ba902b7 service=auth-service method=/v1.Auth/VerifyToken status=DEADLINE_EXCEEDED latency_ms=502',
    kernel_syslog: 'kernel: [ 1042.891024] audit: type=1400 audit(1724838662.891:42): apparmor="DENIED" operation="open" profile="/usr/sbin/cupsd" name="/etc/shadow" pid=1204 comm="cupsd" requested_mask="r" denied_mask="r" fsuid=7 ouid=0'
  },

  current: null,        // last /api/mapper/infer result (mappings editable)
  targetFields: [],
  rules: [],
  animFrameId: null,
  loaded: false,

  init() {
    this.bindEvents();
  },

  onScreenOpen() {
    this.loadRules();
    if (!this.loaded) {
      this.loaded = true;
      this.loadPreset('kv_custom');
    }
    this.startMeshLoop();
  },

  bindEvents() {
    document.querySelectorAll('[data-ai-preset]').forEach(btn => {
      btn.addEventListener('click', () => this.loadPreset(btn.getAttribute('data-ai-preset')));
    });
    const input = () => (document.getElementById('ai-raw-input-box') || {}).value || '';
    const runBtn = document.getElementById('btn-run-ai-inference');
    if (runBtn) runBtn.addEventListener('click', () => this.analyze(input().trim(), false));
    const aiBtn = document.getElementById('btn-run-ai-classify');
    if (aiBtn) aiBtn.addEventListener('click', () => this.analyze(input().trim(), true));
    const acceptBtn = document.getElementById('btn-accept-mapping');
    if (acceptBtn) acceptBtn.addEventListener('click', () => this.acceptMapping());
    const regexBtn = document.getElementById('btn-export-regex');
    if (regexBtn) regexBtn.addEventListener('click', () => this.exportRegex());
  },

  loadPreset(key) {
    const raw = this.samples[key];
    if (!raw) return;
    document.querySelectorAll('[data-ai-preset]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-ai-preset') === key);
    });
    this.analyze(raw, false);
  },

  setBadge(text, cls = 'green-pill') {
    const badge = document.getElementById('ai-inference-status-badge');
    if (badge) {
      badge.className = `badge-pill ${cls}`;
      badge.innerHTML = text;
    }
  },

  async analyze(raw, useAi) {
    if (!raw) {
      Utils.showToast('Paste a log record first.', 'warning');
      return;
    }
    const input = document.getElementById('ai-raw-input-box');
    if (input) input.value = raw;
    this.setBadge(`<span class="pulse-dot"></span> ${useAi ? 'Asking local AI...' : 'Mapping fields...'}`, 'gold-pill');
    try {
      const result = await LogVaultAPI.mapperInfer(raw, useAi);
      result.mappings.forEach(m => { if (!m.mapped) m.targetField = 'ignore'; });
      this.current = result;
      this.render();
      this.renderPreview();
      this.setBadge(`<span class="status-dot green-dot"></span> ${result.mapped_fields} of ${result.total_fields} fields mapped`);
    } catch (err) {
      this.setBadge('<span class="status-dot"></span> Error', 'crit-pill');
      Utils.showToast(`Mapping failed: ${err.message}`, 'error');
    }
  },

  render() {
    const d = this.current;
    if (!d) return;
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

    set('ai-raw-preview-box', `<span>${Utils.escapeHtml(d.raw)}</span>`);
    const mapped = d.mappings.filter(m => m.targetField !== 'ignore');
    const conf = mapped.length ? (mapped.reduce((a, m) => a + m.confidence, 0) / mapped.length * 100).toFixed(1) : '0.0';
    set('ai-overall-confidence', `${conf}%`);
    set('ai-engine-latency', d.kind === 'kv' ? 'key=value pairs' : 'positional (matched by leading token)');
    set('ai-ribbon-latency', `${d.latency_ms} ms`);
    set('ai-ribbon-fields', `${mapped.length} / ${d.mappings.length}`);
    const cur = d.current_parser;
    set('ai-ribbon-current', cur.format === 'unknown' ? 'Not recognised' : Utils.escapeHtml(Charts.formatLabel(cur.format)));

    const eventType = document.getElementById('ai-rule-event-type');
    if (eventType) eventType.value = d.suggested_event_type || 'GENERIC_EVENT';

    const box = document.getElementById('ai-classify-box');
    if (box) {
      if (d.ai) {
        const ok = d.ai.provider === 'ollama';
        box.style.display = 'block';
        box.innerHTML = ok
          ? `<strong>Local AI (${Utils.escapeHtml(d.ai.model || '')})</strong>: ${Utils.escapeHtml(d.ai.event_type || 'no class')}
             ${d.ai.severity ? `&bull; ${Utils.escapeHtml(d.ai.severity)}` : ''}
             ${d.ai.mitre_techniques && d.ai.mitre_techniques.length ? `&bull; ${Utils.escapeHtml(d.ai.mitre_techniques.join(', '))}` : ''}
             <div style="margin-top:4px; color:var(--text-muted);">${Utils.escapeHtml(d.ai.reasoning || '')}</div>`
          : `<strong>Local AI unavailable</strong>: ${Utils.escapeHtml(d.ai.reasoning || 'Ollama is not ready')}. The field mapping above does not need it.`;
      } else {
        box.style.display = 'none';
      }
    }

    const container = document.getElementById('ai-mapping-rows-container');
    if (container) {
      const targets = [...new Set([...(this.targetFields.length ? this.targetFields : []), ...d.mappings.map(m => m.targetField)])]
        .filter(t => t !== 'ignore');
      container.innerHTML = d.mappings.length ? d.mappings.map((m, idx) => {
        const pct = Math.round(m.confidence * 100);
        const confClass = pct >= 90 ? 'high' : pct >= 70 ? 'med' : 'low';
        const options = ['ignore', ...targets].map(opt =>
          `<option value="${Utils.escapeHtml(opt)}" ${opt === m.targetField ? 'selected' : ''}>${Utils.escapeHtml(opt)}</option>`).join('');
        return `
          <div class="ai-mapping-item-card">
            <div class="ai-map-left">
              <span class="ai-raw-field-badge" title="value: ${Utils.escapeHtml(m.value)}">${Utils.escapeHtml(m.rawField)}</span>
              <span class="ai-arrow-connector">&rarr;</span>
            </div>
            <div class="ai-map-center">
              <select class="ai-target-field-select" onchange="AiMapper.updateFieldTarget(${idx}, this.value)">${options}</select>
              <div class="ai-conf-bar-wrap">
                <div class="ai-conf-track"><div class="ai-conf-fill ${confClass}" style="width:${pct}%;"></div></div>
                <span class="ai-conf-pct">${pct}%</span>
              </div>
            </div>
            <span class="ai-type-tag" title="${Utils.escapeHtml(m.value)}">${Utils.escapeHtml(String(m.value).slice(0, 24))}</span>
          </div>`;
      }).join('') : '<div class="analytics-empty">No fields found in this record.</div>';
    }
    if (window.lucide) lucide.createIcons();
  },

  // Normalized preview built from the current (possibly edited) mapping
  renderPreview() {
    const d = this.current;
    const code = document.getElementById('ai-schema-preview-code');
    if (!d || !code) return;
    const out = {};
    d.mappings.forEach(m => {
      if (m.targetField && m.targetField !== 'ignore') out[m.targetField] = m.value;
    });
    const et = (document.getElementById('ai-rule-event-type') || {}).value;
    if (et && !out.event_type) out.event_type = et;
    code.textContent = JSON.stringify(out, null, 2);
  },

  updateFieldTarget(idx, newTarget) {
    if (!this.current || !this.current.mappings[idx]) return;
    this.current.mappings[idx].targetField = newTarget;
    this.render();
    this.renderPreview();
  },

  async loadRules() {
    try {
      const res = await LogVaultAPI.getMappingRules();
      this.rules = res.rules;
      this.targetFields = res.target_fields;
    } catch {
      return;
    }
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    set('ai-ribbon-rules', String(this.rules.length));
    set('ai-rules-tbody', this.rules.length ? this.rules.map((r, i) => `
      <tr>
        <td><strong>${Utils.escapeHtml(r.name)}</strong></td>
        <td>${r.kind === 'kv' ? 'key=value' : 'positional'}</td>
        <td><code style="font-size:0.68rem;">${Utils.escapeHtml(r.kind === 'kv' ? (r.signature || []).join(', ') : r.anchor || '')}</code></td>
        <td>${r.mappings.map(m => `${Utils.escapeHtml(m.rawField)}&rarr;${Utils.escapeHtml(m.targetField)}`).join(', ')}</td>
        <td style="font-family:var(--font-mono);">${(r.events_matched || 0).toLocaleString()}</td>
        <td style="font-size:0.7rem;">${Utils.escapeHtml(r.created_by || '')} &bull; ${App.timeAgo(r.created_at)}</td>
        <td><button class="btn-outline-cherry btn-sm" onclick="AiMapper.deleteRule(${i})">Delete</button></td>
      </tr>`).join('')
      : '<tr><td colspan="7" style="text-align:center; padding:18px; color:var(--text-muted);">No rules saved yet.</td></tr>');
  },

  async acceptMapping() {
    const d = this.current;
    if (!d) {
      Utils.showToast('Map a record first.', 'warning');
      return;
    }
    const nameEl = document.getElementById('ai-rule-name');
    const name = nameEl ? nameEl.value.trim() : '';
    if (!name) {
      Utils.showToast('Give the rule a name first.', 'warning');
      if (nameEl) nameEl.focus();
      return;
    }
    const mappings = d.mappings.filter(m => m.targetField && m.targetField !== 'ignore');
    const eventType = ((document.getElementById('ai-rule-event-type') || {}).value || '').trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    try {
      await LogVaultAPI.saveMappingRule({
        name, kind: d.kind, mappings,
        // kv rules match on the keys that are actually mapped
        signature: d.kind === 'kv' ? mappings.map(m => m.rawField) : null,
        anchor: d.anchor, event_type: eventType || null, sample: d.raw
      });
      Utils.showToast(`Rule "${name}" saved. New records of this format are now parsed with it.`, 'success');
      if (nameEl) nameEl.value = '';
      this.loadRules();
      this.analyze(d.raw, false);
    } catch (err) {
      Utils.showToast(`Could not save rule: ${err.message}`, 'error');
    }
  },

  async deleteRule(i) {
    const r = this.rules[i];
    if (!r || !window.confirm(`Delete mapping rule "${r.name}"? Records already stored keep their fields.`)) return;
    try {
      await LogVaultAPI.deleteMappingRule(r.id);
      Utils.showToast(`Rule "${r.name}" deleted.`, 'success');
      this.loadRules();
    } catch (err) {
      Utils.showToast(`Could not delete: ${err.message}`, 'error');
    }
  },

  testInNormalizer() {
    Navigation.navigateTo('normalizer');
    if (window.Normalizer && this.current) Normalizer.loadRawCustomInput(this.current.raw);
  },

  // A regex matching this format: anchor for positional records, one lookahead per mapped key otherwise
  exportRegex() {
    const d = this.current;
    if (!d) return;
    const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const safe = t => t.replace(/[^A-Za-z0-9_]/g, '_');
    const mapped = d.mappings.filter(m => m.targetField !== 'ignore');
    const pattern = d.kind === 'kv'
      ? '^' + mapped.map(m => `(?=.*\\b${esc(m.rawField)}=(?<${safe(m.targetField)}>"[^"]*"|\\S+))`).join('')
      : d.anchor;
    navigator.clipboard.writeText(pattern)
      .then(() => Utils.showToast('Regex copied to clipboard.', 'success'))
      .catch(() => Utils.showToast('Could not copy to clipboard.', 'error'));
  },

  startMeshLoop() {
    if (this.animFrameId) cancelAnimationFrame(this.animFrameId);
    const canvas = document.getElementById('aiNeuralMeshCanvas');
    if (!canvas) return;
    const loop = () => {
      if (Navigation.activeScreen !== 'ai-mapper') {
        this.animFrameId = null;
        return;
      }
      this.drawMesh(canvas);
      this.animFrameId = requestAnimationFrame(loop);
    };
    this.animFrameId = requestAnimationFrame(loop);
  },

  // Neural-style mapping graph of the current proposal: raw fields (left) pass through the method
  // that matched them (middle layer) to normalized fields (right). Pulses run only on real paths.
  METHODS: ['key name', 'value shape', 'position', 'unmapped'],

  methodOf(m) {
    if (m.targetField === 'ignore') return 3;
    if (m.rawField.includes('#')) return 2;
    return m.confidence >= 0.9 ? 0 : 1;
  },

  drawMesh(canvas) {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = rect.width || 750;
    const h = rect.height || 140;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const ink = isDark ? '#FFF8F0' : '#24191B';

    const rows = this.current ? this.current.mappings.slice(0, 9) : [];
    if (!rows.length) {
      ctx.fillStyle = isDark ? '#A89094' : '#756568';
      ctx.font = '12px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Map a record to see its fields here', w / 2, h / 2);
      return;
    }
    const yAt = (i, n, pad) => n === 1 ? h / 2 : pad + i * ((h - pad * 2) / (n - 1));
    const inputs = rows.map((m, i) => ({ m, x: w * 0.2, y: yAt(i, rows.length, 12) }));
    const hidden = this.METHODS.map((name, i) => ({ name, x: w * 0.5, y: yAt(i, this.METHODS.length, 22) }));
    const mapped = rows.filter(m => m.targetField !== 'ignore');
    const outputs = mapped.map((m, i) => ({ m, x: w * 0.8, y: yAt(i, mapped.length, 12) }));

    // Faint full mesh
    ctx.lineWidth = 1;
    inputs.forEach(inp => hidden.forEach(hd => {
      ctx.beginPath();
      ctx.moveTo(inp.x, inp.y);
      ctx.lineTo(hd.x, hd.y);
      ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.06)' : 'rgba(116, 21, 42, 0.05)';
      ctx.stroke();
    }));
    hidden.slice(0, 3).forEach(hd => outputs.forEach(out => {
      ctx.beginPath();
      ctx.moveTo(hd.x, hd.y);
      ctx.lineTo(out.x, out.y);
      ctx.strokeStyle = isDark ? 'rgba(37, 133, 90, 0.08)' : 'rgba(37, 133, 90, 0.06)';
      ctx.stroke();
    }));

    // Real paths with firing pulses
    const pulse = (x1, y1, x2, y2, t, color, glow) => {
      ctx.beginPath();
      ctx.arc(x1 + (x2 - x1) * t, y1 + (y2 - y1) * t, 2.4, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.shadowColor = glow;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    };
    inputs.forEach((inp, i) => {
      const hd = hidden[this.methodOf(inp.m)];
      const out = outputs.find(o => o.m === inp.m);
      const strong = isDark ? 'rgba(232, 160, 170, 0.45)' : 'rgba(116, 21, 42, 0.35)';
      ctx.beginPath();
      ctx.moveTo(inp.x, inp.y);
      ctx.lineTo(hd.x, hd.y);
      ctx.strokeStyle = out ? strong : (isDark ? 'rgba(168, 144, 148, 0.3)' : 'rgba(117, 101, 104, 0.25)');
      ctx.lineWidth = 1 + inp.m.confidence * 1.5;
      ctx.stroke();
      const t1 = ((now / 1500) + i * 0.17) % 1;
      pulse(inp.x, inp.y, hd.x, hd.y, t1, '#B4233C', '#FF6B7A');
      if (out) {
        ctx.beginPath();
        ctx.moveTo(hd.x, hd.y);
        ctx.lineTo(out.x, out.y);
        ctx.strokeStyle = isDark ? 'rgba(37, 133, 90, 0.5)' : 'rgba(37, 133, 90, 0.38)';
        ctx.lineWidth = 1 + inp.m.confidence * 1.5;
        ctx.stroke();
        pulse(hd.x, hd.y, out.x, out.y, ((now / 1400) + i * 0.19) % 1, '#25855A', '#2A9D8F');
      }
    });

    // Nodes and labels
    ctx.font = '700 9.5px JetBrains Mono, monospace';
    inputs.forEach(inp => {
      ctx.beginPath();
      ctx.arc(inp.x, inp.y, 6.5, 0, Math.PI * 2);
      ctx.fillStyle = '#B4233C';
      ctx.fill();
      ctx.strokeStyle = '#FFF8F0';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.fillStyle = ink;
      ctx.textAlign = 'right';
      ctx.fillText(String(inp.m.rawField).slice(0, 22), inp.x - 11, inp.y + 3);
    });
    hidden.forEach((hd, i) => {
      const used = inputs.some(inp => this.methodOf(inp.m) === i);
      const r = 6 + (used ? Math.sin(now / 200 + i) * 1.5 : 0);
      ctx.beginPath();
      ctx.arc(hd.x, hd.y, r, 0, Math.PI * 2);
      ctx.fillStyle = used ? (i === 3 ? '#756568' : '#C47A16') : (isDark ? '#3D3537' : '#E8DCCE');
      if (used) {
        ctx.shadowColor = '#FFAA00';
        ctx.shadowBlur = 8;
      }
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.font = '600 8.5px JetBrains Mono, monospace';
      ctx.fillStyle = used ? (isDark ? '#E8A0AA' : '#756568') : (isDark ? '#5A4A4D' : '#C9B8AC');
      ctx.textAlign = 'center';
      ctx.fillText(hd.name, hd.x, hd.y - 10);
    });
    ctx.font = '700 9.5px JetBrains Mono, monospace';
    outputs.forEach(out => {
      ctx.beginPath();
      ctx.arc(out.x, out.y, 6.5, 0, Math.PI * 2);
      ctx.fillStyle = '#25855A';
      ctx.fill();
      ctx.strokeStyle = '#FFF8F0';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.fillStyle = ink;
      ctx.textAlign = 'left';
      ctx.fillText(`${out.m.targetField}  ${Math.round(out.m.confidence * 100)}%`, out.x + 11, out.y + 3);
    });
  }
};

window.AiMapper = AiMapper;
