/**
 * LOGVAULT — Anomaly screen (one real incident: entity graph, related-event timeline, containment)
 * and Alert Center (queue, Kanban, AI investigation with analyst approval).
 */

const AnomalyModule = {
  activeIncidentId: null,
  workflowFilter: 'ALL',
  animFrameId: null,
  hoveredNode: null,

  incident: null,       // dossier of the incident shown on the Anomaly screen
  graph: null,          // entity graph built from that dossier

  alerts: [],
  anomalies: [],

  // Alert workflow: OPEN -> AI Investigating -> Awaiting Approval -> Resolved
  //                                               -> (analyst reject) Investigating
  STATUS_COLUMNS: {
    'OPEN': 'new',
    'AI Investigating': 'new',
    'Awaiting Approval': 'awaiting',
    'Investigating': 'investigating',
    'Resolved': 'resolved'
  },
  FILTER_STATUSES: {
    'Active': ['OPEN', 'AI Investigating'],
    'Awaiting Approval': ['Awaiting Approval'],
    'Investigating': ['Investigating'],
    'Resolved': ['Resolved']
  },
  COLUMN_DROP_STATUS: { new: 'OPEN', awaiting: 'Awaiting Approval', investigating: 'Investigating', resolved: 'Resolved' },
  VERDICT_META: {
    TRUE_POSITIVE: { label: 'Confirmed threat', pill: 'crit-pill' },
    SUSPICIOUS: { label: 'Suspicious', pill: 'warn-pill' },
    FALSE_POSITIVE: { label: 'False positive', pill: 'green-pill' }
  },

  statusCounts: {},
  activeDossierTab: 'details',
  noteDraft: '',
  pendingSearch: '',
  busy: false,
  _pollTimer: null,

  async init() {
    this.bindEvents();
    await this.fetchData();
  },

  async onScreenOpen(screenId) {
    if (screenId === 'alerts' || screenId === 'anomalies') {
      await this.fetchData();
    }
    if (screenId === 'anomalies') {
      this.openIncident(this.activeIncidentId, true);
      this.startGraphLoop();
    }
  },

  async fetchData() {
    if (!window.LogVaultAPI) return;
    
    // All alerts are fetched; the workflow filter is applied client-side to the queue
    const alertRes = await LogVaultAPI.getAlerts(500, 0, 'ALL');
    this.alerts = (alertRes && alertRes.alerts) ? alertRes.alerts : [];
    this.statusCounts = (alertRes && alertRes.status_counts) || {};

    const anomalyRes = await LogVaultAPI.getAnomalies();
    this.anomalies = (anomalyRes && anomalyRes.anomalies) ? anomalyRes.anomalies : [];

    this.updateCounts();
    this.renderAlertCenterQueue();
    this.renderKanbanBoard();

    if (this.alerts.length > 0) {
      if (!this.alerts.find(a => a.id === this.activeIncidentId)) {
        this.activeIncidentId = this.alerts[0].id;
      }
      this.loadIncidentDossier(this.activeIncidentId);
    } else {
      this.clearIncidentDossier();
    }

    this.applyPendingSearch();
    this.updateTriageStrip();
    this.renderIncidentPicker();
    this.schedulePoll();
  },

  bindEvents() {
    // Workflow filter buttons in Alert Center
    document.querySelectorAll('[data-wf-filter]').forEach(btn => {
      btn.addEventListener('click', () => {
        const status = btn.getAttribute('data-wf-filter');
        this.setWorkflowFilter(status);
      });
    });

    // Dossier tabs (AI investigation / timeline / assets / analyst decision)
    document.querySelectorAll('[data-dossier-tab]').forEach(btn => {
      btn.addEventListener('click', () => this.switchDossierTab(btn.getAttribute('data-dossier-tab')));
    });

    // Alert queue search
    const searchInput = document.getElementById('workflow-queue-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.filterQueueSearch(e.target.value.toLowerCase().trim());
      });
    }

    // Incident picker and containment actions on the Anomaly screen
    const picker = document.getElementById('incident-select');
    if (picker) picker.addEventListener('change', (e) => this.openIncident(e.target.value, false));
    const on = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); };
    on('btn-qc-isolate', () => this.containActive('host'));
    on('btn-contain-server', () => this.containActive('host'));
    on('btn-qc-acl', () => this.containActive('ip'));
    on('btn-block-source-ip', () => this.containActive('ip'));
    on('btn-qc-logs', () => this.viewActiveLogs());
    on('btn-export-dossier', () => this.downloadDossier());
  },

  setWorkflowFilter(status) {
    this.workflowFilter = status;
    document.querySelectorAll('[data-wf-filter]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-wf-filter') === status);
    });
    this.fetchData();
  },

  analystName() {
    return (window.AuthModule && AuthModule.operator && AuthModule.operator.name)
      || localStorage.getItem('logvault_op_name') || 'analyst';
  },

  esc(v) {
    return Utils.escapeHtml(v === null || v === undefined ? '' : String(v));
  },

  statusLabel(status) {
    return status === 'OPEN' ? 'Active' : status;
  },

  statusClass(status) {
    return ({
      'OPEN': 'state-active',
      'AI Investigating': 'state-ai',
      'Awaiting Approval': 'state-awaiting',
      'Investigating': 'state-investigating',
      'Resolved': 'state-resolved'
    })[status] || 'state-active';
  },

  severityPill(sev) {
    return ({ CRITICAL: 'crit-pill', HIGH: 'high-pill', MEDIUM: 'warn-pill', LOW: 'green-pill' })[sev] || 'neutral-pill';
  },

  siblingsAwaiting(inc) {
    return this.alerts.filter(a => a.id !== inc.id && a.status === 'Awaiting Approval'
      && a.source_ip === inc.source_ip && a.title === inc.title);
  },

  updateCounts() {
    const c = this.statusCounts || {};
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = v; };
    const active = (c['OPEN'] || 0) + (c['AI Investigating'] || 0);
    set('wf-count-active', active);
    set('wf-count-awaiting', c['Awaiting Approval'] || 0);
    set('wf-count-investigating', c['Investigating'] || 0);
    set('wf-count-resolved', c['Resolved'] || 0);
    set('wf-count-all', Object.values(c).reduce((s, v) => s + v, 0));
    set('kanban-count-new', active);
    set('kanban-count-awaiting', c['Awaiting Approval'] || 0);
    set('kanban-count-investigating', c['Investigating'] || 0);
    set('kanban-count-resolved', c['Resolved'] || 0);
  },

  async updateTriageStrip() {
    const el = document.getElementById('ai-triage-strip-text');
    const strip = document.getElementById('ai-triage-strip');
    if (!el) return;
    const health = window.LogVaultAPI ? await LogVaultAPI.checkBackend() : null;
    const c = this.statusCounts || {};
    const queued = (c['OPEN'] || 0) + (c['AI Investigating'] || 0);
    const awaiting = c['Awaiting Approval'] || 0;
    if (!health) {
      el.innerText = 'Backend offline: AI auto-investigation unavailable.';
      if (strip) strip.dataset.state = 'off';
      return;
    }
    const engine = health.local_ai ? `Local AI ${health.model} + detection rules` : 'Detection rules only (local AI not ready)';
    const auto = health.auto_investigate !== false;
    el.innerHTML = `${auto ? '<strong>AI auto-investigation on</strong>' : '<strong>AI auto-investigation off</strong> (run it per alert)'}
      &bull; ${this.esc(engine)} &bull; ${queued} in AI queue &bull;
      <strong>${awaiting} awaiting your approval</strong> &bull; nothing is closed without an analyst`;
    if (strip) strip.dataset.state = queued ? 'busy' : 'idle';
  },

  schedulePoll() {
    clearTimeout(this._pollTimer);
    const busy = this.alerts.some(a => a.status === 'AI Investigating' || (a.status === 'OPEN' && !a.investigation));
    const onScreen = window.Navigation && Navigation.activeScreen === 'alerts';
    if (busy && onScreen) {
      this._pollTimer = setTimeout(() => this.fetchData(), 4000);
    }
  },

  focusSource(ip) {
    this.pendingSearch = ip;
    this.setWorkflowFilter('ALL');
  },

  applyPendingSearch() {
    const input = document.getElementById('workflow-queue-search');
    if (this.pendingSearch && input) {
      input.value = this.pendingSearch;
      const match = this.alerts.find(a => a.source_ip === this.pendingSearch);
      if (match) this.loadIncidentDossier(match.id);
      this.pendingSearch = '';
    }
    if (input && input.value) this.filterQueueSearch(input.value.toLowerCase().trim());
  },

  // Kanban Drag & Drop System (60 FPS smooth animation)
  renderKanbanBoard() {
    const columns = {
      new: document.getElementById('kanban-col-new'),
      awaiting: document.getElementById('kanban-col-awaiting'),
      investigating: document.getElementById('kanban-col-investigating'),
      resolved: document.getElementById('kanban-col-resolved')
    };

    if (!columns.new) return;

    Object.entries(columns).forEach(([colKey, col]) => {
      if (!col) return;
      col.innerHTML = '';

      col.ondragover = (e) => {
        e.preventDefault();
        col.classList.add('drag-over');
      };
      col.ondragleave = () => {
        col.classList.remove('drag-over');
      };
      col.ondrop = (e) => {
        e.preventDefault();
        col.classList.remove('drag-over');
        const alertId = e.dataTransfer.getData('text/plain');
        if (alertId) {
          this.moveKanbanCard(alertId, this.COLUMN_DROP_STATUS[colKey]);
        }
      };
    });

    if (this.alerts.length === 0) {
      columns.new.innerHTML = '<div class="kanban-empty">No alerts yet. Anomalies from ingested logs appear here.</div>';
      return;
    }

    this.alerts.forEach(inc => {
      const targetCol = columns[this.STATUS_COLUMNS[inc.status] || 'new'];
      const pClass = ({ MEDIUM: 'medium', LOW: 'low' })[inc.severity] || 'high';
      const inv = inc.investigation;
      const verdict = inv && this.VERDICT_META[inv.verdict];

      let actionBtn = '';
      if (inc.status === 'AI Investigating') {
        actionBtn = '<span class="k-ai-working"><span class="pulse-dot"></span> AI investigating</span>';
      } else if (inc.status === 'OPEN') {
        actionBtn = `<button class="k-move-btn" data-action="investigate" data-id="${this.esc(inc.id)}">Run AI now</button>`;
      } else if (inc.status === 'Awaiting Approval') {
        actionBtn = `<button class="k-move-btn" data-action="review" data-id="${this.esc(inc.id)}">Review &amp; approve</button>`;
      } else if (inc.status === 'Investigating') {
        actionBtn = `<button class="k-move-btn" data-action="resolve" data-id="${this.esc(inc.id)}">Resolve &check;</button>`;
      } else {
        actionBtn = `<button class="k-move-btn" data-action="reopen" data-id="${this.esc(inc.id)}">Reopen</button>`;
      }

      const card = document.createElement('div');
      card.className = `kanban-item-card${inc.id === this.activeIncidentId ? ' selected' : ''}`;
      card.id = `kanban-card-${inc.id}`;
      card.draggable = true;

      card.innerHTML = `
        <div class="k-card-top">
          <span class="k-priority-pill ${pClass}">${this.esc(inc.severity)}</span>
          ${verdict ? `<span class="badge-pill ${verdict.pill} k-verdict">${verdict.label} ${Math.round((inv.confidence || 0) * 100)}%</span>`
            : `<span style="font-size:0.68rem; color:var(--text-muted);"><code>${this.esc(inc.id.substring(0, 8))}</code></span>`}
        </div>
        <div class="k-card-title">${this.esc(inc.title)}</div>
        <div class="k-card-sub"><code>${this.esc(inc.source_ip || 'N/A')}</code> &rarr; ${this.esc(inc.host || 'N/A')}</div>
        <div class="k-card-footer">
          <span><i data-lucide="${inc.decided_by ? 'user-check' : 'bot'}" style="width:12px;"></i> ${this.esc(inc.decided_by || 'AI triage')}</span>
          <div class="k-move-actions">${actionBtn}</div>
        </div>
      `;

      card.ondragstart = (e) => {
        e.dataTransfer.setData('text/plain', inc.id);
        card.classList.add('dragging');
      };

      card.ondragend = () => {
        card.classList.remove('dragging');
        document.querySelectorAll('.kanban-drop-zone').forEach(z => z.classList.remove('drag-over'));
      };

      card.onclick = (e) => {
        const btn = e.target.closest('[data-action]');
        if (btn) {
          e.stopPropagation();
          this.handleCardAction(btn.dataset.action, btn.dataset.id);
          return;
        }
        this.loadIncidentDossier(inc.id);
      };

      targetCol.appendChild(card);
    });

    Object.values(columns).forEach(col => {
      if (col && !col.children.length) col.innerHTML = '<div class="kanban-empty">Empty</div>';
    });

    if (window.lucide) lucide.createIcons();
  },

  handleCardAction(action, id) {
    if (action === 'investigate') return this.runInvestigation(id);
    if (action === 'review') {
      this.loadIncidentDossier(id);
      const pane = document.querySelector('.workflow-dossier-pane');
      if (pane) pane.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    if (action === 'resolve') return this.moveKanbanCard(id, 'Resolved');
    if (action === 'reopen') return this.moveKanbanCard(id, 'OPEN');
  },

  async moveKanbanCard(id, newState) {
    const inc = this.alerts.find(i => i.id === id);
    if (!inc || !newState || inc.status === newState) return;

    if (newState === 'Awaiting Approval' && !inc.investigation) {
      // Only the AI can put an alert into "Awaiting Approval"
      return this.runInvestigation(id);
    }

    try {
      await LogVaultAPI.setAlertStatus(id, newState, this.analystName());
      Utils.showToast(`${inc.title} moved to ${this.statusLabel(newState)} by ${this.analystName()}.`, 'success');
    } catch (err) {
      Utils.showToast(`Could not update alert: ${err.message}`, 'error');
      return;
    }
    this.activeIncidentId = id;
    await this.fetchData();

    const movedEl = document.getElementById(`kanban-card-${id}`);
    if (movedEl) {
      movedEl.classList.add('glide-anim');
      setTimeout(() => movedEl.classList.remove('glide-anim'), 450);
    }
  },

  async runInvestigation(id) {
    const inc = this.alerts.find(i => i.id === id);
    if (inc) inc.status = 'AI Investigating';
    this.activeIncidentId = id;
    this.renderKanbanBoard();
    this.renderAlertCenterQueue();
    this.loadIncidentDossier(id);
    Utils.showToast('AI investigation started. Correlating related events...', 'info');
    try {
      const res = await LogVaultAPI.investigateAlert(id);
      const v = this.VERDICT_META[res.investigation.verdict];
      Utils.showToast(`AI verdict: ${v ? v.label : res.investigation.verdict}. Awaiting analyst approval.`, 'success');
    } catch (err) {
      Utils.showToast(`AI investigation failed: ${err.message}`, 'error');
    }
    await this.fetchData();
  },

  async approveActive(includeRelated) {
    const inc = this.alerts.find(i => i.id === this.activeIncidentId);
    if (!inc || this.busy) return;
    this.busy = true;
    try {
      const res = await LogVaultAPI.approveAlert(inc.id, this.analystName(), this.noteDraft || null, includeRelated);
      const n = (res.resolved_ids || [inc.id]).length;
      Utils.showToast(`Approved by ${this.analystName()}: ${n} alert${n > 1 ? 's' : ''} resolved.`, 'success');
      this.noteDraft = '';
    } catch (err) {
      Utils.showToast(`Approval failed: ${err.message}`, 'error');
    }
    this.busy = false;
    await this.fetchData();
  },

  async rejectActive() {
    const inc = this.alerts.find(i => i.id === this.activeIncidentId);
    if (!inc || this.busy) return;
    this.busy = true;
    try {
      await LogVaultAPI.rejectAlert(inc.id, this.analystName(), this.noteDraft || null);
      Utils.showToast('AI proposal rejected. Alert moved to manual investigation.', 'warning');
      this.noteDraft = '';
    } catch (err) {
      Utils.showToast(`Reject failed: ${err.message}`, 'error');
    }
    this.busy = false;
    await this.fetchData();
  },

  filterQueueSearch(query) {
    const cards = document.querySelectorAll('.incident-queue-card');
    cards.forEach(c => {
      const text = c.innerText.toLowerCase();
      c.style.display = text.includes(query) ? 'flex' : 'none';
    });
  },

  renderAlertCenterQueue() {
    const container = document.getElementById('incident-card-stack');
    if (!container) return;

    const allowed = this.FILTER_STATUSES[this.workflowFilter];
    const filtered = this.alerts.filter(inc => !allowed || allowed.includes(inc.status));

    if (filtered.length === 0) {
      container.innerHTML = `<div class="kanban-empty">No ${this.workflowFilter === 'ALL' ? '' : this.esc(this.workflowFilter.toLowerCase()) + ' '}alerts.</div>`;
      return;
    }

    container.innerHTML = filtered.map(inc => {
      const isSelected = inc.id === this.activeIncidentId;
      const inv = inc.investigation;
      const verdict = inv && this.VERDICT_META[inv.verdict];
      return `
        <div class="incident-queue-card ${isSelected ? 'selected' : ''}" data-id="${this.esc(inc.id)}">
          <div class="inc-q-head">
            <span class="inc-id-tag"><code>${this.esc(inc.id.substring(0, 8))}</code></span>
            <span class="badge-pill ${this.severityPill(inc.severity)}">${this.esc(inc.severity)}</span>
          </div>
          <div class="inc-q-title">${this.esc(inc.title)}</div>
          <div class="inc-q-sub">Origin: <code>${this.esc(inc.source_ip || 'N/A')}</code> &bull; Target: <code>${this.esc(inc.host || 'N/A')}</code></div>
          ${verdict ? `<div class="inc-q-verdict"><span class="badge-pill ${verdict.pill}">AI: ${verdict.label}</span> ${Math.round((inv.confidence || 0) * 100)}% confidence</div>` : ''}
          <div class="inc-q-meta">
            <span><i data-lucide="clock" style="width:12px;"></i> ${this.esc(inc.timestamp || '')}</span>
            <span class="inc-state-pill ${this.statusClass(inc.status)}">${this.esc(this.statusLabel(inc.status))}</span>
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('.incident-queue-card').forEach(card => {
      card.addEventListener('click', () => this.loadIncidentDossier(card.dataset.id));
    });

    if (window.lucide) lucide.createIcons();
  },

  switchDossierTab(tab) {
    this.activeDossierTab = tab;
    document.querySelectorAll('[data-dossier-tab]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-dossier-tab') === tab);
    });
    document.querySelectorAll('[data-dossier-panel]').forEach(panel => {
      panel.hidden = panel.getAttribute('data-dossier-panel') !== tab;
    });
  },

  loadIncidentDossier(id) {
    if (id !== this.activeIncidentId) this.noteDraft = '';
    this.activeIncidentId = id;
    const inc = this.alerts.find(i => i.id === id);
    if (!inc) return this.clearIncidentDossier();

    // Update queue + kanban highlight
    document.querySelectorAll('.incident-queue-card').forEach(c => {
      c.classList.toggle('selected', c.dataset.id === id);
    });
    document.querySelectorAll('.kanban-item-card').forEach(c => {
      c.classList.toggle('selected', c.id === `kanban-card-${id}`);
    });

    const inv = inc.investigation;
    const set = (elId, text) => { const el = document.getElementById(elId); if (el) el.innerText = text; };
    set('dossier-main-title', inc.title);
    set('dossier-src-ip', inc.source_ip || 'N/A');
    set('dossier-src-location', inv && inv.source_location ? `(${inv.source_location})` : '');
    set('dossier-target-ip', inc.host || 'N/A');
    set('dossier-event-type', inc.mitre_technique || 'No MITRE mapping');
    set('dossier-threat-score', inc.threat_score !== null && inc.threat_score !== undefined ? `${inc.threat_score} / 100` : 'N/A');
    set('dossier-time-range', inc.timestamp || '');
    set('dossier-desc-text', inc.description);

    const statusEl = document.getElementById('dossier-status-pill');
    if (statusEl) {
      statusEl.innerText = this.statusLabel(inc.status);
      statusEl.className = `inc-state-pill ${this.statusClass(inc.status)}`;
    }

    this.renderInvestigation(inc);
    this.renderTimeline(inc);
    this.renderAssets(inc);
    this.renderAnalystPanel(inc);
    this.renderDossierActions(inc);
    this.switchDossierTab(this.activeDossierTab);

    if (window.lucide) lucide.createIcons();
  },

  renderInvestigation(inc) {
    const el = document.getElementById('ai-investigation-card');
    if (!el) return;
    const inv = inc.investigation;

    if (inc.status === 'AI Investigating') {
      el.innerHTML = `<div class="ai-inv-pending"><span class="pulse-dot"></span> AI is investigating: correlating related events, checking detection rules and consulting the local model&hellip;</div>`;
      return;
    }
    if (!inv) {
      el.innerHTML = `<div class="ai-inv-pending"><i data-lucide="bot"></i> Queued for automatic AI investigation. You can also run it now.</div>`;
      return;
    }

    const v = this.VERDICT_META[inv.verdict] || { label: inv.verdict, pill: 'neutral-pill' };
    const conf = Math.round((inv.confidence || 0) * 100);
    const list = (items) => (items || []).map(i => `<li>${this.esc(i)}</li>`).join('');
    const op = inv.ai_opinion;

    el.innerHTML = `
      <div class="ai-inv-head">
        <div class="d-flex align-center gap-2">
          <span class="badge-pill ${v.pill}"><i data-lucide="bot"></i> ${v.label}</span>
          <div class="ai-inv-conf" title="Confidence ${conf}%"><div style="width:${conf}%"></div></div>
          <strong class="ai-inv-conf-val">${conf}%</strong>
        </div>
        <span class="ai-inv-engine">${this.esc(inv.engine || '')}${inv.duration_ms !== undefined ? ` &bull; ${inv.duration_ms} ms` : ''}</span>
      </div>
      <p class="ai-inv-summary">${this.esc(inv.summary)}</p>
      <div class="ai-inv-grid">
        <div><span class="ai-inv-label">Root cause</span><div>${this.esc(inv.root_cause || 'Not determined')}</div></div>
        <div><span class="ai-inv-label">Attack stage</span><div>${this.esc(inv.attack_stage || 'None identified')}</div></div>
      </div>
      ${inv.evidence && inv.evidence.length ? `<span class="ai-inv-label">Evidence</span><ul class="ai-inv-list">${list(inv.evidence)}</ul>` : ''}
      <span class="ai-inv-label">Recommended actions</span>
      <ol class="ai-inv-list">${list(inv.recommended_actions)}</ol>
      <div class="ai-inv-resolution"><i data-lucide="clipboard-check"></i><div><strong>Proposed resolution</strong><br>${this.esc(inv.proposed_resolution || '')}</div></div>
      ${inv.ai_disagreement && op ? `
        <div class="ai-inv-disagree"><i data-lucide="alert-triangle"></i><div>
          <strong>Second opinion differs.</strong> Local model said <em>${this.esc((this.VERDICT_META[op.verdict] || {}).label || op.verdict)}</em>
          (${Math.round((op.confidence || 0) * 100)}%); rules said <em>${this.esc((this.VERDICT_META[inv.rule_verdict.verdict] || {}).label || inv.rule_verdict.verdict)}</em>.
          The more cautious verdict was kept. Please review the evidence before approving.
          ${op.summary ? `<div class="ai-inv-op">Model's view: ${this.esc(op.summary)}</div>` : ''}
        </div></div>` : ''}
    `;
  },

  renderTimeline(inc) {
    const el = document.getElementById('dossier-timeline');
    if (!el) return;
    const items = (inc.investigation && inc.investigation.timeline) || [];
    if (!items.length) {
      el.innerHTML = '<div class="kanban-empty">The timeline is built during the AI investigation.</div>';
      return;
    }
    el.innerHTML = items.map(t => `
      <div class="inv-tl-item${t.is_alert ? ' is-alert' : ''}${t.anomalous ? ' anomalous' : ''}">
        <div class="inv-tl-dot"></div>
        <div>
          <div class="inv-tl-head"><code>${this.esc(t.time || 'no timestamp')}</code>
            <span class="badge-pill ${this.severityPill(t.severity)}">${this.esc(t.severity || 'INFO')}</span>
            ${t.is_alert ? '<span class="badge-pill cherry-pill">This alert</span>' : ''}</div>
          <div class="inv-tl-type">${this.esc(t.event_type || '')}</div>
          <div class="inv-tl-msg">${this.esc(t.message)}</div>
        </div>
      </div>`).join('');
  },

  renderAssets(inc) {
    const el = document.getElementById('dossier-assets');
    if (!el) return;
    const corr = inc.investigation && inc.investigation.correlation;
    const chips = (arr) => (arr && arr.length) ? arr.map(a => `<span class="asset-chip">${this.esc(a)}</span>`).join('') : '<span class="dossier-muted">None recorded</span>';
    el.innerHTML = `
      <table class="forensic-table"><tbody>
        <tr><td>Source</td><td><code>${this.esc(inc.source_ip || 'N/A')}</code> ${inc.investigation && inc.investigation.source_location ? this.esc(inc.investigation.source_location) : ''}</td></tr>
        <tr><td>Hosts</td><td>${chips(corr ? corr.distinct_hosts : [inc.host].filter(Boolean))}</td></tr>
        <tr><td>Users</td><td>${chips(corr ? corr.distinct_users : [inc.user].filter(Boolean))}</td></tr>
        <tr><td>Related events</td><td>${corr ? `${corr.related_events} (${corr.related_anomalous} anomalous, ${corr.failed_auth_count} failed logins)` : 'N/A'}</td></tr>
        <tr><td>Event types</td><td>${corr ? chips(Object.entries(corr.event_types).map(([k, v]) => `${k} ×${v}`)) : 'N/A'}</td></tr>
      </tbody></table>`;
  },

  renderAnalystPanel(inc) {
    const el = document.getElementById('dossier-analyst');
    if (!el) return;
    const name = this.analystName();
    const initials = name.split(/\s+/).map(p => p[0]).join('').substring(0, 2).toUpperCase();
    el.innerHTML = `
      <div class="assigned-analyst-card">
        <div class="avatar-circle">${this.esc(initials)}</div>
        <div>
          <strong style="font-size:0.8rem; color:var(--text-ink);">${this.esc(name)}</strong>
          <div style="font-size:0.68rem; color:var(--text-muted);">Signed-in analyst &bull; approval authority</div>
        </div>
      </div>
      <table class="forensic-table mt-2"><tbody>
        <tr><td>Status</td><td><span class="inc-state-pill ${this.statusClass(inc.status)}">${this.esc(this.statusLabel(inc.status))}</span></td></tr>
        <tr><td>Decided by</td><td>${this.esc(inc.decided_by || 'Pending human decision')}</td></tr>
        <tr><td>Decided at</td><td>${this.esc(inc.decided_at || '-')}</td></tr>
        <tr><td>Analyst note</td><td>${this.esc(inc.analyst_note || '-')}</td></tr>
      </tbody></table>`;
  },

  renderDossierActions(inc) {
    const el = document.getElementById('dossier-actions');
    if (!el) return;
    const siblings = this.siblingsAwaiting(inc);
    const btn = (action, cls, icon, label, extra = '') =>
      `<button class="${cls}" data-dossier-action="${action}" ${extra}><i data-lucide="${icon}"></i> ${label}</button>`;
    let html = '';

    if (inc.status === 'Awaiting Approval') {
      html = `
        <div class="approval-heading"><i data-lucide="user-check"></i> Human approval required: review the AI proposal, then approve or reject.</div>
        <input type="text" class="approval-note" id="approval-note" placeholder="Optional note for the audit record" value="${this.esc(this.noteDraft)}" />
        <div class="d-flex gap-2 flex-wrap">
          ${btn('approve', 'btn-cherry-primary', 'check-circle', 'Approve &amp; Resolve')}
          ${siblings.length ? btn('approve-related', 'btn-outline-cherry', 'check-check', `Approve + ${siblings.length} related`, `title="Also resolve ${siblings.length} other '${this.esc(inc.title)}' alerts from ${this.esc(inc.source_ip)}"`) : ''}
          ${btn('reject', 'btn-cream-action', 'x-circle', 'Reject (manual)')}
          ${btn('rerun', 'btn-cream-action', 'refresh-cw', 'Re-run AI')}
        </div>`;
    } else if (inc.status === 'OPEN') {
      html = `<div class="d-flex gap-2 flex-wrap">${btn('rerun', 'btn-cherry-primary', 'bot', 'Run AI investigation now')}</div>`;
    } else if (inc.status === 'AI Investigating') {
      html = `<div class="d-flex gap-2"><button class="btn-cream-action" disabled><span class="pulse-dot"></span> AI investigating&hellip;</button></div>`;
    } else if (inc.status === 'Investigating') {
      html = `
        <div class="approval-heading"><i data-lucide="search"></i> Manual investigation in progress.</div>
        <input type="text" class="approval-note" id="approval-note" placeholder="Resolution note" value="${this.esc(this.noteDraft)}" />
        <div class="d-flex gap-2 flex-wrap">
          ${btn('resolve', 'btn-cherry-primary', 'check-circle', 'Mark Resolved')}
          ${btn('rerun', 'btn-cream-action', 'refresh-cw', 'Re-run AI')}
        </div>`;
    } else {
      html = `<div class="d-flex gap-2 flex-wrap">${btn('reopen', 'btn-cream-action', 'rotate-ccw', 'Reopen')}</div>`;
    }
    // Containment and evidence export are available whatever the triage status
    const hasIp = inc.source_ip && inc.source_ip !== 'Unknown';
    const hasHost = inc.host && inc.host !== 'Unknown';
    html += `<div class="d-flex gap-2 flex-wrap" style="margin-top:8px;">
      ${hasIp ? btn('block-ip', 'btn-outline-cherry', 'lock', `Block IP ${this.esc(inc.source_ip)}`) : ''}
      ${hasHost ? btn('isolate-host', 'btn-cream-action', 'shield-ban', `Isolate ${this.esc(inc.host)}`) : ''}
      ${btn('dossier', 'btn-cream-action', 'download', 'Dossier JSON')}
    </div>`;
    el.innerHTML = html;

    const note = document.getElementById('approval-note');
    if (note) note.addEventListener('input', (e) => { this.noteDraft = e.target.value; });
    el.querySelectorAll('[data-dossier-action]').forEach(b => {
      b.addEventListener('click', () => {
        const a = b.dataset.dossierAction;
        if (a === 'approve') this.approveActive(false);
        else if (a === 'approve-related') this.approveActive(true);
        else if (a === 'reject') this.rejectActive();
        else if (a === 'rerun') this.runInvestigation(inc.id);
        else if (a === 'resolve') this.resolveManually(inc.id);
        else if (a === 'reopen') this.moveKanbanCard(inc.id, 'OPEN');
        else if (a === 'block-ip' || a === 'isolate-host' || a === 'dossier') this.alertCenterAction(a, inc);
      });
    });
  },

  async resolveManually(id) {
    try {
      await LogVaultAPI._postJSON(`/api/alerts/${encodeURIComponent(id)}/status`,
        { status: 'Resolved', analyst: this.analystName(), note: this.noteDraft || 'Resolved after manual investigation' });
      Utils.showToast(`Resolved by ${this.analystName()}.`, 'success');
      this.noteDraft = '';
    } catch (err) {
      Utils.showToast(`Could not resolve: ${err.message}`, 'error');
    }
    await this.fetchData();
  },

  async alertCenterAction(action, inc) {
    if (action === 'dossier') {
      this.activeIncidentId = inc.id;
      return this.downloadDossier();
    }
    const kind = action === 'block-ip' ? 'ip' : 'host';
    const value = kind === 'ip' ? inc.source_ip : inc.host;
    const reason = window.prompt(`${kind === 'ip' ? 'Block IP' : 'Isolate host'} ${value}?\n\nNew logs involving it will raise CRITICAL alerts and it is added to the firewall export. Reason:`, inc.title || '');
    if (reason === null) return;
    try {
      const res = await LogVaultAPI.contain(kind, value, reason, inc.id);
      Utils.showToast(res.already_contained ? `${value} was already contained.` : `${value} contained.`, 'success');
      await this.fetchData();
    } catch (err) {
      Utils.showToast(`Could not contain: ${err.message}`, 'error');
    }
  },

  clearIncidentDossier() {
    const set = (elId, text) => { const el = document.getElementById(elId); if (el) el.innerText = text; };
    set('dossier-main-title', 'No Incident Selected');
    set('dossier-desc-text', 'Select an incident from the queue to view details.');
    ['ai-investigation-card', 'dossier-timeline', 'dossier-assets', 'dossier-analyst', 'dossier-actions'].forEach(elId => {
      const el = document.getElementById(elId);
      if (el) el.innerHTML = '';
    });
  },

  // ------------------------------------------------------------ Anomaly screen: one incident

  renderIncidentPicker() {
    const select = document.getElementById('incident-select');
    if (!select) return;
    select.innerHTML = this.alerts.length
      ? this.alerts.slice(0, 200).map(a => `<option value="${this.esc(a.id)}">[${this.esc(a.severity)}] ${this.esc(a.title)} · ${this.esc(a.source_ip || a.host || 'no source')} · ${this.esc(a.status)}</option>`).join('')
      : '<option value="">No alerts yet</option>';
    if (this.activeIncidentId) select.value = this.activeIncidentId;
    if (!this.alerts.length) this.renderIncident(null);
  },

  // Open an alert on the Anomaly screen (dashboard threat feed, picker)
  async openIncident(id, quiet = false) {
    if (!id) id = this.alerts.length ? this.alerts[0].id : null;
    if (!id) {
      this.renderIncident(null);
      return;
    }
    this.activeIncidentId = id;
    const select = document.getElementById('incident-select');
    if (select) select.value = id;
    try {
      const [dossier, cont] = await Promise.all([
        LogVaultAPI._getJSON(`/api/alerts/${encodeURIComponent(id)}/dossier`, 20000),
        LogVaultAPI.getContainment()
      ]);
      this.incident = dossier;
      this.containment = cont.entries;
      this.renderIncident(dossier);
    } catch (err) {
      if (!quiet) Utils.showToast(`Could not load incident: ${err.message}`, 'error');
    }
  },

  renderIncident(d) {
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    if (!d) {
      this.incident = null;
      this.graph = null;
      set('incident-title', 'No anomalies yet');
      set('incident-desc', 'Upload or paste logs in the Normalizer. Events that match a detection rule, look obfuscated, or that the local AI flags will appear here.');
      ['incident-id-badge', 'incident-detected', 'incident-sev-tag', 'incident-score', 'incident-src-ip', 'incident-src-sub', 'incident-target',
        'incident-target-sub', 'incident-related', 'incident-related-sub', 'incident-duration', 'incident-duration-sub', 'incident-timeline-badge']
        .forEach(id => set(id, '&mdash;'));
      set('incident-timeline', '');
      return;
    }
    const a = d.alert;
    const an = a.anomaly || {};
    const findings = an.findings || [];
    const useful = v => v && !['unknown', 'none', '-', 'n/a'].includes(String(v).toLowerCase());
    const sev = an.max_severity && an.max_severity !== 'NONE' ? an.max_severity : (a.severity || 'MEDIUM');
    const triage = d.triage || {};

    set('incident-id-badge', `ALERT ${this.esc(a.id.slice(0, 8).toUpperCase())} &bull; ${this.esc(triage.status || 'OPEN')}`);
    set('incident-sev-badge', `<i data-lucide="shield-alert"></i> ${this.esc(sev)} ANOMALY`);
    set('incident-detected', a.timestamp ? `Log time ${this.esc(a.timestamp)}` : 'No timestamp in the log record');
    set('incident-title', this.esc(findings.length ? findings[0].rule_name : 'Anomaly detected'));
    set('incident-desc', this.esc(findings.map(f => f.description || `${f.rule_name}${f.mitre_technique ? ` (${f.mitre_technique})` : ''}`).join(' · ') || a.message || ''));
    set('incident-sev-tag', this.esc(sev));
    set('incident-score', String(an.threat_score ?? 0));

    // Metrics
    const rel = d.related_events;
    const relAnom = rel.filter(e => e.anomaly && e.anomaly.is_anomalous).length;
    set('incident-src-ip', this.esc(useful(a.source_ip) ? a.source_ip : 'none'));
    const fromIp = rel.filter(e => e.source_ip === a.source_ip).length;
    set('incident-src-sub', useful(a.source_ip) ? `${fromIp} other event${fromIp === 1 ? '' : 's'} from this IP` : 'no source IP in this record');
    const target = useful(a.host) ? a.host : useful(a.destination_ip) ? a.destination_ip : 'unknown';
    set('incident-target', this.esc(target));
    set('incident-target-sub', this.esc([useful(a.user) ? `user ${a.user}` : null, a.destination_port ? `port ${a.destination_port}` : null, a.process || null].filter(Boolean).join(' · ') || a.detected_format || ''));
    set('incident-related', rel.length.toLocaleString());
    set('incident-related-sub', `${relAnom} anomalous &bull; same IP, user or host`);
    const times = [a, ...rel].map(e => e.timestamp).filter(Boolean).sort();
    set('incident-duration', times.length > 1 ? this.esc(times[0]) : this.esc(a.timestamp || '—'));
    set('incident-duration-sub', times.length > 1 ? `to ${this.esc(times[times.length - 1])} (log times)` : 'single event');

    // Timeline: this alert + related events, grouped by log minute
    const all = [a, ...rel];
    const groups = {};
    all.forEach(e => {
      const key = (e.timestamp || '').slice(0, 16) || 'no timestamp';
      const g = groups[key] || (groups[key] = { key, events: 0, anomalies: 0, types: {} });
      g.events += 1;
      if (e.anomaly && e.anomaly.is_anomalous) g.anomalies += 1;
      const t = e.event_type || 'EVENT';
      g.types[t] = (g.types[t] || 0) + 1;
    });
    const list = Object.values(groups).sort((x, y) => x.key.localeCompare(y.key)).slice(-12);
    set('incident-timeline-badge', `${all.length} events &bull; ${list.length} time groups`);
    set('incident-timeline', list.map(g => `
      <div class="timeline-step-item">
        <span class="timeline-time-col">${this.esc(g.key.length > 10 ? g.key.slice(-5) : g.key)}</span>
        <span class="step-node-dot"></span>
        <div class="step-details-card"${g.anomalies ? ' style="border-left: 3px solid var(--status-red);"' : ''}>
          <div><strong>${this.esc(Object.entries(g.types).sort((x, y) => y[1] - x[1]).map(([t, n]) => `${t} ×${n}`).join(', '))}</strong>
            <span class="step-note-text">&bull; ${this.esc(g.key)}</span></div>
          <span class="step-fail-count">${g.anomalies} anomalous / ${g.events}</span>
        </div>
      </div>`).join(''));

    // Containment state and button labels
    const contained = (this.containment || []).filter(c => c.value === a.source_ip || c.value === a.host || c.alert_id === a.id);
    set('incident-containment', contained.length ? contained.map((c, i) =>
      `<div style="margin-bottom:4px;"><span class="badge-pill crit-pill" style="font-size:0.6rem;">${c.kind.toUpperCase()}</span>
        <strong>${this.esc(c.value)}</strong> contained by ${this.esc(c.created_by)} ${App.timeAgo(c.created_at)} &bull; ${c.events_since} events since
        <button class="btn-cream-action btn-sm" style="margin-left:6px;" onclick="AnomalyModule.releaseContainment(${i})">Release</button></div>`).join('')
      : 'None. Blocking or isolating adds the asset to the containment list: new logs involving it raise CRITICAL alerts, and it is included in the firewall rule export (Settings).');
    this.incidentContainment = contained;
    const ipContained = contained.some(c => c.kind === 'ip' && c.value === a.source_ip);
    const hostContained = contained.some(c => c.kind === 'host' && c.value === a.host);
    set('btn-block-source-ip-label', useful(a.source_ip) ? (ipContained ? `${this.esc(a.source_ip)} blocked` : `Block IP ${this.esc(a.source_ip)}`) : 'No source IP');
    set('btn-contain-server-label', useful(a.host) ? (hostContained ? `${this.esc(a.host)} isolated` : `Isolate Host ${this.esc(a.host)}`) : 'No host to isolate');
    const dis = (id, v) => { const el = document.getElementById(id); if (el) el.disabled = v; };
    dis('btn-block-source-ip', !useful(a.source_ip) || ipContained);
    dis('btn-contain-server', !useful(a.host) || hostContained);

    this.graph = this.buildGraph(a, rel);
    set('incident-graph-tag', `<i data-lucide="radio" style="width:12px; color:var(--status-red);"></i> ${this.graph.nodes.length} entities`);
    if (window.lucide) lucide.createIcons();
  },

  // Entities of the alert and how they co-occur in related events. The alert source is the gold
  // sphere, the most-hit host (or destination) is the summit target, height = share of anomalous events.
  buildGraph(a, rel) {
    const useful = v => v && !['unknown', 'none', '-', 'n/a'].includes(String(v).toLowerCase());
    const events = [a, ...rel];
    const nodes = {};
    const links = {};
    const touch = (id, kind, anomalous) => {
      const n = nodes[id] || (nodes[id] = { id, kind, count: 0, anomalous: 0 });
      n.count += 1;
      if (anomalous) n.anomalous += 1;
    };
    events.forEach(e => {
      const anomalous = !!(e.anomaly && e.anomaly.is_anomalous);
      const ents = [];
      if (useful(e.source_ip)) ents.push([e.source_ip, e.source_ip === a.source_ip ? 'source' : 'peer']);
      if (useful(e.host)) ents.push([e.host, 'host']);
      if (useful(e.user)) ents.push([e.user, 'user']);
      if (useful(e.destination_ip)) ents.push([e.destination_ip, 'destination']);
      // Detection rules the event triggered (what the source was doing)
      ((e.anomaly && e.anomaly.findings) || []).forEach(f => {
        if (f.rule_name && f.type !== 'severity_flag') ents.push([f.rule_name, 'rule']);
      });
      ents.forEach(([id, kind]) => touch(id, kind, anomalous));
      // Every pair of entities seen in the same event is a link
      for (let i = 0; i < ents.length; i++) {
        for (let j = i + 1; j < ents.length; j++) {
          const key = [ents[i][0], ents[j][0]].sort().join('\u0000');
          const l = links[key] || (links[key] = { from: ents[i][0], to: ents[j][0], count: 0, anomalous: 0 });
          l.count += 1;
          if (anomalous) l.anomalous += 1;
        }
      }
    });

    const source = useful(a.source_ip) ? a.source_ip : null;
    if (source && nodes[source]) nodes[source].kind = 'source';
    const candidates = Object.values(nodes).filter(n => n.id !== source);
    // Summit: the most-hit host or destination, else the most-triggered detection rule
    const byCount = (x, y) => y.count - x.count;
    const target = candidates.filter(n => n.kind === 'host' || n.kind === 'destination').sort(byCount)[0]
      || candidates.filter(n => n.kind === 'rule').sort(byCount)[0] || candidates.sort(byCount)[0] || null;
    const others = candidates.filter(n => n !== target).sort((x, y) => y.count - x.count).slice(0, 10);

    // Place on the floor: source left, target centre-right summit, others fanned around
    const placed = [];
    if (source) placed.push({ ...nodes[source], type: 'attacker', gx: 0.16, gy: 0.58, elev: 10, radius: 15 });
    if (target) placed.push({ ...target, type: 'target', gx: 0.6, gy: 0.46, elev: 45 + 50 * (target.anomalous / target.count), radius: 16 });
    others.forEach((n, i) => {
      const col = i % 5, row = Math.floor(i / 5);
      placed.push({
        ...n, type: 'node',
        gx: 0.34 + col * 0.13 + (row ? 0.06 : 0),
        gy: (i % 2 ? 0.74 : 0.34) + row * 0.08,
        elev: 14 + 70 * (n.anomalous / Math.max(1, n.count)),
        radius: 8 + Math.min(5, n.count)
      });
    });
    const ids = new Set(placed.map(n => n.id));
    const keptLinks = Object.values(links).filter(l => ids.has(l.from) && ids.has(l.to));
    const maxLink = Math.max(1, ...keptLinks.map(l => l.count));
    return {
      nodes: placed,
      links: keptLinks.map(l => ({ ...l, arc: 10 + 24 * (l.count / maxLink) })),
      sourceId: source,
      targetId: target ? target.id : null,
      events: events.length,
      anomalous: events.filter(e => e.anomaly && e.anomaly.is_anomalous).length,
      threat: (a.anomaly && a.anomaly.threat_score) || 0,
      severity: (a.anomaly && a.anomaly.max_severity && a.anomaly.max_severity !== 'NONE') ? a.anomaly.max_severity : (a.severity || 'MEDIUM'),
      technique: ((a.anomaly && a.anomaly.findings) || []).map(f => f.mitre_technique).find(Boolean) || null
    };
  },

  // Rising mist behind the graph (decoration)
  smokeParticles: Array.from({ length: 36 }, () => ({
    x: 0.25 + Math.random() * 0.55,
    y: 0.35 + Math.random() * 0.45,
    elev: Math.random() * 110,
    size: 16 + Math.random() * 28,
    speed: 0.2 + Math.random() * 0.5,
    opacity: 0.04 + Math.random() * 0.07
  })),

  startGraphLoop() {
    if (this.animFrameId) cancelAnimationFrame(this.animFrameId);
    const loop = () => {
      if (Navigation.activeScreen !== 'anomalies') {
        this.animFrameId = null;
        return;
      }
      this.drawGraph();
      this.animFrameId = requestAnimationFrame(loop);
    };
    this.animFrameId = requestAnimationFrame(loop);
  },

  drawGraph() {
    const canvas = document.getElementById('threatGraphCanvas');
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = rect.width || 800;
    const h = rect.height || 380;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    // 1. Perspective floor grid
    ctx.beginPath();
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.08)' : 'rgba(116, 21, 42, 0.08)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 9; i++) {
      const gy = h * 0.32 + i * (h * 0.068);
      const span = i / 9;
      ctx.moveTo(w * 0.08 - span * (w * 0.03), gy);
      ctx.lineTo(w * 0.92 + span * (w * 0.03), gy);
    }
    for (let j = 0; j <= 14; j++) {
      ctx.moveTo(w * 0.12 + j * (w * 0.055), h * 0.32);
      ctx.lineTo(w * 0.06 + j * (w * 0.064), h * 0.94);
    }
    ctx.stroke();

    const g = this.graph;
    if (!g || !g.nodes.length) {
      ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
      ctx.font = '600 14px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(g ? 'This alert has no IP, host or user to graph.' : 'No anomalies detected.', w / 2, h / 2);
      return;
    }

    const contained = new Set((this.containment || []).map(c => c.value));
    const map = {};
    g.nodes.forEach(n => {
      const fx = n.gx * w, fy = n.gy * h;
      map[n.id] = { ...n, fx, fy, px: fx, py: fy - n.elev };
    });

    // 2. Floor pads and drop stems
    Object.values(map).forEach(n => {
      ctx.beginPath();
      ctx.ellipse(n.fx, n.fy, n.radius * 1.5, n.radius * 0.55, 0, 0, Math.PI * 2);
      ctx.fillStyle = isDark ? 'rgba(0, 0, 0, 0.45)' : 'rgba(116, 21, 42, 0.12)';
      ctx.fill();
      if (n.elev > 10) {
        ctx.beginPath();
        ctx.moveTo(n.fx, n.fy);
        ctx.lineTo(n.px, n.py);
        ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.18)' : 'rgba(116, 21, 42, 0.16)';
        ctx.setLineDash([2, 4]);
        ctx.stroke();
        ctx.setLineDash([]);
      }
    });

    // 3. Mist
    const mist = isDark ? '232, 160, 170' : '116, 21, 42';
    this.smokeParticles.forEach(p => {
      p.elev = (p.elev + p.speed) % 130;
      const sx = p.x * w, sy = p.y * h - p.elev;
      const grad = ctx.createRadialGradient(sx, sy, 2, sx, sy, p.size);
      grad.addColorStop(0, `rgba(${mist}, ${p.opacity})`);
      grad.addColorStop(1, `rgba(${mist}, 0)`);
      ctx.beginPath();
      ctx.arc(sx, sy, p.size, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
    });

    // 4. Curved arcs: attack paths (touching the source or target) glow, with particles
    g.links.forEach((l, li) => {
      const s = map[l.from], d = map[l.to];
      if (!s || !d) return;
      const attack = l.anomalous > 0 && [g.sourceId, g.targetId].some(id => id === l.from || id === l.to);
      const midX = (s.px + d.px) / 2;
      const midY = Math.min(s.py, d.py) - l.arc;
      ctx.beginPath();
      ctx.moveTo(s.px, s.py);
      ctx.quadraticCurveTo(midX, midY, d.px, d.py);
      if (attack) {
        const grad = ctx.createLinearGradient(s.px, s.py, d.px, d.py);
        grad.addColorStop(0, '#C47A16');
        grad.addColorStop(0.6, '#B4233C');
        grad.addColorStop(1, '#74152A');
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1.6 + Math.min(3, l.count / 2);
      } else {
        ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.28)' : 'rgba(116, 21, 42, 0.22)';
        ctx.lineWidth = 1.4;
      }
      ctx.stroke();

      // Event count on the arc
      ctx.font = '700 9px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#E8A0AA' : '#74152A';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(`${l.count}`, midX, (Math.min(s.py, d.py) + midY) / 2 - 2);

      if (attack) {
        for (let p = 0; p < 3; p++) {
          const t = ((now / 1500) + p / 3 + li * 0.07) % 1;
          const u = 1 - t;
          ctx.beginPath();
          ctx.arc(u * u * s.px + 2 * u * t * midX + t * t * d.px, u * u * s.py + 2 * u * t * midY + t * t * d.py, 3.4, 0, Math.PI * 2);
          ctx.fillStyle = '#FFFFFF';
          ctx.shadowColor = '#C6283D';
          ctx.shadowBlur = 9;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }
    });

    // 5. Target summit: spinning rings, halo, pulsing sphere
    const target = map[g.targetId];
    if (target) {
      const spin = (now / 1200) % (Math.PI * 2);
      for (let r = 1; r <= 3; r++) {
        ctx.save();
        ctx.translate(target.px, target.py);
        ctx.rotate(spin * (r % 2 === 0 ? 1 : -1));
        ctx.beginPath();
        ctx.ellipse(0, 0, target.radius * (1.8 + r * 0.9), target.radius * (0.9 + r * 0.45), 0, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(78, 205, 196, ${0.85 - r * 0.22})`;
        ctx.lineWidth = 2.2 - r * 0.4;
        ctx.shadowColor = 'rgba(78, 205, 196, 0.8)';
        ctx.shadowBlur = 12;
        ctx.stroke();
        ctx.restore();
      }
      const halo = ctx.createRadialGradient(target.px, target.py, 4, target.px, target.py, target.radius * 3.8);
      halo.addColorStop(0, 'rgba(78, 205, 196, 0.4)');
      halo.addColorStop(0.6, 'rgba(78, 205, 196, 0.12)');
      halo.addColorStop(1, 'rgba(78, 205, 196, 0)');
      ctx.beginPath();
      ctx.arc(target.px, target.py, target.radius * 3.8, 0, Math.PI * 2);
      ctx.fillStyle = halo;
      ctx.fill();
      const tr = target.radius + Math.sin(now / 200) * 2;
      const tg = ctx.createRadialGradient(target.px - 4, target.py - 4, 2, target.px, target.py, tr);
      tg.addColorStop(0, '#FF4D6D');
      tg.addColorStop(0.5, '#B4233C');
      tg.addColorStop(1, '#4A0814');
      ctx.beginPath();
      ctx.arc(target.px, target.py, tr, 0, Math.PI * 2);
      ctx.fillStyle = tg;
      ctx.fill();
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = 2.4;
      ctx.stroke();
      this.drawNodePillBadge(ctx, target.px, target.py - tr - 12, `${target.id} (${target.kind})`, isDark, contained.has(target.id));
    }

    // 6. Other spheres
    Object.values(map).forEach(n => {
      if (n.type === 'target') return;
      const r = n.radius;
      const sg = ctx.createRadialGradient(n.px - r * 0.35, n.py - r * 0.35, 1, n.px, n.py, r);
      if (n.type === 'attacker') {
        sg.addColorStop(0, '#FFD166');
        sg.addColorStop(0.6, '#F4A261');
        sg.addColorStop(1, '#8C4A00');
      } else if (n.kind === 'rule') {
        sg.addColorStop(0, '#E6FFFB');
        sg.addColorStop(0.45, '#2A9D8F');
        sg.addColorStop(1, '#0B4F47');
      } else if (n.kind === 'user') {
        sg.addColorStop(0, '#FFF1D6');
        sg.addColorStop(0.45, '#C47A16');
        sg.addColorStop(1, '#6B3D00');
      } else {
        sg.addColorStop(0, '#FFE6EA');
        sg.addColorStop(0.4, '#C6283D');
        sg.addColorStop(1, '#5C1021');
      }
      ctx.beginPath();
      ctx.arc(n.px, n.py, r, 0, Math.PI * 2);
      ctx.fillStyle = sg;
      ctx.fill();
      ctx.strokeStyle = contained.has(n.id) ? '#E53E3E' : 'rgba(255, 248, 240, 0.9)';
      ctx.lineWidth = contained.has(n.id) ? 3 : 1.8;
      ctx.stroke();
      const label = n.type === 'attacker' ? `${n.id} (source)` : `${n.id} (${n.kind})`;
      this.drawNodePillBadge(ctx, n.px, n.py - r - 11, label, isDark, contained.has(n.id));
    });

    // 7. Summary card with real figures
    if (target) {
      // Top-right corner: clear of the nodes and of the containment panel (bottom-right)
      const x = w - 200;
      const y = 12;
      this.drawTargetTooltipCard(ctx, x, y, isDark, [
        ['Related events', `${g.events}`, '#C6283D'],
        ['Anomalous', `${g.anomalous}`, '#C47A16'],
        [g.technique ? 'MITRE' : 'Risk', g.technique ? g.technique.split(' - ')[0] : `${g.severity} · ${g.threat}`, '#C6283D']
      ]);
    }
  },

  drawNodePillBadge(ctx, x, y, text, isDark, contained = false) {
    text = String(text).length > 30 ? String(text).slice(0, 29) + '…' : String(text);
    if (contained) text = `🔒 ${text}`;
    ctx.font = '700 10px JetBrains Mono, monospace';
    const boxW = ctx.measureText(text).width + 12;
    const boxH = 17;
    ctx.fillStyle = isDark ? 'rgba(34, 20, 24, 0.92)' : 'rgba(255, 248, 240, 0.95)';
    ctx.strokeStyle = contained ? '#E53E3E' : (isDark ? 'rgba(232, 160, 170, 0.35)' : 'rgba(116, 21, 42, 0.25)');
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(x - boxW / 2, y - boxH / 2, boxW, boxH, 4);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = isDark ? '#FFF8F0' : '#24191B';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, x, y);
    ctx.textBaseline = 'alphabetic';
  },

  drawTargetTooltipCard(ctx, x, y, isDark, rows) {
    const cardW = 188;
    const cardH = 18 + rows.length * 17;
    ctx.fillStyle = isDark ? 'rgba(28, 14, 18, 0.95)' : 'rgba(255, 248, 240, 0.98)';
    ctx.strokeStyle = 'rgba(198, 40, 61, 0.45)';
    ctx.lineWidth = 1.4;
    ctx.shadowColor = 'rgba(116, 21, 42, 0.18)';
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.roundRect(x, y, cardW, cardH, 6);
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;
    ctx.textAlign = 'left';
    rows.forEach(([label, value, color], i) => {
      const ry = y + 18 + i * 17;
      ctx.font = '600 9.5px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
      ctx.fillText(`${label}:`, x + 10, ry);
      ctx.font = '800 10px JetBrains Mono, monospace';
      ctx.fillStyle = color;
      ctx.fillText(value, x + 104, ry);
    });
  },

  async containActive(kind) {
    const d = this.incident;
    if (!d) return;
    const value = kind === 'ip' ? d.alert.source_ip : d.alert.host;
    if (!value) {
      Utils.showToast(`This alert has no ${kind === 'ip' ? 'source IP' : 'host'}.`, 'warning');
      return;
    }
    const findings = (d.alert.anomaly && d.alert.anomaly.findings) || [];
    const reason = window.prompt(`${kind === 'ip' ? 'Block IP' : 'Isolate host'} ${value}?\n\nNew logs involving it will raise CRITICAL alerts and it is added to the firewall export. Reason:`,
      findings.length ? findings[0].rule_name : '');
    if (reason === null) return;
    try {
      const res = await LogVaultAPI.contain(kind, value, reason, d.alert.id);
      Utils.showToast(res.already_contained ? `${value} was already contained.` : `${value} contained. Export firewall rules from Settings.`, 'success');
      await this.fetchData();
      this.openIncident(d.alert.id, true);
    } catch (err) {
      Utils.showToast(`Could not contain: ${err.message}`, 'error');
    }
  },

  async releaseContainment(i) {
    const c = (this.incidentContainment || [])[i];
    if (!c || !window.confirm(`Release ${c.value}? New logs involving it will no longer be raised as critical.`)) return;
    try {
      await LogVaultAPI.releaseContainment(c.id);
      Utils.showToast(`${c.value} released.`, 'success');
      this.openIncident(this.activeIncidentId, true);
    } catch (err) {
      Utils.showToast(`Could not release: ${err.message}`, 'error');
    }
  },

  viewActiveLogs() {
    const d = this.incident;
    if (d && d.alert.source_ip) LogStream.filterByIp(d.alert.source_ip);
    else Navigation.navigateTo('live-logs');
  },

  async downloadDossier() {
    if (!this.activeIncidentId) return;
    try {
      const r = await LogVaultAPI.download(`/api/alerts/${encodeURIComponent(this.activeIncidentId)}/dossier`, 'logvault-dossier.json');
      Utils.showToast(`Downloaded ${r.name}.`, 'success');
    } catch (err) {
      Utils.showToast(`Download failed: ${err.message}`, 'error');
    }
  },

  openInAlertCenter() {
    Navigation.navigateTo('alerts');
    if (this.activeIncidentId) this.loadIncidentDossier(this.activeIncidentId);
  },
};

window.AnomalyModule = AnomalyModule;
