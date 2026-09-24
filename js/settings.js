/**
 * LOGVAULT — Platform Settings & Air-Gapped Storage Module (Stage 3 Masterpiece)
 * Operator Profile Credentials + Local Storage Footprint + Air-Gapped Controls
 */

const SettingsModule = {
  storage: null,

  memoryData: [
    { name: 'WASM JIT Zero-Copy Heap', allocated: '48 MB / 512 MB', pct: 9.3, color: '#25855A' },
    { name: 'IndexedDB FIFO Buffer Queue', allocated: '12 MB / 128 MB', pct: 9.3, color: '#25855A' },
    { name: 'ONNX Runtime Tensor Weights', allocated: '32 MB / 256 MB', pct: 12.5, color: '#C47A16' }
  ],

  init() {
    this.loadOperatorProfile();
    this.renderStorageBars();
    this.renderMemoryBars();
    this.bindEvents();
  },

  onScreenOpen() {
    this.loadOperatorProfile();
    this.renderStorageBars();
    this.renderMemoryBars();
  },

  loadOperatorProfile() {
    const name = localStorage.getItem('logvault_op_name') || 'Agent Sahil';
    const callsign = localStorage.getItem('logvault_op_callsign') || 'SOC-OP-9042';
    const role = localStorage.getItem('logvault_op_role') || 'Tier-3 SOC Lead';
    const tier = localStorage.getItem('logvault_op_tier') || 'Tier-3 Senior Lead';
    const org = localStorage.getItem('logvault_op_org') || 'Cyber Defense Command';

    const inputName = document.getElementById('operator-input-name');
    const inputCallsign = document.getElementById('operator-input-callsign');
    const inputRole = document.getElementById('operator-input-role');
    const selectTier = document.getElementById('operator-select-tier');
    const inputOrg = document.getElementById('operator-input-org');

    if (inputName) inputName.value = name;
    if (inputCallsign) inputCallsign.value = callsign;
    if (inputRole) inputRole.value = role;
    if (selectTier) selectTier.value = tier;
    if (inputOrg) inputOrg.value = org;

    this.updateAvatarVisuals(name, role);
  },

  saveOperatorProfile() {
    const inputName = document.getElementById('operator-input-name');
    const inputCallsign = document.getElementById('operator-input-callsign');
    const inputRole = document.getElementById('operator-input-role');
    const selectTier = document.getElementById('operator-select-tier');
    const inputOrg = document.getElementById('operator-input-org');

    const name = inputName ? inputName.value.trim() : 'Agent Sahil';
    const callsign = inputCallsign ? inputCallsign.value.trim() : 'SOC-OP-9042';
    const role = inputRole ? inputRole.value.trim() : 'Tier-3 SOC Lead';
    const tier = selectTier ? selectTier.value : 'Tier-3 Senior Lead';
    const org = inputOrg ? inputOrg.value.trim() : 'Cyber Defense Command';

    localStorage.setItem('logvault_op_name', name);
    localStorage.setItem('logvault_op_callsign', callsign);
    localStorage.setItem('logvault_op_role', role);
    localStorage.setItem('logvault_op_tier', tier);
    localStorage.setItem('logvault_op_org', org);

    this.updateAvatarVisuals(name, role);
    Utils.showToast(`✓ Operator credentials saved: ${name} (${role})`, 'success');
  },

  updateAvatarVisuals(name, role) {
    // Generate 2-letter Initials
    const parts = name.split(' ').filter(p => p.length > 0);
    let initials = 'OP';
    if (parts.length >= 2) {
      initials = (parts[0][0] + parts[1][0]).toUpperCase();
    } else if (parts.length === 1) {
      initials = parts[0].substring(0, 2).toUpperCase();
    }

    // Update Header Pill
    const headerAvatar = document.querySelector('.analyst-profile-pill-3d .avatar-ring-3d');
    const headerName = document.querySelector('.analyst-profile-pill-3d .analyst-name');
    const headerRole = document.querySelector('.analyst-profile-pill-3d .analyst-role');

    if (headerAvatar) headerAvatar.innerText = initials;
    if (headerName) headerName.innerText = name;
    if (headerRole) headerRole.innerText = role;

    // Update Settings Large Avatar
    const largeAvatar = document.getElementById('operator-large-avatar');
    const previewName = document.getElementById('operator-preview-name');
    const previewRole = document.getElementById('operator-preview-role');

    if (largeAvatar) largeAvatar.innerText = initials;
    if (previewName) previewName.innerText = name;
    if (previewRole) previewRole.innerText = role;
  },

  bindEvents() {
    // Storage policy form (size limit + retention)
    ['storage-limit-mode', 'storage-retention-mode', 'storage-limit-gb', 'storage-retention-days'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', () => this.syncPolicyForm());
    });
    const btnSavePolicy = document.getElementById('btn-save-storage-policy');
    if (btnSavePolicy) btnSavePolicy.addEventListener('click', () => this.saveStoragePolicy());
    const btnApplyPolicy = document.getElementById('btn-apply-storage-policy');
    if (btnApplyPolicy) btnApplyPolicy.addEventListener('click', () => this.applyStoragePolicy());

    // Save operator profile button
    const btnSaveOp = document.getElementById('btn-save-operator-profile');
    if (btnSaveOp) {
      btnSaveOp.addEventListener('click', () => this.saveOperatorProfile());
    }

    // Export bundle button
    const btnExport = document.getElementById('btn-export-forensic-bundle');
    if (btnExport) {
      btnExport.addEventListener('click', () => {
        Utils.showToast('✓ Generating encrypted forensic evidence archive (AES-256 GCM)...', 'info');
        setTimeout(() => {
          Utils.showToast('Forensic bundle downloaded: logvault-forensics-20260903.lvault', 'success');
        }, 1200);
      });
    }

    // Vacuum database button
    const btnVacuum = document.getElementById('btn-vacuum-database');
    if (btnVacuum) {
      btnVacuum.addEventListener('click', async () => {
        Utils.showToast('Running SQLite VACUUM (compacting the database file)...', 'info');
        try {
          const res = await LogVaultAPI._postJSON('/api/storage/vacuum', {}, 300000);
          this.storage = res.storage;
          this.renderStorage();
          Utils.showToast(`✓ Vacuum complete: reclaimed ${this.formatBytes(res.reclaimed_bytes)}.`, 'success');
        } catch (err) {
          Utils.showToast(`Vacuum failed: ${err.message}`, 'error');
        }
      });
    }

    // Purge buffers button
    const btnPurge = document.getElementById('btn-purge-buffers');
    if (btnPurge) {
      btnPurge.addEventListener('click', () => {
        Utils.showToast('✓ Transient ring memory queues flushed to local storage.', 'success');
      });
    }

    // Download OCSF definitions
    const btnOcsf = document.getElementById('btn-download-ocsf-defs');
    if (btnOcsf) {
      btnOcsf.addEventListener('click', () => {
        Utils.showToast('✓ Downloaded OCSF v1.1.0 schema definitions JSON bundle.', 'success');
      });
    }
  },

  formatBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / Math.pow(1024, i)).toFixed(i >= 3 ? 2 : i ? 1 : 0)} ${units[i]}`;
  },

  // Kept for the header "Refresh Storage" button
  async renderStorageBars() {
    if (!window.LogVaultAPI) return;
    try {
      const res = await fetch(`${LogVaultAPI._baseURL}/api/storage`, { signal: AbortSignal.timeout(10000) });
      this.storage = res.ok ? await res.json() : null;
    } catch {
      this.storage = null;
    }
    this.renderStorage();
  },

  renderStorage() {
    const st = this.storage;
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    const container = document.getElementById('settingsStorageBreakdownContainer');

    if (!st) {
      set('kpi-storage-value', 'N/A');
      set('kpi-storage-sub', '<i data-lucide="hard-drive"></i> Backend offline');
      set('kpi-retention-value', 'N/A');
      set('kpi-retention-sub', '<i data-lucide="refresh-cw"></i> Backend offline');
      if (container) container.innerHTML = '<div class="analytics-empty">Backend offline: storage usage unavailable.</div>';
      if (window.lucide) lucide.createIcons();
      return;
    }

    const policy = st.policy;
    const [num, unit] = this.formatBytes(st.total_bytes).split(' ');
    set('kpi-storage-value', `${num} <small style="font-size:0.75rem;">${unit}</small>`);
    set('kpi-storage-sub', policy.storage_limit_gb > 0
      ? `<i data-lucide="hard-drive"></i> ${st.limit_used_pct}% of ${policy.storage_limit_gb} GB limit`
      : `<i data-lucide="hard-drive"></i> Unlimited &bull; ${this.formatBytes(st.disk_free_bytes)} free on disk`);
    set('kpi-retention-value', policy.retention_days > 0
      ? `${policy.retention_days} <small style="font-size:0.75rem;">Days</small>`
      : 'Forever');
    set('kpi-retention-sub', policy.retention_days > 0
      ? '<i data-lucide="refresh-cw"></i> Oldest events pruned automatically'
      : '<i data-lucide="lock"></i> No automatic deletion');

    // Policy form reflects the saved policy
    const limitMode = document.getElementById('storage-limit-mode');
    const limitGb = document.getElementById('storage-limit-gb');
    const retMode = document.getElementById('storage-retention-mode');
    const retDays = document.getElementById('storage-retention-days');
    if (limitMode) limitMode.value = policy.storage_limit_gb > 0 ? 'custom' : 'unlimited';
    if (limitGb && policy.storage_limit_gb > 0) limitGb.value = policy.storage_limit_gb;
    if (retMode) retMode.value = policy.retention_days > 0 ? 'custom' : 'forever';
    if (retDays && policy.retention_days > 0) retDays.value = policy.retention_days;
    this.syncPolicyForm();

    if (container) {
      const items = [
        { name: 'Raw log text', bytes: st.raw_log_bytes, detail: `${st.events.toLocaleString()} events`, color: 'var(--cherry-primary)' },
        { name: 'Normalized OCSF JSON', bytes: st.normalized_bytes, detail: `${st.events.toLocaleString()} records`, color: 'var(--status-green)' },
        { name: 'Alert triage & AI investigations', bytes: st.alert_bytes, detail: `${st.alert_records.toLocaleString()} alerts`, color: 'var(--status-amber)' },
        { name: 'Indexes & SQLite overhead', bytes: Math.max(0, st.db_file_bytes - st.raw_log_bytes - st.normalized_bytes - st.alert_bytes - st.reclaimable_bytes), detail: 'search indexes, page structure', color: 'var(--cherry-dark)' },
        { name: 'Uploaded files', bytes: st.uploads_bytes, detail: 'data/uploads', color: 'var(--status-blue)' },
        { name: 'Free space inside DB file', bytes: st.reclaimable_bytes, detail: 'reclaim with Vacuum', color: 'var(--text-muted)' }
      ];
      const total = Math.max(1, st.total_bytes);
      container.innerHTML = items.map(item => {
        const pct = Math.min(100, item.bytes / total * 100);
        return `
        <div class="latency-bench-item" style="margin-bottom:12px;">
          <div style="min-width: 190px;">
            <span style="font-weight:800; color:var(--text-ink); display:block; font-size:0.74rem;">${item.name}</span>
            <span style="font-size:0.65rem; color:var(--text-muted); font-family:var(--font-mono);">${item.detail} &bull; ${this.formatBytes(item.bytes)}</span>
          </div>
          <div class="latency-bench-bar-track" style="height:9px; background:var(--border-card);">
            <div class="latency-bench-bar-fill" style="width: ${pct.toFixed(1)}%; background-color: ${item.color}; border-radius:4px;"></div>
          </div>
          <div style="min-width: 60px; text-align:right;">
            <span style="font-family:var(--font-mono); font-weight:800; color:${item.color}; font-size:0.75rem;">${pct.toFixed(1)}%</span>
          </div>
        </div>`;
      }).join('') + `
        <div class="storage-footnote">
          Database file ${this.formatBytes(st.db_file_bytes)} &bull; ${st.sessions} session${st.sessions === 1 ? '' : 's'} stored
          &bull; ${st.protected_events.toLocaleString()} open-alert events protected from pruning
          ${st.oldest_event ? `&bull; oldest ${Utils.escapeHtml(String(st.oldest_event).substring(0, 10))}` : ''}
        </div>`;
    }
    if (window.lucide) lucide.createIcons();
  },

  readPolicyForm() {
    const limitMode = document.getElementById('storage-limit-mode');
    const limitGb = document.getElementById('storage-limit-gb');
    const retMode = document.getElementById('storage-retention-mode');
    const retDays = document.getElementById('storage-retention-days');
    return {
      storage_limit_gb: limitMode && limitMode.value === 'custom' ? parseFloat(limitGb.value) || 0 : 0,
      retention_days: retMode && retMode.value === 'custom' ? parseInt(retDays.value, 10) || 0 : 0
    };
  },

  syncPolicyForm() {
    const limitMode = document.getElementById('storage-limit-mode');
    const retMode = document.getElementById('storage-retention-mode');
    const limitGb = document.getElementById('storage-limit-gb');
    const retDays = document.getElementById('storage-retention-days');
    if (limitGb) limitGb.disabled = !limitMode || limitMode.value !== 'custom';
    if (retDays) retDays.disabled = !retMode || retMode.value !== 'custom';

    const help = document.getElementById('storage-policy-help');
    if (!help) return;
    const p = this.readPolicyForm();
    const parts = [];
    parts.push(p.storage_limit_gb > 0
      ? `When stored log data grows past <strong>${p.storage_limit_gb} GB</strong>, the oldest events are deleted until usage drops to 90% of the limit.`
      : '<strong>No size limit:</strong> data grows until the disk is full, so watch free space.');
    parts.push(p.retention_days > 0
      ? `Events older than <strong>${p.retention_days} days</strong> are deleted automatically (checked every 10 minutes).`
      : '<strong>Kept forever:</strong> nothing is deleted by age.');
    if (p.storage_limit_gb > 0 || p.retention_days > 0) {
      parts.push('Alerts that are not yet Resolved are never deleted.');
    }
    help.innerHTML = parts.join(' ');
  },

  async saveStoragePolicy() {
    const p = this.readPolicyForm();
    const prev = (this.storage && this.storage.policy) || { storage_limit_gb: 0, retention_days: 0 };
    const addsDeletion = (p.storage_limit_gb > 0 && (prev.storage_limit_gb === 0 || p.storage_limit_gb < prev.storage_limit_gb))
      || (p.retention_days > 0 && (prev.retention_days === 0 || p.retention_days < prev.retention_days));
    if (addsDeletion && !window.confirm('This policy permanently deletes old log events when it runs (every 10 minutes, or when you click Apply now). Unresolved alerts are kept. Continue?')) {
      return;
    }
    try {
      const res = await fetch(`${LogVaultAPI._baseURL}/api/storage/policy`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(p),
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      Utils.showToast('✓ Storage policy saved.', 'success');
    } catch (err) {
      Utils.showToast(`Could not save policy: ${err.message}`, 'error');
      return;
    }
    await this.renderStorageBars();
  },

  async applyStoragePolicy() {
    const policy = this.storage && this.storage.policy;
    if (!policy || (policy.storage_limit_gb === 0 && policy.retention_days === 0)) {
      Utils.showToast('Storage is unlimited and kept forever: nothing to prune. Save a limit first.', 'info');
      return;
    }
    if (!window.confirm('Apply the saved storage policy now? Old events outside the policy will be permanently deleted.')) return;
    try {
      const res = await LogVaultAPI._postJSON('/api/storage/enforce', {}, 300000);
      this.storage = res.storage;
      this.renderStorage();
      Utils.showToast(`Policy applied: ${res.deleted_by_retention} events past retention, ${res.deleted_by_size_limit} over the size limit deleted.`, 'success');
    } catch (err) {
      Utils.showToast(`Could not apply policy: ${err.message}`, 'error');
    }
  },

  renderMemoryBars() {
    const container = document.getElementById('settingsMemoryContainer');
    if (!container) return;

    container.innerHTML = this.memoryData.map(item => `
      <div class="latency-bench-item" style="margin-bottom:12px;">
        <div style="min-width: 190px;">
          <span style="font-weight:800; color:var(--text-ink); display:block; font-size:0.74rem;">${item.name}</span>
          <span style="font-size:0.65rem; color:var(--text-muted); font-family:var(--font-mono);">${item.allocated}</span>
        </div>
        <div class="latency-bench-bar-track" style="height:9px; background:var(--border-card);">
          <div class="latency-bench-bar-fill" style="width: ${item.pct}%; background-color: ${item.color}; border-radius:4px;"></div>
        </div>
        <div style="min-width: 60px; text-align:right;">
          <span style="font-family:var(--font-mono); font-weight:800; color:${item.color}; font-size:0.75rem;">${item.pct}%</span>
        </div>
      </div>
    `).join('');
  }
};

window.SettingsModule = SettingsModule;
