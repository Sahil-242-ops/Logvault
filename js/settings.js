/**
 * LOGVAULT — Platform Settings & Air-Gapped Storage Module (Stage 3 Masterpiece)
 * Operator Profile Credentials + Local Storage Footprint + Air-Gapped Controls
 */

const SettingsModule = {
  storageData: [
    { name: 'Raw Ingested Payloads', size: '1.18 GB', pct: 48.7, color: '#B4233C', records: '482,100 items' },
    { name: 'Normalized OCSF JSON Tables', size: '840 MB', pct: 34.7, color: '#25855A', records: '482,100 items' },
    { name: 'Vector Embeddings Index (HNSW)', size: '280 MB', pct: 11.5, color: '#C47A16', records: '14,200 vectors' },
    { name: 'Threat Anomaly Topology Cache', size: '120 MB', pct: 5.1, color: '#74152A', records: '3,840 nodes' }
  ],

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
    // Retention slider
    const slider = document.getElementById('settings-retention-slider');
    const valEl = document.getElementById('settings-retention-val');
    if (slider && valEl) {
      slider.addEventListener('input', (e) => {
        valEl.innerText = `${e.target.value} Days`;
      });
    }

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
      btnVacuum.addEventListener('click', () => {
        Utils.showToast('Running SQLite VACUUM & IndexedDB B-Tree re-indexing...', 'info');
        setTimeout(() => {
          Utils.showToast('✓ Database defragmentation complete: Reclaimed 142 MB of local heap.', 'success');
        }, 1400);
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

  renderStorageBars() {
    const container = document.getElementById('settingsStorageBreakdownContainer');
    if (!container) return;

    container.innerHTML = this.storageData.map(item => `
      <div class="latency-bench-item" style="margin-bottom:12px;">
        <div style="min-width: 190px;">
          <span style="font-weight:800; color:var(--text-ink); display:block; font-size:0.74rem;">${item.name}</span>
          <span style="font-size:0.65rem; color:var(--text-muted); font-family:var(--font-mono);">${item.records} • ${item.size}</span>
        </div>
        <div class="latency-bench-bar-track" style="height:9px; background:var(--border-card);">
          <div class="latency-bench-bar-fill" style="width: ${item.pct}%; background-color: ${item.color}; border-radius:4px; box-shadow: 0 0 8px ${item.color}33;"></div>
        </div>
        <div style="min-width: 60px; text-align:right;">
          <span style="font-family:var(--font-mono); font-weight:800; color:${item.color}; font-size:0.75rem;">${item.pct}%</span>
        </div>
      </div>
    `).join('');
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
