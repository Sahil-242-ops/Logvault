/**
 * LOGVAULT — Source topology: the LOGVAULT core and the source IPs seen in stored events
 * (top 7 by anomalies, then volume). Containment goes through the backend containment list.
 */

const TopologyModule = {
  animFrameId: null,
  mousePos: { x: -1, y: -1 },
  hoveredNode: null,
  selectedNode: null,
  viewMode: 'orbital', // 'orbital' | 'layered'
  radarAngle: 0,
  packetBurstActive: false,
  burstTimer: 0,

  nodes: [
    {
      id: 'CORE-VAULT',
      label: 'LOGVAULT CORE',
      zone: 'CORE',
      zoneName: 'LOGVAULT server',
      ip: location.host || 'local',
      throughput: '0 events',
      latency: '0 anomalies',
      status: 'ONLINE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#B4233C',
      type: 'core',
      fixedX: 0,
      fixedY: 0,
      layerX: 280,
      layerY: 0,
      w: 200,
      h: 58,
      x: 0,
      y: 0,
      protocol: 'SQLite event store'
    }
  ],
  conduits: [],
  sources: [],
  containment: [],

  async init() {
    this.bindEvents();
    await this.fetchData();
    this.startMeshAnimationLoop();
  },

  async onScreenOpen() {
    await this.fetchData();
    this.startMeshAnimationLoop();
  },

  isPrivateIp(ip) {
    return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|f[cd])/i.test(ip || '');
  },

  async fetchData() {
    if (!window.LogVaultAPI) return;
    const [res, cont, dash] = await Promise.all([
      LogVaultAPI.getSources(),
      LogVaultAPI.getContainment().catch(() => ({ entries: [] })),
      LogVaultAPI.getDashboard()
    ]);
    this.containment = cont.entries || [];
    this.sources = (res.sources || []).slice()
      .sort((a, b) => (b.anomaly_count - a.anomaly_count) || (b.max_threat_score - a.max_threat_score) || (b.event_count - a.event_count));
    const containedIps = new Map(this.containment.filter(c => c.kind === 'ip').map(c => [c.value, c]));

    const core = this.nodes[0];
    if (dash) {
      core.throughput = `${dash.total_events.toLocaleString()} events`;
      core.latency = `${dash.anomalous_events.toLocaleString()} anomalies`;
    }

    // Fixed slots for up to 7 sources around the core
    const templateSlots = [
      { fixedX: -290, fixedY: -95, layerX: -300, layerY: -110 },
      { fixedX: 0, fixedY: -135, layerX: -300, layerY: 0 },
      { fixedX: 290, fixedY: -95, layerX: -300, layerY: 110 },
      { fixedX: -300, fixedY: 55, layerX: -20, layerY: -135 },
      { fixedX: 300, fixedY: 55, layerX: -20, layerY: 135 },
      { fixedX: -155, fixedY: 150, layerX: -20, layerY: -45 },
      { fixedX: 155, fixedY: 150, layerX: -20, layerY: 45 }
    ];

    const newNodes = [core];
    const newConduits = [];
    this.sources.slice(0, templateSlots.length).forEach((src, i) => {
      const slot = templateSlots[i];
      const contained = containedIps.get(src.source_ip);
      const isCritical = src.anomaly_count > 0 || src.max_threat_score >= 70;
      const internal = this.isPrivateIp(src.source_ip);
      newNodes.push({
        id: 'SRC-' + i,
        label: src.source_ip,
        zone: internal ? 'INTERNAL' : 'EXTERNAL',
        zoneName: internal ? 'Private address' : 'Public address',
        ip: src.source_ip,
        throughput: `${src.event_count.toLocaleString()} events`,
        latency: `${src.anomaly_count} anomalies`,
        events: src.event_count,
        maxThreat: src.max_threat_score,
        lastSeen: src.last_seen,
        status: contained ? 'CONTAINED' : (isCritical ? 'ANOMALOUS' : 'NORMAL'),
        statusClass: contained ? 'cherry' : (isCritical ? 'warn' : 'green'),
        isQuarantined: !!contained,
        containmentId: contained ? contained.id : null,
        color: isCritical ? '#C6283D' : '#25855A',
        type: internal ? 'server' : 'cloud',
        fixedX: slot.fixedX,
        fixedY: slot.fixedY,
        layerX: slot.layerX,
        layerY: slot.layerY,
        w: 160,
        h: 52,
        x: 0,
        y: 0,
        protocol: `max threat ${src.max_threat_score}`
      });
      newConduits.push({ from: i + 1, to: 0, flow: src.anomaly_count ? 'high' : 'med' });
    });

    this.nodes = newNodes;
    this.conduits = newConduits;
    this.computeNodeCoordinates();
    this.renderKpis();
    this.renderBandwidthBars();
    this.renderForensicsTable();
  },

  renderKpis() {
    const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    const src = this.sources;
    const internal = src.filter(x => this.isPrivateIp(x.source_ip));
    const external = src.length - internal.length;
    const anomalous = src.filter(x => x.anomaly_count > 0).length;
    const ev = arr => arr.reduce((a, x) => a + x.event_count, 0);
    const ipContained = this.containment.filter(c => c.kind === 'ip').length;
    const hostContained = this.containment.length - ipContained;
    set('topo-badge', `${src.length} SOURCE IP${src.length === 1 ? '' : 'S'}`);
    set('topo-kpi-sources', String(src.length));
    set('topo-kpi-sources-sub', `<i data-lucide="eye"></i> ${src.length > 7 ? `graph shows top 7 of ${src.length}` : 'all shown in graph'}`);
    set('topo-kpi-anomalous', String(anomalous));
    set('topo-kpi-anomalous-sub', `<i data-lucide="alert-triangle"></i> ${src.length ? Math.round(anomalous / src.length * 100) : 0}% of sources`);
    set('topo-kpi-split', `${internal.length} / ${external}`);
    set('topo-kpi-split-sub', `<i data-lucide="globe"></i> ${ev(internal).toLocaleString()} internal, ${(ev(src) - ev(internal)).toLocaleString()} external events`);
    set('topo-kpi-contained', String(this.containment.length));
    set('topo-kpi-contained-sub', `<i data-lucide="lock"></i> ${ipContained} IP${ipContained === 1 ? '' : 's'}, ${hostContained} host${hostContained === 1 ? '' : 's'}`);
    if (window.lucide) lucide.createIcons();
  },

  computeNodeCoordinates() {
    this.nodes.forEach(n => {
      if (this.viewMode === 'orbital') {
        n.x = n.fixedX;
        n.y = n.fixedY;
      } else {
        n.x = n.layerX;
        n.y = n.layerY;
      }
    });
  },

  bindEvents() {
    const canvas = document.getElementById('networkTopologyFlowCanvas');
    if (canvas) {
      canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        this.mousePos = {
          x: e.clientX - rect.left,
          y: e.clientY - rect.top
        };
      });

      canvas.addEventListener('mouseleave', () => {
        this.mousePos = { x: -1, y: -1 };
        this.hoveredNode = null;
      });

      canvas.addEventListener('click', () => {
        if (this.hoveredNode) {
          this.toggleQuarantine(this.hoveredNode.id);
        }
      });
    }

    // View mode switch buttons
    document.querySelectorAll('.topology-view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.topology-view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.viewMode = btn.getAttribute('data-view') || 'orbital';
        this.computeNodeCoordinates();
        Utils.showToast(`Switched topology view to: ${btn.innerText.trim()}`);
      });
    });

    window.addEventListener('resize', () => {
      if (Navigation.activeScreen === 'topology') {
        this.computeNodeCoordinates();
      }
    });
  },

  // Contain or release a source IP through the backend containment list
  async toggleQuarantine(nodeId) {
    const n = this.nodes.find(node => node.id === nodeId);
    if (!n || n.id === 'CORE-VAULT') return;
    try {
      if (n.isQuarantined) {
        if (!window.confirm(`Release ${n.ip}? New logs from it will no longer be raised as critical.`)) return;
        await LogVaultAPI.releaseContainment(n.containmentId);
        Utils.showToast(`${n.ip} released.`, 'success');
      } else {
        const reason = window.prompt(`Block ${n.ip}?\n\nNew logs from it will raise CRITICAL alerts and it is added to the firewall export (Settings). Reason:`);
        if (reason === null) return;
        await LogVaultAPI.contain('ip', n.ip, reason);
        Utils.showToast(`${n.ip} blocked.`, 'success');
      }
    } catch (err) {
      Utils.showToast(`Containment failed: ${err.message}`, 'error');
    }
    this.fetchData();
  },

  startMeshAnimationLoop() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }

    const canvas = document.getElementById('networkTopologyFlowCanvas');
    if (!canvas) return;

    const loop = () => {
      try {
        this.drawTopologyFrame(canvas);
      } catch (e) {
        console.error('Topology canvas frame error:', e);
      }
      this.animFrameId = requestAnimationFrame(loop);
    };

    this.animFrameId = requestAnimationFrame(loop);
  },

  drawTopologyFrame(canvas) {
    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    const cssW = rect.width || 1000;
    const cssH = rect.height || 520;

    const targetW = Math.floor(cssW * dpr);
    const targetH = Math.floor(cssH * dpr);

    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
    }

    // Absolute clean slate on every frame
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.scale(dpr, dpr);

    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const cx = cssW / 2;
    const cy = cssH / 2;

    if (this.burstTimer > 0) {
      this.burstTimer--;
      if (this.burstTimer === 0) this.packetBurstActive = false;
    }

    // 1. Concentric Range Distance Rings (Crisp, No Blur)
    ctx.shadowColor = 'transparent';
    ctx.shadowBlur = 0;
    ctx.shadowOffsetX = 0;
    ctx.shadowOffsetY = 0;

    const rings = [115, 210, 320];
    rings.forEach((r, idx) => {
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = isDark
        ? `rgba(232, 160, 170, ${0.10 + idx * 0.04})`
        : `rgba(180, 35, 60, ${0.08 + idx * 0.03})`;
      ctx.lineWidth = 1.2;
      ctx.setLineDash([6, 8]);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    // 2. Rotating Radar Scanner Beam
    this.radarAngle += 0.012;
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(this.radarAngle);

    const radarGrad = ctx.createLinearGradient(0, 0, 320, 0);
    radarGrad.addColorStop(0, 'rgba(180, 35, 60, 0.22)');
    radarGrad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');

    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, 320, -0.22, 0);
    ctx.fillStyle = radarGrad;
    ctx.fill();
    ctx.restore();

    // 3. Draw Vascular Bezier Conduits & Flowing Photon Packets
    this.conduits.forEach(c => {
      const n1 = this.nodes[c.from];
      const n2 = this.nodes[c.to];
      const x1 = cx + n1.x;
      const y1 = cy + n1.y;
      const x2 = cx + n2.x;
      const y2 = cy + n2.y;

      const isSevered = n1.isQuarantined || n2.isQuarantined;

      const mx = (x1 + x2) / 2 + (y1 - y2) * 0.12;
      const my = (y1 + y2) / 2 + (x2 - x1) * 0.12;

      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.quadraticCurveTo(mx, my, x2, y2);
      ctx.strokeStyle = isSevered
        ? 'rgba(196, 40, 61, 0.45)'
        : (isDark ? 'rgba(232, 160, 170, 0.35)' : 'rgba(180, 35, 60, 0.28)');
      ctx.lineWidth = isSevered ? 2.0 : 2.4;
      if (isSevered) ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.setLineDash([]);

      if (!isSevered) {
        const speedMult = this.packetBurstActive ? 0.0018 : 0.0007;
        const numPackets = this.packetBurstActive ? 5 : (c.flow === 'high' ? 3 : 2);

        for (let p = 0; p < numPackets; p++) {
          const t = ((now * speedMult) + (p / numPackets)) % 1;
          const px = (1 - t) * (1 - t) * x1 + 2 * (1 - t) * t * mx + t * t * x2;
          const py = (1 - t) * (1 - t) * y1 + 2 * (1 - t) * t * my + t * t * y2;

          ctx.beginPath();
          ctx.arc(px, py, this.packetBurstActive ? 4.2 : 3.2, 0, Math.PI * 2);
          ctx.fillStyle = this.packetBurstActive ? '#FFAA00' : '#FF3366';
          ctx.fill();
        }
      }
    });

    // 4. Render Razor-Sharp, Zero-Overlap Node Cards
    this.hoveredNode = null;

    this.nodes.forEach(n => {
      const nx = cx + n.x;
      const ny = cy + n.y;
      const isCore = n.id === 'CORE-VAULT';
      const nw = n.w;
      const nh = n.h;
      const cardX = nx - nw / 2;
      const cardY = ny - nh / 2;

      const isHovered = (
        this.mousePos.x >= cardX &&
        this.mousePos.x <= cardX + nw &&
        this.mousePos.y >= cardY &&
        this.mousePos.y <= cardY + nh
      );

      if (isHovered) {
        this.hoveredNode = n;
      }

      ctx.save();

      // Quarantine Barrier Pulsing Hazard Shield
      if (n.isQuarantined) {
        const qPulse = Math.sin(now / 120) * 4;
        this.drawBox(ctx, cardX - 8 - qPulse, cardY - 8 - qPulse, nw + 16 + qPulse * 2, nh + 16 + qPulse * 2, 10);
        ctx.strokeStyle = 'rgba(196, 40, 61, 0.85)';
        ctx.lineWidth = 2.2;
        ctx.setLineDash([6, 6]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // Card Background (Solid, High-Contrast, Zero Ghosting)
      this.drawBox(ctx, cardX, cardY, nw, nh, 8);
      if (isCore) {
        const coreGrad = ctx.createLinearGradient(cardX, cardY, cardX + nw, cardY + nh);
        coreGrad.addColorStop(0, '#9C1A30');
        coreGrad.addColorStop(0.5, '#74152A');
        coreGrad.addColorStop(1, '#450B17');
        ctx.fillStyle = coreGrad;
      } else {
        ctx.fillStyle = isDark
          ? (isHovered ? '#2D2024' : '#1C1517')
          : (isHovered ? '#FFFFFF' : '#FFFDF9');
      }

      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;
      ctx.fill();

      // Card Border
      ctx.strokeStyle = n.isQuarantined
        ? '#C6283D'
        : (isCore ? '#FF4D6D' : (isHovered ? '#B4233C' : (isDark ? 'rgba(232, 160, 170, 0.40)' : 'rgba(180, 35, 60, 0.30)')));
      ctx.lineWidth = isHovered || isCore ? 2.0 : 1.4;
      ctx.stroke();

      // Status Indicator Dot
      ctx.beginPath();
      ctx.arc(cardX + 14, cardY + 18, 4, 0, Math.PI * 2);
      ctx.fillStyle = n.isQuarantined ? '#FF3366' : '#25855A';
      ctx.fill();

      // Clean Typography (Explicitly Disable Shadow Leaks)
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;

      // Row 1: Title
      ctx.font = isCore ? '800 11px Plus Jakarta Sans, sans-serif' : '800 10.5px Plus Jakarta Sans, sans-serif';
      ctx.fillStyle = isCore ? '#FFFFFF' : (isDark ? '#FFFFFF' : '#181113');
      ctx.textAlign = 'left';
      ctx.fillText(n.label, cardX + 24, cardY + 21);

      // Row 2: IP Address
      ctx.font = '700 8.5px JetBrains Mono, monospace';
      ctx.fillStyle = isCore ? '#FFD4DC' : (isDark ? '#E8A0AA' : '#74152A');
      ctx.fillText(n.ip, cardX + 12, cardY + 36);

      // Row 3: Live Flow & Latency
      ctx.font = '700 8px JetBrains Mono, monospace';
      ctx.fillStyle = isCore ? '#FFAA00' : (n.isQuarantined ? '#C6283D' : (isDark ? '#9AE6B4' : '#25855A'));
      ctx.fillText(`${n.throughput} • ${n.latency}`, cardX + 12, cardY + 48);

      ctx.restore();
    });

    // 5. Floating Antigravity Telemetry HUD on Hover
    if (this.hoveredNode) {
      const n = this.hoveredNode;
      const nx = cx + n.x;
      const ny = cy + n.y;
      const hudW = 220;
      const hudH = 100;
      let hx = nx - hudW / 2;
      let hy = ny - hudH - 20;
      if (hy < 12) {
        hy = ny + n.h / 2 + 14;
      }
      hx = Math.max(14, Math.min(cssW - hudW - 14, hx));

      ctx.save();
      this.drawBox(ctx, hx, hy, hudW, hudH, 8);
      ctx.fillStyle = isDark ? 'rgba(24, 17, 19, 0.98)' : 'rgba(255, 255, 255, 0.98)';
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;
      ctx.fill();

      ctx.strokeStyle = n.isQuarantined ? '#C6283D' : '#B4233C';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;

      // HUD Header
      ctx.font = '800 11px Plus Jakarta Sans, sans-serif';
      ctx.fillStyle = isDark ? '#FFFFFF' : '#181113';
      ctx.textAlign = 'left';
      ctx.fillText(n.label, hx + 12, hy + 18);

      ctx.font = '800 8.5px JetBrains Mono, monospace';
      ctx.fillStyle = n.isQuarantined ? '#C6283D' : '#25855A';
      ctx.fillText(`ZONE: ${n.zoneName} • ${n.status}`, hx + 12, hy + 32);

      // Telemetry Specs
      ctx.font = '600 8px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#D4A8B0' : '#68595B';
      ctx.fillText(`IP: ${n.ip}`, hx + 12, hy + 46);
      ctx.fillText(`EVENTS: ${n.throughput} • ${n.latency}`, hx + 12, hy + 58);
      ctx.fillText(n.protocol, hx + 12, hy + 70);

      // Action Hint
      ctx.font = '800 8px JetBrains Mono, monospace';
      ctx.fillStyle = '#B4233C';
      ctx.fillText(n.id === 'CORE-VAULT' ? 'LOGVAULT SERVER' : (n.isQuarantined ? 'CLICK TO RELEASE' : 'CLICK TO BLOCK THIS IP'), hx + 12, hy + 88);
      ctx.restore();
    }
  },

  // 2. Active Node Conduits Telemetry Matrix (2-Column SOC Deck)
  renderBandwidthBars() {
    const container = document.getElementById('topologyBandwidthContainer');
    if (!container) return;
    const sources = this.nodes.filter(n => n.id !== 'CORE-VAULT');
    if (!sources.length) {
      container.innerHTML = '<div class="analytics-empty">No source IPs in stored events yet.</div>';
      return;
    }
    const max = Math.max(1, ...sources.map(n => n.events));
    container.innerHTML = `
      <div class="node-conduits-matrix">
        ${sources.map(n => {
          const pct = Math.max(2, Math.round(n.events / max * 100));
          const zoneBadgeClass = n.zone === 'EXTERNAL' ? 'warn' : 'green';
          const idx = this.nodes.indexOf(n);
          return `
            <div class="node-conduit-card ${n.isQuarantined ? 'quarantined' : ''}">
              <div class="node-conduit-top">
                <div class="d-flex align-center gap-2" style="min-width:0;">
                  <div class="node-conduit-emblem ${zoneBadgeClass}"><i data-lucide="${n.type === 'cloud' ? 'globe' : 'server'}"></i></div>
                  <div style="min-width:0;">
                    <strong class="node-conduit-title">${Utils.escapeHtml(n.label)}</strong>
                    <span class="node-conduit-sub">${Utils.escapeHtml(n.zoneName)} &bull; ${Utils.escapeHtml(n.protocol)}</span>
                  </div>
                </div>
                <div class="d-flex align-center gap-1" style="flex-shrink:0;">
                  <span class="badge-pill ${zoneBadgeClass}-pill" style="font-size:0.56rem;">${n.zone}</span>
                  <span class="badge-pill ${n.statusClass}-pill" style="font-size:0.56rem;">${n.status}</span>
                </div>
              </div>
              <div class="node-conduit-meter-box">
                <div class="d-flex justify-between align-center mb-1">
                  <span class="node-conduit-meter-label">SHARE OF BUSIEST SOURCE</span>
                  <span class="node-conduit-meter-pct">${pct}%</span>
                </div>
                <div class="node-conduit-track">
                  <div class="node-conduit-fill ${n.isQuarantined ? 'crit' : ''}" style="width:${pct}%; background-color:${n.isQuarantined ? '#C6283D' : n.color};"></div>
                </div>
              </div>
              <div class="node-conduit-footer">
                <div class="node-conduit-metrics">
                  <div><span class="node-metric-lbl">EVENTS</span><strong class="node-metric-val">${n.throughput}</strong></div>
                  <div><span class="node-metric-lbl">ANOMALIES</span><strong class="node-metric-val" style="color:${n.latency.startsWith('0 ') ? 'var(--status-green)' : 'var(--cherry-primary)'};">${n.latency}</strong></div>
                </div>
                <button class="btn-cream-action btn-sm node-conduit-action-btn" onclick="TopologyModule.toggleQuarantine(TopologyModule.nodes[${idx}].id)" style="font-size:0.65rem; padding:3px 8px; font-weight:700; color:${n.isQuarantined ? 'var(--status-green)' : 'var(--status-red)'};">
                  <i data-lucide="${n.isQuarantined ? 'shield-check' : 'shield-alert'}"></i> ${n.isQuarantined ? 'Release' : 'Block IP'}
                </button>
              </div>
            </div>`;
        }).join('')}
      </div>`;
    if (window.lucide) lucide.createIcons();
  },

  renderForensicsTable() {
    const tbody = document.getElementById('topology-forensics-tbody');
    if (!tbody) return;
    if (!this.sources.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px; color:var(--text-muted);">No source IPs yet.</td></tr>';
      return;
    }
    const contained = new Map(this.containment.filter(c => c.kind === 'ip').map(c => [c.value, c]));
    tbody.innerHTML = this.sources.map((s, i) => {
      const c = contained.get(s.source_ip);
      const internal = this.isPrivateIp(s.source_ip);
      return `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:800; color:var(--cherry-primary);">${Utils.escapeHtml(s.source_ip)}</td>
        <td><span class="badge-pill ${internal ? 'green' : 'warn'}-pill" style="font-size:0.60rem;">${internal ? 'Private' : 'Public'}</span></td>
        <td style="font-family:var(--font-mono); font-weight:800;">${s.event_count.toLocaleString()}</td>
        <td style="font-family:var(--font-mono); color:${s.anomaly_count ? 'var(--cherry-primary)' : 'inherit'};">${s.anomaly_count}</td>
        <td style="font-family:var(--font-mono);">${s.max_threat_score}</td>
        <td style="font-family:var(--font-mono); font-size:0.70rem;">${App.timeAgo(s.last_seen)}</td>
        <td><span class="badge-pill ${c ? 'cherry' : s.anomaly_count ? 'warn' : 'green'}-pill">${c ? 'CONTAINED' : s.anomaly_count ? 'ANOMALOUS' : 'NORMAL'}</span></td>
        <td style="white-space:nowrap;">
          <button class="btn-outline-cherry btn-sm" onclick="LogStream.filterByIp(TopologyModule.sources[${i}].source_ip)">Logs</button>
          <button class="btn-cream-action btn-sm" onclick="TopologyModule.toggleSourceContainment(${i})" style="color:${c ? 'var(--status-green)' : 'var(--status-red)'};">${c ? 'Release' : 'Block'}</button>
        </td>
      </tr>`;
    }).join('');
  },

  // Table rows include sources beyond the 7 drawn in the graph
  async toggleSourceContainment(i) {
    const s = this.sources[i];
    if (!s) return;
    const node = this.nodes.find(n => n.ip === s.source_ip);
    if (node) return this.toggleQuarantine(node.id);
    const c = this.containment.find(x => x.kind === 'ip' && x.value === s.source_ip);
    try {
      if (c) {
        if (!window.confirm(`Release ${s.source_ip}?`)) return;
        await LogVaultAPI.releaseContainment(c.id);
      } else {
        const reason = window.prompt(`Block ${s.source_ip}? Reason:`);
        if (reason === null) return;
        await LogVaultAPI.contain('ip', s.source_ip, reason);
      }
      this.fetchData();
    } catch (err) {
      Utils.showToast(`Containment failed: ${err.message}`, 'error');
    }
  },

  drawBox(ctx, x, y, width, height, radius = 6) {
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + width - radius, y);
    ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
    ctx.lineTo(x + width, y + height - radius);
    ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
    ctx.lineTo(x + radius, y + height);
    ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
  }
};

window.TopologyModule = TopologyModule;
