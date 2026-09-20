/**
 * LOGVAULT — Anomaly Investigation & 3D Threat Topology Module
 * High-Fidelity 3D Volumetric Mountain Elevation Graph + Cyan Vortex Summit
 * Merges Network Forensics with 60 FPS Volumetric Particle Arcs & Kanban Engine
 */

const AnomalyModule = {
  activeIncidentId: 'INC-01',
  workflowFilter: 'Active',
  scrubProgress: 0.85,
  isScrubbing: false,
  scrubTimer: null,
  animFrameId: null,
  hoveredNode: null,

  // 3D Nodes with Ground (gx, gy) and Elevation (elev)
  graphNodes: [
    { id: 'attacker', name: '192.168.1.45 (Attacker)', label: '192.168.1.45', gx: 0.16, gy: 0.54, elev: 8, radius: 15, type: 'attacker' },
    { id: 'fw1', name: 'Perimeter FW 01', label: 'Perimeter FW 01', gx: 0.28, gy: 0.44, elev: 28, radius: 11, type: 'firewall' },
    { id: 'vpn', name: 'VPN Gateway', label: 'VPN Gateway', gx: 0.30, gy: 0.68, elev: 22, radius: 10, type: 'gateway' },
    { id: 'swA', name: 'Core Switch A', label: 'Core Switch A', gx: 0.45, gy: 0.38, elev: 65, radius: 10, type: 'switch' },
    { id: 'swB', name: 'Core Switch B', label: 'Core Switch B', gx: 0.46, gy: 0.60, elev: 52, radius: 10, type: 'switch' },
    { id: 'auth', name: 'Auth Server DC-01', label: 'Auth Server DC-01', gx: 0.62, gy: 0.26, elev: 90, radius: 9, type: 'server' },
    { id: 'target', name: 'server-07 (DB Target)', label: 'server-07 (DB Target)', gx: 0.63, gy: 0.42, elev: 130, radius: 16, type: 'target' }, // Summit Apex
    { id: 'web4', name: 'Web Cluster 04', label: 'Web Cluster 04', gx: 0.58, gy: 0.76, elev: 35, radius: 9, type: 'shielded_web' },
    { id: 'pay', name: 'Payment API Node', label: 'Payment API Node', gx: 0.78, gy: 0.58, elev: 42, radius: 9, type: 'shielded_pay' },
    { id: 'redis', name: 'Redis Cache 02', label: 'Redis Cache 02', gx: 0.80, gy: 0.30, elev: 48, radius: 9, type: 'shielded_redis' },
    { id: 'edge1', name: 'Edge Node 01', label: 'Edge 01', gx: 0.72, gy: 0.78, elev: 15, radius: 7, type: 'server' },
    { id: 'edge2', name: 'Backup Storage', label: 'Backup Vault', gx: 0.88, gy: 0.46, elev: 18, radius: 8, type: 'server' }
  ],

  graphLinks: [
    { from: 'attacker', to: 'fw1', arc: 18 },
    { from: 'attacker', to: 'vpn', arc: 14 },
    { from: 'fw1', to: 'swA', arc: 26 },
    { from: 'vpn', to: 'swB', arc: 22 },
    { from: 'swA', to: 'target', arc: 45 },
    { from: 'swB', to: 'target', arc: 48 },
    { from: 'swA', to: 'auth', arc: 28 },
    { from: 'swB', to: 'web4', arc: 20 },
    { from: 'target', to: 'auth', arc: 24 },
    { from: 'target', to: 'pay', arc: 38 },
    { from: 'target', to: 'redis', arc: 34 },
    { from: 'web4', to: 'edge1', arc: 12 },
    { from: 'pay', to: 'edge2', arc: 16 }
  ],

  // Procedural Smoke Particles
  smokeParticles: Array.from({ length: 42 }, () => ({
    x: 0.25 + Math.random() * 0.55,
    y: 0.35 + Math.random() * 0.45,
    elev: Math.random() * 110,
    size: 16 + Math.random() * 28,
    speed: 0.2 + Math.random() * 0.5,
    opacity: 0.04 + Math.random() * 0.08
  })),

  alerts: [],
  anomalies: [],

  async init() {
    this.bindEvents();
    await this.fetchData();
    this.startThreatGraphLoop();
  },

  async onScreenOpen(screenId) {
    if (screenId === 'alerts' || screenId === 'anomalies') {
      await this.fetchData();
    }
    if (screenId === 'anomalies') {
      this.startThreatGraphLoop();
    }
  },

  async fetchData() {
    if (!window.LogVaultAPI) return;
    
    // Fetch alerts using the current workflow filter
    const alertFilter = this.workflowFilter === 'ALL' ? 'ALL' : this.workflowFilter;
    const alertRes = await LogVaultAPI.getAlerts(100, 0, alertFilter);
    this.alerts = (alertRes && alertRes.alerts) ? alertRes.alerts : [];
    
    const anomalyRes = await LogVaultAPI.getAnomalies();
    this.anomalies = (anomalyRes && anomalyRes.anomalies) ? anomalyRes.anomalies : [];
    
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
  },

  bindEvents() {
    // Workflow filter buttons in Alert Center
    document.querySelectorAll('[data-wf-filter]').forEach(btn => {
      btn.addEventListener('click', () => {
        const status = btn.getAttribute('data-wf-filter');
        this.setWorkflowFilter(status);
      });
    });

    // Alert queue search
    const searchInput = document.getElementById('workflow-queue-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.filterQueueSearch(e.target.value.toLowerCase().trim());
      });
    }

    // Timeline Scrubber Slider
    const scrubRange = document.getElementById('anomaly-timeline-slider');
    if (scrubRange) {
      scrubRange.addEventListener('input', (e) => {
        this.scrubProgress = parseFloat(e.target.value) / 100;
        this.updateScrubLabel();
      });
    }

    // Scrub Play/Pause
    const scrubPlayBtn = document.getElementById('btn-scrub-play');
    if (scrubPlayBtn) {
      scrubPlayBtn.addEventListener('click', () => this.toggleScrubPlay());
    }

    // Quick Containment Actions
    const btnIsolate = document.getElementById('btn-qc-isolate');
    if (btnIsolate) {
      btnIsolate.addEventListener('click', () => this.isolateTargetNode());
    }

    const btnViewLogs = document.getElementById('btn-qc-logs');
    if (btnViewLogs) {
      btnViewLogs.addEventListener('click', () => {
        Navigation.navigateTo('live-logs');
        Utils.showToast('Filtered live log stream for server-07 attack vector.');
      });
    }

    const btnUpdateAcl = document.getElementById('btn-qc-acl');
    if (btnUpdateAcl) {
      btnUpdateAcl.addEventListener('click', () => {
        Utils.showToast('Perimeter Firewall ACL updated: 192.168.1.45 dropped.', 'danger');
      });
    }

    // Mitigation actions
    const btnQuarantine = document.getElementById('btn-contain-server');
    if (btnQuarantine) {
      btnQuarantine.addEventListener('click', () => this.triggerContainment());
    }

    const btnBlockIp = document.getElementById('btn-block-source-ip');
    if (btnBlockIp) {
      btnBlockIp.addEventListener('click', () => this.triggerBlockIp());
    }

    const btnExportDossier = document.getElementById('btn-export-dossier');
    if (btnExportDossier) {
      btnExportDossier.addEventListener('click', () => this.exportDossier());
    }
  },

  setWorkflowFilter(status) {
    this.workflowFilter = status;
    document.querySelectorAll('[data-wf-filter]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-wf-filter') === status);
    });
    this.fetchData();
  },

  toggleScrubPlay() {
    const btn = document.getElementById('btn-scrub-play');
    this.isScrubbing = !this.isScrubbing;

    if (this.isScrubbing) {
      if (btn) btn.innerHTML = '<i data-lucide="pause"></i>';
      this.scrubTimer = setInterval(() => {
        this.scrubProgress += 0.015;
        if (this.scrubProgress > 1) this.scrubProgress = 0.1;
        const slider = document.getElementById('anomaly-timeline-slider');
        if (slider) slider.value = Math.round(this.scrubProgress * 100);
        this.updateScrubLabel();
      }, 80);
      Utils.showToast('Replaying attack progression telemetry timeline.');
    } else {
      if (btn) btn.innerHTML = '<i data-lucide="play"></i>';
      clearInterval(this.scrubTimer);
    }
    if (window.lucide) lucide.createIcons();
  },

  updateScrubLabel() {
    const label = document.getElementById('scrub-time-label');
    if (label) {
      const minutes = Math.round(this.scrubProgress * 7);
      label.innerText = `T+${minutes}m (${Math.round(this.scrubProgress * 4821)} attempts)`;
    }
  },

  isolateTargetNode() {
    Utils.showToast('Target Node server-07 isolated from internal switch fabrics.', 'danger');
  },

  startThreatGraphLoop() {
    if (this.animFrameId) cancelAnimationFrame(this.animFrameId);

    const loop = () => {
      if (Navigation.activeScreen === 'anomalies') {
        this.drawThreatGraphFrame();
      }
      this.animFrameId = requestAnimationFrame(loop);
    };

    this.animFrameId = requestAnimationFrame(loop);
  },

  drawThreatGraphFrame() {
    const canvas = document.getElementById('threatGraphCanvas');
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = rect.width || 800;
    const h = rect.height || 380;
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    // 1. Draw 3D Isometric Perspective Floor Grid (From Reference Images)
    ctx.beginPath();
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.08)' : 'rgba(116, 21, 42, 0.08)';
    ctx.lineWidth = 1;

    for (let i = 0; i <= 9; i++) {
      const gy = h * 0.32 + i * (h * 0.068);
      const span = (i / 9);
      const lx = w * 0.08 - span * (w * 0.03);
      const rx = w * 0.92 + span * (w * 0.03);
      ctx.moveTo(lx, gy);
      ctx.lineTo(rx, gy);
    }

    for (let j = 0; j <= 14; j++) {
      const topX = w * 0.12 + j * (w * 0.055);
      const botX = w * 0.06 + j * (w * 0.064);
      ctx.moveTo(topX, h * 0.32);
      ctx.lineTo(botX, h * 0.94);
    }
    ctx.stroke();

    // Map Screen Node Coordinates (with 3D Elevation offset)
    const nodeMap = {};
    this.graphNodes.forEach(n => {
      const floorX = n.gx * w;
      const floorY = n.gy * h;
      const elevatedY = floorY - n.elev * (0.6 + this.scrubProgress * 0.4);
      nodeMap[n.id] = { ...n, fx: floorX, fy: floorY, px: floorX, py: elevatedY };
    });

    // 2. Draw Floor Projection Pads & Drop Stems
    Object.values(nodeMap).forEach(n => {
      // Floor Pad (Soft Ellipse Footprint on Grid)
      ctx.beginPath();
      ctx.ellipse(n.fx, n.fy, n.radius * 1.5, n.radius * 0.55, 0, 0, Math.PI * 2);
      ctx.fillStyle = isDark ? 'rgba(0, 0, 0, 0.45)' : 'rgba(116, 21, 42, 0.12)';
      ctx.fill();

      // Vertical Elevation Drop Stem
      if (n.elev > 10) {
        ctx.beginPath();
        ctx.moveTo(n.fx, n.fy);
        ctx.lineTo(n.px, n.py);
        ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.18)' : 'rgba(116, 21, 42, 0.16)';
        ctx.setLineDash([2, 4]);
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.setLineDash([]);
      }
    });

    // 3. Draw Volumetric Smoke / Particle Mist rising to Summit (Image 2 effect)
    this.smokeParticles.forEach(p => {
      p.elev = (p.elev + p.speed) % 130;
      const sx = p.x * w;
      const sy = p.y * h - p.elev;
      ctx.beginPath();
      ctx.arc(sx, sy, p.size, 0, Math.PI * 2);
      const mistGrad = ctx.createRadialGradient(sx, sy, 2, sx, sy, p.size);
      const mistColor = isDark ? '232, 160, 170' : '116, 21, 42';
      mistGrad.addColorStop(0, `rgba(${mistColor}, ${p.opacity})`);
      mistGrad.addColorStop(1, `rgba(${mistColor}, 0)`);
      ctx.fillStyle = mistGrad;
      ctx.fill();
    });

    // 4. Draw Elevated Curved Spline Arcs (Parabolic Mountain Ribbons from Image 2)
    this.graphLinks.forEach(link => {
      const src = nodeMap[link.from];
      const dst = nodeMap[link.to];
      if (!src || !dst) return;

      const isAttackPath = (link.from === 'attacker' || link.to === 'target' || link.from === 'fw1' || link.from === 'vpn');
      const midX = (src.px + dst.px) / 2;
      const midY = Math.min(src.py, dst.py) - link.arc * (0.8 + this.scrubProgress * 0.4);

      // Curved Spline Path
      ctx.beginPath();
      ctx.moveTo(src.px, src.py);
      ctx.quadraticCurveTo(midX, midY, dst.px, dst.py);

      const grad = ctx.createLinearGradient(src.px, src.py, dst.px, dst.py);
      if (isAttackPath) {
        grad.addColorStop(0, '#C47A16');
        grad.addColorStop(0.6, '#B4233C');
        grad.addColorStop(1, '#74152A');
        ctx.strokeStyle = grad;
        ctx.lineWidth = 2.4;
      } else {
        ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.28)' : 'rgba(116, 21, 42, 0.22)';
        ctx.lineWidth = 1.4;
      }
      ctx.stroke();

      // Flowing Luminous Data Particles riding the 3D curved arc
      if (isAttackPath && this.scrubProgress > 0.15) {
        const particleCount = 3;
        for (let p = 0; p < particleCount; p++) {
          const t = ((now / 1500) + (p / particleCount)) % 1;
          const u = 1 - t;
          const px = u * u * src.px + 2 * u * t * midX + t * t * dst.px;
          const py = u * u * src.py + 2 * u * t * midY + t * t * dst.py;

          ctx.beginPath();
          ctx.arc(px, py, 3.4, 0, Math.PI * 2);
          ctx.fillStyle = '#FFFFFF';
          ctx.shadowColor = '#C6283D';
          ctx.shadowBlur = 9;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }
    });

    // 5. Draw Apex Cyan Vortex Swirl at the Summit (Image 2 Key Feature)
    const target = nodeMap['target'];
    if (target) {
      const vortexX = target.px;
      const vortexY = target.py;
      const spin = (now / 1200) % (Math.PI * 2);

      // Cyan Vortex Spiral Rings
      for (let r = 1; r <= 3; r++) {
        ctx.save();
        ctx.translate(vortexX, vortexY);
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

      // Volumetric Cyan Halo
      const haloGrad = ctx.createRadialGradient(vortexX, vortexY, 4, vortexX, vortexY, target.radius * 3.8);
      haloGrad.addColorStop(0, 'rgba(78, 205, 196, 0.4)');
      haloGrad.addColorStop(0.6, 'rgba(78, 205, 196, 0.12)');
      haloGrad.addColorStop(1, 'rgba(78, 205, 196, 0)');
      ctx.beginPath();
      ctx.arc(vortexX, vortexY, target.radius * 3.8, 0, Math.PI * 2);
      ctx.fillStyle = haloGrad;
      ctx.fill();

      // Deep Crimson Target Sphere at center of vortex
      const pulse = Math.sin(now / 200) * 2;
      const tr = target.radius + pulse;
      const targetGrad = ctx.createRadialGradient(vortexX - 4, vortexY - 4, 2, vortexX, vortexY, tr);
      targetGrad.addColorStop(0, '#FF4D6D');
      targetGrad.addColorStop(0.5, '#B4233C');
      targetGrad.addColorStop(1, '#4A0814');
      ctx.beginPath();
      ctx.arc(vortexX, vortexY, tr, 0, Math.PI * 2);
      ctx.fillStyle = targetGrad;
      ctx.fill();
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = 2.4;
      ctx.stroke();
    }

    // 6. Draw Remaining 3D Node Spheres with Gradient Highlights
    if (this.anomalies.length === 0) {
      ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
      ctx.font = '600 14px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText('No anomalies detected.', w / 2, h / 2);
      return; // Skip drawing nodes if no anomalies
    }

    Object.values(nodeMap).forEach(n => {
      if (n.type === 'target') return;

      const r = n.radius;
      const sphereGrad = ctx.createRadialGradient(n.px - r * 0.35, n.py - r * 0.35, 1, n.px, n.py, r);

      if (n.type === 'attacker') {
        // Golden Sphere
        sphereGrad.addColorStop(0, '#FFD166');
        sphereGrad.addColorStop(0.6, '#F4A261');
        sphereGrad.addColorStop(1, '#8C4A00');
        ctx.beginPath();
        ctx.arc(n.px, n.py, r, 0, Math.PI * 2);
        ctx.fillStyle = sphereGrad;
        ctx.fill();
        ctx.strokeStyle = '#FFF8F0';
        ctx.lineWidth = 2.2;
        ctx.stroke();
      } else {
        // Crimson / White Shaded Nodes
        sphereGrad.addColorStop(0, '#FFE6EA');
        sphereGrad.addColorStop(0.4, '#C6283D');
        sphereGrad.addColorStop(1, '#5C1021');
        ctx.beginPath();
        ctx.arc(n.px, n.py, r, 0, Math.PI * 2);
        ctx.fillStyle = sphereGrad;
        ctx.fill();
        ctx.strokeStyle = 'rgba(255, 248, 240, 0.9)';
        ctx.lineWidth = 1.6;
        ctx.stroke();
      }

      // Draw Floating Pill Label
      this.drawNodePillBadge(ctx, n.px, n.py - r - 11, n.label, isDark);
    });

    // 7. Draw Target Telemetry Tooltip Card
    if (target) {
      this.drawTargetTooltipCard(ctx, target.px - 140, target.py + 32, isDark);
    }
  },

  drawNodePillBadge(ctx, x, y, text, isDark) {
    ctx.font = '700 10px JetBrains Mono, monospace';
    const textW = ctx.measureText(text).width;
    const boxW = textW + 12;
    const boxH = 17;

    ctx.fillStyle = isDark ? 'rgba(34, 20, 24, 0.92)' : 'rgba(255, 248, 240, 0.95)';
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.35)' : 'rgba(116, 21, 42, 0.25)';
    ctx.lineWidth = 1;

    ctx.beginPath();
    ctx.roundRect(x - boxW / 2, y - boxH / 2, boxW, boxH, 4);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = isDark ? '#FFF8F0' : '#24191B';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, x, y);
  },

  drawTargetTooltipCard(ctx, x, y, isDark) {
    const cardW = 180;
    const cardH = 64;

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

    ctx.font = '600 9.5px JetBrains Mono, monospace';
    ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
    ctx.textAlign = 'left';
    ctx.fillText('Active connections: ', x + 10, y + 18);
    ctx.fillStyle = '#C6283D';
    ctx.font = '800 10px JetBrains Mono, monospace';
    ctx.fillText('14', x + 130, y + 18);

    ctx.font = '600 9.5px JetBrains Mono, monospace';
    ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
    ctx.fillText('Vulnerability: ', x + 10, y + 35);
    ctx.fillStyle = '#C47A16';
    ctx.font = '700 9.5px JetBrains Mono, monospace';
    ctx.fillText('CVE-2023-1234', x + 94, y + 35);

    ctx.font = '600 9.5px JetBrains Mono, monospace';
    ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
    ctx.fillText('Risk: ', x + 10, y + 52);
    ctx.fillStyle = '#C6283D';
    ctx.font = '800 10px JetBrains Mono, monospace';
    ctx.fillText('Critical', x + 44, y + 52);
  },

  // Kanban Drag & Drop System (60 FPS smooth animation)
  renderKanbanBoard() {
    const columns = {
      Active: document.getElementById('kanban-col-new'),
      Investigating: document.getElementById('kanban-col-investigating'),
      Resolved: document.getElementById('kanban-col-resolved')
    };

    if (!columns.Active) return;

    Object.entries(columns).forEach(([state, col]) => {
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
          this.moveKanbanCard(alertId, state);
        }
      };
    });

    if (this.alerts.length === 0) {
      columns.Active.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted);">No active alerts.</div>';
      return;
    }

    this.alerts.forEach(inc => {
      const targetCol = columns[inc.status === 'OPEN' ? 'Active' : inc.status] || columns.Active;
      let pClass = 'high';
      if (inc.sev === 'MEDIUM') pClass = 'medium';
      if (inc.sev === 'LOW') pClass = 'low';

      const nextState = inc.status === 'OPEN' ? 'Investigating' : (inc.status === 'Investigating' ? 'Resolved' : 'OPEN');
      const nextLabel = inc.status === 'OPEN' ? 'Investigate &rarr;' : (inc.status === 'Investigating' ? 'Resolve &check;' : 'Reopen');

      const card = document.createElement('div');
      card.className = 'kanban-item-card';
      card.id = `kanban-card-${inc.id}`;
      card.draggable = true;

      card.innerHTML = `
        <div class="k-card-top">
          <span class="k-priority-pill ${pClass}">Priority ${inc.severity}</span>
          <span style="font-size:0.68rem; color:var(--text-muted);"><code>${inc.id.substring(0,8)}</code></span>
        </div>
        <div class="k-card-title">${Utils.escapeHtml(inc.title)}</div>
        <div class="k-card-footer">
          <span><i data-lucide="bell" style="width:12px;"></i> Agent Sahil</span>
          <div class="k-move-actions">
            <button class="k-move-btn" onclick="event.stopPropagation(); AnomalyModule.moveKanbanCard('${inc.id}', '${nextState}')">${nextLabel}</button>
          </div>
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

      card.onclick = () => {
        this.loadIncidentDossier(inc.id);
      };

      targetCol.appendChild(card);
    });

    if (window.lucide) lucide.createIcons();
  },

  async moveKanbanCard(id, newState) {
    const inc = this.alerts.find(i => i.id === id);
    if (!inc) return;
    inc.status = newState;
    
    // In a real app we'd call an API here to update the status.
    
    this.renderKanbanBoard();
    this.renderAlertCenterQueue();
    this.loadIncidentDossier(id);

    const movedEl = document.getElementById(`kanban-card-${id}`);
    if (movedEl) {
      movedEl.classList.add('glide-anim');
      setTimeout(() => movedEl.classList.remove('glide-anim'), 450);
    }

    Utils.showToast(`Updated ${id} status to ${newState}`, 'success');
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
    
    if (this.alerts.length === 0) {
      container.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted);">No active alerts.</div>';
      return;
    }

    const filtered = this.alerts.filter(inc => {
      if (this.workflowFilter === 'ALL') return true;
      const statusMap = { 'Active': 'OPEN', 'Investigating': 'Investigating', 'Resolved': 'Resolved' };
      return inc.status === (statusMap[this.workflowFilter] || this.workflowFilter);
    });

    container.innerHTML = filtered.map(inc => {
      const isSelected = inc.id === this.activeIncidentId;
      let badgeClass = 'crit-pill';
      if (inc.sev === 'HIGH') badgeClass = 'high-pill';
      if (inc.sev === 'MEDIUM') badgeClass = 'warn-pill';
      if (inc.state === 'Resolved') badgeClass = 'green-pill';

      return `
        <div class="incident-queue-card ${isSelected ? 'selected' : ''}" onclick="AnomalyModule.loadIncidentDossier('${inc.id}')">
          <div class="inc-q-head">
            <span class="inc-id-tag"><code>${inc.id.substring(0,8)}</code></span>
            <span class="badge-pill ${badgeClass}">${inc.severity}</span>
          </div>
          <div class="inc-q-title">${Utils.escapeHtml(inc.title)}</div>
          <div class="inc-q-sub">Origin: <code>${inc.source_ip || 'N/A'}</code> &bull; Target: <code>${inc.host || 'N/A'}</code></div>
          <div class="inc-q-meta">
            <span><i data-lucide="clock" style="width:12px;"></i> ${new Date(inc.timestamp || Date.now()).toLocaleTimeString()}</span>
            <span class="inc-state-pill state-${(inc.status === 'OPEN' ? 'active' : inc.status).toLowerCase()}">${inc.status === 'OPEN' ? 'Active' : inc.status}</span>
          </div>
        </div>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
  },

  loadIncidentDossier(id) {
    this.activeIncidentId = id;
    const inc = this.alerts.find(i => i.id === id);
    if (!inc) return this.clearIncidentDossier();

    // Update queue highlight
    document.querySelectorAll('.incident-queue-card').forEach(c => {
      c.classList.toggle('selected', c.innerHTML.includes(id));
    });

    // Populate Dossier pane elements
    const titleEl = document.getElementById('dossier-main-title');
    const srcEl = document.getElementById('dossier-src-ip');
    const targetEl = document.getElementById('dossier-target-ip');
    const typeEl = document.getElementById('dossier-event-type');
    const timeEl = document.getElementById('dossier-time-range');
    const descEl = document.getElementById('dossier-desc-text');
    const statusEl = document.getElementById('dossier-status-pill');

    if (titleEl) titleEl.innerText = inc.title;
    if (srcEl) srcEl.innerText = inc.source_ip || 'N/A';
    if (targetEl) targetEl.innerText = inc.host || 'N/A';
    if (typeEl) typeEl.innerText = inc.mitre_technique || 'Anomaly Detected';
    if (timeEl) timeEl.innerText = new Date(inc.timestamp || Date.now()).toLocaleString();
    if (descEl) descEl.innerText = inc.description;
    if (statusEl) {
      statusEl.innerText = inc.status === 'OPEN' ? 'Active' : inc.status;
      statusEl.className = `badge-pill state-${(inc.status === 'OPEN' ? 'active' : inc.status).toLowerCase()}`;
    }

    if (window.lucide) lucide.createIcons();
  },

  clearIncidentDossier() {
    const titleEl = document.getElementById('dossier-main-title');
    const descEl = document.getElementById('dossier-desc-text');
    if (titleEl) titleEl.innerText = 'No Incident Selected';
    if (descEl) descEl.innerText = 'Select an incident from the queue to view details.';
  },

  triggerContainment() {
    Utils.showToast('Automated Containment executed: server-07 quarantined and firewall ACL drop rule engaged.', 'danger');
  },

  triggerBlockIp() {
    Utils.showToast('Source IP 192.168.1.45 permanently added to edge firewall blacklist.', 'danger');
  },

  exportDossier() {
    const data = {
      incident_id: this.activeIncidentId,
      analyst_assigned: 'Agent Sahil (Tier-3 Lead)',
      generated_at: new Date().toISOString()
    };
    navigator.clipboard.writeText(JSON.stringify(data, null, 2))
      .then(() => Utils.showToast('Forensic Dossier JSON copied to clipboard.', 'success'))
      .catch(() => Utils.showToast('Exported Forensic Dossier.'));
  },

  selectTimelineNode(index) {
    this.scrubProgress = index / 6;
    const slider = document.getElementById('anomaly-timeline-slider');
    if (slider) slider.value = Math.round(this.scrubProgress * 100);
    this.updateScrubLabel();
    Utils.showToast(`Focused attack progression at checkpoint T+${index} mins.`);
  }
};

window.AnomalyModule = AnomalyModule;
