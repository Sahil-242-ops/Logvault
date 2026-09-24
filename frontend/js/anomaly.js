/**
 * LOGVAULT — Anomaly Investigation & 3D Threat Topology Module
 * High-Fidelity 3D Volumetric Mountain Elevation Graph + Cyan Vortex Summit
 * Merges Network Forensics with 60 FPS Volumetric Particle Arcs & Kanban Engine
 */

const AnomalyModule = {
  activeIncidentId: 'INC-01',
  workflowFilter: 'ALL',
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

  // ================================================================
  // ALERT CENTER: AI auto-investigation + human approval workflow
  // OPEN -> AI Investigating -> Awaiting Approval -> (analyst) Resolved
  //                                               -> (analyst reject) Investigating
  // ================================================================
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

  analystName() {
    try {
      return localStorage.getItem('logvault_op_name') || 'Agent Sahil';
    } catch {
      return 'Agent Sahil';
    }
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

  clearIncidentDossier() {
    const set = (elId, text) => { const el = document.getElementById(elId); if (el) el.innerText = text; };
    set('dossier-main-title', 'No Incident Selected');
    set('dossier-desc-text', 'Select an incident from the queue to view details.');
    ['ai-investigation-card', 'dossier-timeline', 'dossier-assets', 'dossier-analyst', 'dossier-actions'].forEach(elId => {
      const el = document.getElementById(elId);
      if (el) el.innerHTML = '';
    });
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
