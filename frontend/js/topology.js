/**
 * LOGVAULT — High-Definition Network Topology Flow Mesh (Stage 3 Masterpiece)
 * Zero Overlap + Crystal Clear HiDPI Rendering + Vascular 60 FPS Conduits
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

  // Explicit Symmetrical Fixed Coordinate Map (Zero Overlap Guaranteed)
  nodes: [
    {
      id: 'CORE-VAULT',
      label: 'LOGVAULT AIR-GAPPED CORE',
      zone: 'CORE',
      zoneName: 'Central Vault Core',
      ip: '10.0.3.1',
      throughput: '142.5K logs/s',
      latency: '0.038 ms',
      status: 'OPTIMAL',
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
      protocol: 'OCSF 1.1 In-Memory Ring'
    },
    {
      id: 'NODE-FW01',
      label: 'Palo Alto NGFW',
      zone: 'DMZ',
      zoneName: 'Perimeter DMZ',
      ip: '185.220.101.5',
      throughput: '840 Mbps',
      latency: '0.12 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#B4233C',
      type: 'firewall',
      fixedX: -290,
      fixedY: -95,
      layerX: -300,
      layerY: -110,
      w: 156,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'CEF / IPsec'
    },
    {
      id: 'NODE-AWS',
      label: 'AWS CloudTrail S3 VPC',
      zone: 'DMZ',
      zoneName: 'Cloud Egress Proxy',
      ip: '172.16.0.4',
      throughput: '410 Mbps',
      latency: '0.22 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#C47A16',
      type: 'cloud',
      fixedX: 0,
      fixedY: -135,
      layerX: -300,
      layerY: 0,
      w: 165,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'SigV4 HTTPS'
    },
    {
      id: 'NODE-VPN',
      label: 'WireGuard VPN Gateway',
      zone: 'DMZ',
      zoneName: 'Perimeter DMZ',
      ip: '10.0.1.1',
      throughput: '320 Mbps',
      latency: '0.18 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#B4233C',
      type: 'vpn',
      fixedX: 290,
      fixedY: -95,
      layerX: -300,
      layerY: 110,
      w: 160,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'ChaCha20-Poly1305'
    },
    {
      id: 'NODE-K8S',
      label: 'Core K8s Cluster',
      zone: 'INTERNAL',
      zoneName: 'Application Mesh',
      ip: '10.0.2.10',
      throughput: '620 Mbps',
      latency: '0.08 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#25855A',
      type: 'k8s',
      fixedX: -300,
      fixedY: 55,
      layerX: -20,
      layerY: -135,
      w: 154,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'gRPC mTLS 1.3'
    },
    {
      id: 'NODE-KERBEROS',
      label: 'Kerberos Identity Realm',
      zone: 'INTERNAL',
      zoneName: 'Zero-Trust IAM',
      ip: '192.168.10.1',
      throughput: '180 Mbps',
      latency: '0.05 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#25855A',
      type: 'iam',
      fixedX: 300,
      fixedY: 55,
      layerX: -20,
      layerY: 135,
      w: 165,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'Kerberos v5'
    },
    {
      id: 'NODE-IDS',
      label: 'Suricata EVE IDS',
      zone: 'INTERNAL',
      zoneName: 'Packet Inspection',
      ip: '10.0.2.80',
      throughput: '510 Mbps',
      latency: '0.07 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#C47A16',
      type: 'ids',
      fixedX: -155,
      fixedY: 150,
      layerX: -20,
      layerY: -45,
      w: 154,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'AF_PACKET Zero-Copy'
    },
    {
      id: 'NODE-SSH',
      label: 'Linux SSH Bastion',
      zone: 'INTERNAL',
      zoneName: 'Host OS Tier',
      ip: '192.168.1.105',
      throughput: '48 Mbps',
      latency: '0.06 ms',
      status: 'ACTIVE',
      statusClass: 'green',
      isQuarantined: false,
      color: '#25855A',
      type: 'ssh',
      fixedX: 155,
      fixedY: 150,
      layerX: -20,
      layerY: 45,
      w: 154,
      h: 52,
      x: 0,
      y: 0,
      protocol: 'OpenSSH PAM'
    }
  ],

  // Vascular conduits
  conduits: [
    { from: 1, to: 4, flow: 'high' },
    { from: 2, to: 4, flow: 'med' },
    { from: 3, to: 5, flow: 'med' },
    { from: 4, to: 0, flow: 'high' },
    { from: 5, to: 0, flow: 'high' },
    { from: 6, to: 4, flow: 'high' },
    { from: 6, to: 0, flow: 'med' },
    { from: 7, to: 5, flow: 'low' },
    { from: 7, to: 0, flow: 'high' }
  ],

  async init() {
    this.bindEvents();
    await this.fetchData();
    this.startMeshAnimationLoop();
  },

  async onScreenOpen() {
    await this.fetchData();
    this.startMeshAnimationLoop();
  },

  async fetchData() {
    if (!window.LogVaultAPI) return;
    
    const res = await LogVaultAPI.getSources();
    const realSources = res.sources || [];
    
    // Keep CORE-VAULT always.
    const coreNode = this.nodes.find(n => n.id === 'CORE-VAULT') || this.nodes[0];
    
    // Fixed positions for up to 7 sources based on the original symmetrical layout
    const templateSlots = [
      { fixedX: -290, fixedY: -95, layerX: -300, layerY: -110 },
      { fixedX: 0, fixedY: -135, layerX: -300, layerY: 0 },
      { fixedX: 290, fixedY: -95, layerX: -300, layerY: 110 },
      { fixedX: -300, fixedY: 55, layerX: -20, layerY: -135 },
      { fixedX: 300, fixedY: 55, layerX: -20, layerY: 135 },
      { fixedX: -155, fixedY: 150, layerX: -20, layerY: -45 },
      { fixedX: 155, fixedY: 150, layerX: -20, layerY: 45 }
    ];
    
    const newNodes = [coreNode];
    const newConduits = [];
    
    for (let i = 0; i < Math.min(realSources.length, templateSlots.length); i++) {
      const src = realSources[i];
      const slot = templateSlots[i];
      const isCritical = src.anomaly_count > 0 || src.max_threat_score >= 70;
      
      newNodes.push({
        id: 'SRC-' + i,
        label: 'Source Node ' + (i+1),
        zone: 'INTERNAL',
        zoneName: 'Observed Network',
        ip: src.source_ip,
        throughput: src.event_count + ' events',
        latency: src.anomaly_count + ' anomalies',
        status: isCritical ? 'ANOMALOUS' : 'ACTIVE',
        statusClass: isCritical ? 'cherry' : 'green',
        isQuarantined: false,
        color: isCritical ? '#C6283D' : '#25855A',
        type: 'server',
        fixedX: slot.fixedX,
        fixedY: slot.fixedY,
        layerX: slot.layerX,
        layerY: slot.layerY,
        w: 160,
        h: 52,
        x: 0,
        y: 0,
        protocol: 'Detected'
      });
      
      newConduits.push({ from: i + 1, to: 0, flow: isCritical ? 'high' : 'med' });
    }
    
    this.nodes = newNodes;
    this.conduits = newConduits;
    
    this.computeNodeCoordinates();
    this.renderBandwidthBars();
    this.renderForensicsTable();
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

    // Packet burst button
    const btnBurst = document.getElementById('btn-topology-packet-burst');
    if (btnBurst) {
      btnBurst.addEventListener('click', () => {
        this.packetBurstActive = true;
        this.burstTimer = 180;
        Utils.showToast('⚡ Ingesting high-velocity telemetry packet burst (180,000 pkts/s)', 'info');
      });
    }

    // Reset isolation button
    const btnReset = document.getElementById('btn-topology-reset-isolation');
    if (btnReset) {
      btnReset.addEventListener('click', () => {
        this.nodes.forEach(n => {
          n.isQuarantined = false;
          n.status = n.id === 'CORE-VAULT' ? 'OPTIMAL' : 'ACTIVE';
          n.statusClass = 'green';
        });
        this.renderBandwidthBars();
        this.renderForensicsTable();
        Utils.showToast('✓ All containment barriers disengaged. Mesh nominal.', 'success');
      });
    }

    window.addEventListener('resize', () => {
      if (Navigation.activeScreen === 'topology') {
        this.computeNodeCoordinates();
      }
    });
  },

  toggleQuarantine(nodeId) {
    const n = this.nodes.find(node => node.id === nodeId);
    if (!n || n.id === 'CORE-VAULT') return;

    n.isQuarantined = !n.isQuarantined;
    n.status = n.isQuarantined ? 'QUARANTINED' : 'ACTIVE';
    n.statusClass = n.isQuarantined ? 'cherry' : 'green';

    if (n.isQuarantined) {
      Utils.showToast(`🚨 Containment forcefield engaged: ${n.label} (${n.ip}) isolated from perimeter mesh!`, 'danger');
    } else {
      Utils.showToast(`✓ Quarantine lifted for ${n.label} (${n.ip}). Conduits restored.`, 'success');
    }

    this.renderBandwidthBars();
    this.renderForensicsTable();
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
      ctx.fillText(`THROUGHPUT: ${n.throughput}`, hx + 12, hy + 58);
      ctx.fillText(`TRANSPORT: ${n.protocol}`, hx + 12, hy + 70);

      // Action Hint
      ctx.font = '800 8px JetBrains Mono, monospace';
      ctx.fillStyle = '#B4233C';
      ctx.fillText(n.isQuarantined ? '⚡ CLICK TO LIFT ISOLATION' : '🚨 CLICK TO ENGAGE FORCEFIELD', hx + 12, hy + 88);
      ctx.restore();
    }
  },

  // 2. Active Node Conduits Telemetry Matrix (2-Column SOC Deck)
  renderBandwidthBars() {
    const container = document.getElementById('topologyBandwidthContainer');
    if (!container) return;

    const getCapacityPct = (n) => {
      if (n.isQuarantined) return 4;
      if (n.id === 'CORE-VAULT') return 94;
      if (n.id === 'NODE-FW01') return 84;
      if (n.id === 'NODE-K8S') return 76;
      if (n.id === 'NODE-IDS') return 62;
      if (n.id === 'NODE-AWS') return 51;
      if (n.id === 'NODE-VPN') return 38;
      if (n.id === 'NODE-KERBEROS') return 29;
      return 18;
    };

    container.innerHTML = `
      <div class="node-conduits-matrix">
        ${this.nodes.map(n => {
          const pct = getCapacityPct(n);
          const isCore = n.id === 'CORE-VAULT';
          const zoneBadgeClass = n.zone === 'CORE' ? 'cherry' : (n.zone === 'DMZ' ? 'warn' : 'green');
          const iconName = n.type === 'core' ? 'shield-check' : (n.type === 'firewall' ? 'shield-alert' : (n.type === 'cloud' ? 'cloud' : (n.type === 'vpn' ? 'lock' : (n.type === 'k8s' ? 'layers' : (n.type === 'iam' ? 'key' : (n.type === 'ids' ? 'eye' : 'terminal'))))));
          
          return `
            <div class="node-conduit-card ${n.isQuarantined ? 'quarantined' : ''} ${isCore ? 'core-node' : ''}">
              <div class="node-conduit-top">
                <div class="d-flex align-center gap-2" style="min-width:0;">
                  <div class="node-conduit-emblem ${zoneBadgeClass}">
                    <i data-lucide="${iconName}"></i>
                  </div>
                  <div style="min-width:0;">
                    <strong class="node-conduit-title">${n.label}</strong>
                    <span class="node-conduit-sub">${n.ip} &bull; ${n.protocol}</span>
                  </div>
                </div>
                <div class="d-flex align-center gap-1" style="flex-shrink:0;">
                  <span class="badge-pill ${zoneBadgeClass}-pill" style="font-size:0.56rem;">${n.zone}</span>
                  <span class="badge-pill ${n.statusClass}-pill" style="font-size:0.56rem;"><span class="pulse-dot"></span> ${n.status}</span>
                </div>
              </div>

              <div class="node-conduit-meter-box">
                <div class="d-flex justify-between align-center mb-1">
                  <span class="node-conduit-meter-label">CONDUIT SATURATION</span>
                  <span class="node-conduit-meter-pct" style="color:${n.isQuarantined ? '#C6283D' : (isCore ? '#B4233C' : 'var(--status-green)')};">${pct}% LOAD</span>
                </div>
                <div class="node-conduit-track">
                  <div class="node-conduit-fill ${n.isQuarantined ? 'crit' : ''}" style="width: ${pct}%; background-color: ${n.isQuarantined ? '#C6283D' : n.color};"></div>
                </div>
              </div>

              <div class="node-conduit-footer">
                <div class="node-conduit-metrics">
                  <div>
                    <span class="node-metric-lbl">THROUGHPUT</span>
                    <strong class="node-metric-val" style="color:${n.isQuarantined ? '#C6283D' : 'var(--text-ink)'};">${n.throughput}</strong>
                  </div>
                  <div>
                    <span class="node-metric-lbl">LATENCY</span>
                    <strong class="node-metric-val" style="color:var(--status-green);">${n.latency}</strong>
                  </div>
                </div>
                ${isCore ? '<span class="badge-pill cherry-pill" style="font-size:0.58rem;">PROTECTED CORE</span>' : `
                  <button class="btn-cream-action btn-sm node-conduit-action-btn" onclick="TopologyModule.toggleQuarantine('${n.id}')" style="font-size:0.65rem; padding:3px 8px; font-weight:700; color:${n.isQuarantined ? 'var(--status-green)' : 'var(--status-red)'};">
                    <i data-lucide="${n.isQuarantined ? 'shield-check' : 'shield-alert'}"></i>
                    ${n.isQuarantined ? 'Lift Shield' : 'Drop Forcefield'}
                  </button>
                `}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;

    if (window.lucide) lucide.createIcons();
  },

  // 3. Forensics Table
  renderForensicsTable() {
    const tbody = document.getElementById('topology-forensics-tbody');
    if (!tbody) return;

    tbody.innerHTML = this.nodes.map(n => `
      <tr>
        <td style="font-weight:800; color:var(--cherry-primary); font-family:var(--font-mono);">${n.id}</td>
        <td><strong style="color:var(--text-ink);">${n.label}</strong></td>
        <td><span class="badge-pill ${n.zone === 'CORE' ? 'cherry' : (n.zone === 'DMZ' ? 'warn' : 'green')}-pill" style="font-size:0.60rem;">${n.zoneName}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.74rem; color:var(--text-muted);">${n.ip}</td>
        <td style="font-family:var(--font-mono); color:var(--text-ink); font-weight:800;">${n.throughput}</td>
        <td style="font-family:var(--font-mono); font-size:0.70rem; color:var(--text-muted);">${n.protocol}</td>
        <td style="font-family:var(--font-mono); color:var(--cherry-primary); font-weight:800;">${n.latency}</td>
        <td><span class="badge-pill ${n.statusClass}-pill">${n.status}</span></td>
        <td>
          ${n.id === 'CORE-VAULT' ? '<span style="font-size:0.68rem; color:var(--text-muted); font-family:var(--font-mono);">PROTECTED CORE</span>' : `
            <button class="btn-cream-action btn-sm" onclick="TopologyModule.toggleQuarantine('${n.id}')" style="font-size:0.68rem; padding:4px 10px; color:${n.isQuarantined ? 'var(--status-green)' : 'var(--status-red)'}; font-weight:700;">
              ${n.isQuarantined ? 'Lift Shield' : 'Drop Forcefield'}
            </button>
          `}
        </td>
      </tr>
    `).join('');
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
