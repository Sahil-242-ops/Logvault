/**
 * LOGVAULT — Log Sources & Ingestion Fleet Architecture Module (Stage 5)
 * 60 FPS Ingestion Pipeline Flowchart Canvas + Multi-Source Bar Graphs + Collector Fleet Deck
 */

const SourcesModule = {
  animFrameId: null,
  hoveredNode: null,

  fleetData: [
    { id: 'SRC-01', name: 'server-01.prod.ec2', proto: 'SSH / Syslog (RFC 5424)', eps: 304, bufferPct: 18, bufferStr: '18.2K / min', tls: 'TLS 1.3 mTLS', status: 'HEALTHY', statusClass: 'green-pill', latency: '0.04 ms' },
    { id: 'SRC-02', name: 'perimeter-fw01.dc', proto: 'CEF ArcSight v0.1', eps: 702, bufferPct: 42, bufferStr: '42.1K / min', tls: 'IPsec Tunnel', status: 'HEALTHY', statusClass: 'green-pill', latency: '0.08 ms' },
    { id: 'SRC-03', name: 'aws-cloudtrail.s3', proto: 'AWS S3 JSON Stream', eps: 140, bufferPct: 12, bufferStr: '8.4K / min', tls: 'HTTPS SigV4', status: 'HEALTHY', statusClass: 'green-pill', latency: '0.12 ms' },
    { id: 'SRC-04', name: 'win-domain-dc01', proto: 'Windows EventLog XML', eps: 213, bufferPct: 24, bufferStr: '12.8K / min', tls: 'WinRM Kerberos', status: 'HEALTHY', statusClass: 'green-pill', latency: '0.09 ms' },
    { id: 'SRC-05', name: 'vpn-gateway-west', proto: 'Syslog RFC 5424', eps: 35, bufferPct: 68, bufferStr: '2.1K / min', tls: 'TLS 1.2', status: 'DELAYED', statusClass: 'gold-pill', latency: '0.24 ms' },
    { id: 'SRC-06', name: 'suricata-eve-ids', proto: 'EVE JSON Unix Socket', eps: 85, bufferPct: 8, bufferStr: '5.1K / min', tls: 'Local Socket', status: 'HEALTHY', statusClass: 'green-pill', latency: '0.05 ms' },
    { id: 'SRC-07', name: 'backup-vault-02', proto: 'Storage Replay Mirror', eps: 0, bufferPct: 0, bufferStr: '0 / min', tls: 'NFSv4 / SSH', status: 'STANDBY', statusClass: 'warn-pill', latency: '--' }
  ],

  init() {
    this.renderFleetTable();
    this.renderThroughputChart();
    this.renderProtocolDonutChart();
    this.renderEpsBarsChart();
    this.renderLatencyBenchmarkBars();
    this.renderBufferSaturationBars();
    this.initFlowchart();
    this.bindEvents();
  },

  onScreenOpen() {
    this.renderFleetTable();
    this.renderThroughputChart();
    this.renderProtocolDonutChart();
    this.renderEpsBarsChart();
    this.renderLatencyBenchmarkBars();
    this.renderBufferSaturationBars();
    this.initFlowchart();
  },

  bindEvents() {
    const btnFlush = document.getElementById('btn-flush-buffers');
    if (btnFlush) {
      btnFlush.addEventListener('click', () => {
        Utils.showToast('✓ All Edge Ring Buffers flushed to storage vault successfully.', 'success');
      });
    }

    const btnDeploy = document.getElementById('btn-deploy-agent');
    if (btnDeploy) {
      btnDeploy.addEventListener('click', () => {
        Utils.showToast('Generating one-line collector agent installation curl snippet...', 'warning');
      });
    }

    // Canvas mouse move for interactive node hovering
    const canvas = document.getElementById('sourcesFlowchartCanvas');
    if (canvas) {
      canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        this.mouseX = e.clientX - rect.left;
        this.mouseY = e.clientY - rect.top;
      });
      canvas.addEventListener('mouseleave', () => {
        this.mouseX = -1;
        this.mouseY = -1;
      });
    }
  },

  renderFleetTable() {
    const tbody = document.getElementById('sources-fleet-tbody');
    if (!tbody) return;

    tbody.innerHTML = this.fleetData.map(s => `
      <tr>
        <td style="font-weight:800; color:var(--cherry-primary); font-family:var(--font-mono);">${s.id}</td>
        <td>
          <strong style="color:var(--text-ink);">${s.name}</strong>
        </td>
        <td style="color:var(--text-muted); font-family:var(--font-mono);">${s.proto}</td>
        <td>
          <strong style="color:var(--text-ink);">${s.eps} EPS</strong>
        </td>
        <td>
          <div class="buffer-bar-wrap">
            <div class="buffer-bar-fill ${s.bufferPct > 50 ? 'warn' : ''}" style="width: ${s.bufferPct}%;"></div>
          </div>
          <span style="font-size:0.68rem; color:var(--text-muted);">${s.bufferStr}</span>
        </td>
        <td style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-muted);">${s.tls}</td>
        <td style="font-family:var(--font-mono); color:var(--cherry-primary); font-weight:700;">${s.latency}</td>
        <td><span class="badge-pill ${s.statusClass}">${s.status}</span></td>
      </tr>
    `).join('');
  },

  // 1. Throughput Spline Chart
  renderThroughputChart() {
    const canvas = document.getElementById('sourcesThroughputCanvas');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 80);
    if (!scaled) return;
    const { ctx, width: w, height: h } = scaled;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    ctx.clearRect(0, 0, w, h);

    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.moveTo(30, h * 0.35);
    ctx.lineTo(w - 10, h * 0.35);
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.25)' : '#D4A8B0';
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.setLineDash([]);

    const points = [
      { x: 35, y: h * 0.80 },
      { x: 75, y: h * 0.60 },
      { x: 110, y: h * 0.50 },
      { x: 145, y: h * 0.65 },
      { x: 185, y: h * 0.32 },
      { x: 220, y: h * 0.45 },
      { x: 255, y: h * 0.25 },
      { x: 285, y: h * 0.20 }
    ];

    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, isDark ? 'rgba(212, 56, 83, 0.45)' : 'rgba(180, 35, 60, 0.35)');
    grad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const xc = (points[i].x + points[i + 1].x) / 2;
      const yc = (points[i].y + points[i + 1].y) / 2;
      ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.lineTo(points[points.length - 1].x, h - 18);
    ctx.lineTo(points[0].x, h - 18);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const xc = (points[i].x + points[i + 1].x) / 2;
      const yc = (points[i].y + points[i + 1].y) / 2;
      ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.strokeStyle = isDark ? '#D43853' : '#B4233C';
    ctx.lineWidth = 2;
    ctx.stroke();

    const apex = points[points.length - 1];
    ctx.beginPath();
    ctx.arc(apex.x, apex.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = isDark ? '#D43853' : '#74152A';
    ctx.fill();
    ctx.strokeStyle = '#FFFFFF';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.font = '600 8.5px Inter, sans-serif';
    ctx.fillStyle = isDark ? '#A89094' : '#756568';
    ctx.fillText('05:00', 35, h - 4);
    ctx.fillText('06:00', 105, h - 4);
    ctx.fillText('12:00', 190, h - 4);
    ctx.fillText('12:00', 265, h - 4);
  },

  // 2. Protocol Donut Chart
  renderProtocolDonutChart() {
    const canvas = document.getElementById('sourcesProtocolDonutCanvas');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 85);
    if (!scaled) return;
    const { ctx, width: w, height: h } = scaled;
    const cx = w / 2;
    const cy = h / 2;
    const rOut = Math.min(w, h) * 0.44;
    const rIn = Math.min(w, h) * 0.26;

    ctx.clearRect(0, 0, w, h);

    const slices = [
      { pct: 0.38, color: '#74152A' },
      { pct: 0.26, color: '#9C1A30' },
      { pct: 0.18, color: '#C47A16' },
      { pct: 0.12, color: '#E09F3E' },
      { pct: 0.06, color: '#25855A' }
    ];

    let start = -Math.PI / 2;
    slices.forEach(s => {
      const angle = s.pct * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, rOut, start, start + angle);
      ctx.arc(cx, cy, rIn, start + angle, start, true);
      ctx.closePath();
      ctx.fillStyle = s.color;
      ctx.fill();
      start += angle;
    });
  },

  // 3. EPS Bars Chart (Vertical Bar Graph)
  renderEpsBarsChart() {
    const canvas = document.getElementById('sourcesEpsBarsCanvas');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 65);
    if (!scaled) return;
    const { ctx, width: w, height: h } = scaled;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    ctx.clearRect(0, 0, w, h);

    const bars = [
      { eps: '702', hPct: 0.95, color: isDark ? '#D43853' : '#4A0814', label: 'FW01' },
      { eps: '304', hPct: 0.72, color: isDark ? '#E8A0AA' : '#74152A', label: 'SSH' },
      { eps: '213', hPct: 0.60, color: isDark ? '#B4233C' : '#9C1A30', label: 'WIN' },
      { eps: '140', hPct: 0.48, color: '#D43853', label: 'AWS' },
      { eps: '85', hPct: 0.36, color: '#DD6B20', label: 'EVE' },
      { eps: '35', hPct: 0.22, color: '#E09F3E', label: 'VPN' },
      { eps: '0', hPct: 0.06, color: isDark ? '#68595B' : '#756568', label: 'BAK' }
    ];

    const barWidth = 14;
    const gap = (w - (bars.length * barWidth)) / (bars.length + 1);

    bars.forEach((b, i) => {
      const x = gap + i * (barWidth + gap);
      const barH = (h - 26) * b.hPct;
      const y = h - 14 - barH;

      ctx.fillStyle = b.color;
      ctx.fillRect(x, y, barWidth, barH);

      ctx.font = '700 8.5px "JetBrains Mono", monospace';
      ctx.fillStyle = isDark ? '#FFF8F0' : '#24191B';
      ctx.textAlign = 'center';
      ctx.fillText(b.eps, x + barWidth / 2, y - 3);

      ctx.font = '600 7.5px Inter, sans-serif';
      ctx.fillStyle = isDark ? '#A89094' : '#756568';
      ctx.fillText(b.label, x + barWidth / 2, h - 3);
    });
  },

  // 4. Latency Benchmark Horizontal Bar Graph Stack
  renderLatencyBenchmarkBars() {
    const container = document.getElementById('latency-benchmarks-container');
    if (!container) return;

    const items = [
      { name: 'C++ Deterministic (PAM/Syslog)', latency: '0.04 ms', pct: 6, color: '#25855A' },
      { name: 'WASM CEF Parser (Palo Alto)', latency: '0.08 ms', pct: 14, color: '#25855A' },
      { name: 'WASM CloudTrail Parser (AWS)', latency: '0.12 ms', pct: 20, color: '#25855A' },
      { name: 'Windows EventLog XML Parser', latency: '0.09 ms', pct: 16, color: '#25855A' },
      { name: 'Dynamic Schema Mapper', latency: '1.20 ms', pct: 85, color: '#B4233C' }
    ];

    container.innerHTML = items.map(item => `
      <div class="latency-bench-item">
        <span class="latency-bench-item-label">${item.name}</span>
        <div class="latency-bench-bar-track">
          <div class="latency-bench-bar-fill" style="width: ${item.pct}%; background-color: ${item.color};"></div>
        </div>
        <span class="latency-bench-val" style="color: ${item.color};">${item.latency}</span>
      </div>
    `).join('');
  },

  // 5. Buffer Saturation Capacity Bar Graph Stack
  renderBufferSaturationBars() {
    const container = document.getElementById('buffer-saturation-container');
    if (!container) return;

    const items = [
      { name: 'Perimeter FW 01 Buffer (Ring 0)', load: '42.1%', pct: 42, color: '#25855A' },
      { name: 'Linux SSH Auth Buffer (Ring 1)', load: '18.2%', pct: 18, color: '#25855A' },
      { name: 'Windows Kerberos Buffer (Ring 2)', load: '24.0%', pct: 24, color: '#25855A' },
      { name: 'AWS S3 CloudTrail (Ring 3)', load: '12.0%', pct: 12, color: '#25855A' },
      { name: 'VPN Gateway Buffer (Ring 4)', load: '68.0%', pct: 68, color: '#C47A16' }
    ];

    container.innerHTML = items.map(item => `
      <div class="latency-bench-item">
        <span class="latency-bench-item-label">${item.name}</span>
        <div class="latency-bench-bar-track">
          <div class="latency-bench-bar-fill" style="width: ${item.pct}%; background-color: ${item.color};"></div>
        </div>
        <span class="latency-bench-val" style="color: ${item.color};">${item.load}</span>
      </div>
    `).join('');
  },

  // Universal helper for rounded rectangle
  drawBox(ctx, x, y, width, height, radius = 5) {
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
  },

  // 6. 60 FPS Comprehensive Ingestion Pipeline Flowchart Canvas
  initFlowchart() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }

    const canvas = document.getElementById('sourcesFlowchartCanvas');
    if (!canvas) return;

    const renderLoop = () => {
      try {
        this.drawFlowchartFrame(canvas);
      } catch (err) {
        console.error('Flowchart draw error:', err);
      }
      this.animFrameId = requestAnimationFrame(renderLoop);
    };

    this.animFrameId = requestAnimationFrame(renderLoop);
  },

  drawFlowchartFrame(canvas) {
    if (!canvas) return;
    const parent = canvas.parentElement;
    const w = (parent && parent.clientWidth > 100) ? parent.clientWidth : 1000;
    const h = 480;
    const dpr = window.devicePixelRatio || 1;

    const targetW = Math.floor(w * dpr);
    const targetH = Math.floor(h * dpr);

    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Guaranteed cross-browser scale & clear
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    // 5 Architectural Tiers of Ingestion Pipeline
    const stages = [
      { name: 'Tier 1: Collector Fleet', x: w * 0.12 },
      { name: 'Tier 2: Ring Buffers', x: w * 0.32 },
      { name: 'Tier 3: Ingest Singularity', x: w * 0.52 },
      { name: 'Tier 4: Parser Array', x: w * 0.72 },
      { name: 'Tier 5: Standard Sinks', x: w * 0.90 }
    ];

    // Background Isometric Mesh Grid
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.06)' : 'rgba(116, 21, 42, 0.05)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 36) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 36) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Tier 1 Sources Nodes (6 Nodes)
    const sourcesNodes = [
      { label: 'Linux SSH PAM', y: h * 0.16, icon: '', eps: '304 EPS' },
      { label: 'Palo Alto FW01', y: h * 0.30, icon: '', eps: '702 EPS' },
      { label: 'AWS S3 Trail', y: h * 0.44, icon: '', eps: '140 EPS' },
      { label: 'WinEvent XML', y: h * 0.58, icon: '', eps: '213 EPS' },
      { label: 'VPN Perimeter', y: h * 0.72, icon: '', eps: '35 EPS' },
      { label: 'Suricata EVE', y: h * 0.86, icon: '', eps: '85 EPS' }
    ];

    // Tier 2: Ring Buffer Nodes
    const bufferNode = { x: stages[1].x, y: h * 0.50, label: 'Lock-Free FIFO Ring Buffer (18.4K/s)' };

    // Tier 3: Ingestion Singularity / Fast Dispatcher Core
    const coreNode = { x: stages[2].x, y: h * 0.50, label: 'INGESTION SINGULARITY' };

    // Tier 4: Zero-Copy Parser Engine Array (4 Parsers)
    const parserNodes = [
      { label: 'C++ RFC 5424 (0.04ms)', y: h * 0.20, icon: '' },
      { label: 'WASM CEF v0.1 (0.08ms)', y: h * 0.40, icon: '' },
      { label: 'WASM CloudTrail (0.12ms)', y: h * 0.60, icon: '' },
      { label: 'Dynamic Mapper (1.2ms)', y: h * 0.80, icon: '' }
    ];

    // Tier 5: Output Sinks (3 Sinks)
    const sinkNodes = [
      { label: 'OCSF 1.1 Matrix', y: h * 0.28, icon: '' },
      { label: 'Threat Correlator', y: h * 0.50, icon: '' },
      { label: 'Storage Vault', y: h * 0.72, icon: '' }
    ];

    // 1. Draw Flow Conduits (Tier 1 Sources -> Tier 2 Buffer)
    sourcesNodes.forEach((src, idx) => {
      ctx.beginPath();
      ctx.moveTo(stages[0].x + 40, src.y);
      ctx.quadraticCurveTo((stages[0].x + bufferNode.x) / 2, src.y, bufferNode.x - 45, bufferNode.y);
      ctx.strokeStyle = isDark ? 'rgba(180, 35, 60, 0.40)' : 'rgba(180, 35, 60, 0.28)';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      // Traveling Energy Packets
      const t = ((now / 1300) + (idx * 0.18)) % 1;
      const px = (1 - t) * (1 - t) * (stages[0].x + 40) + 2 * (1 - t) * t * ((stages[0].x + bufferNode.x) / 2) + t * t * (bufferNode.x - 45);
      const py = (1 - t) * (1 - t) * src.y + 2 * (1 - t) * t * src.y + t * t * bufferNode.y;

      ctx.beginPath();
      ctx.arc(px, py, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#FFAA00';
      ctx.shadowColor = '#FF3366';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // 2. Tier 2 Buffer -> Tier 3 Core
    ctx.beginPath();
    ctx.moveTo(bufferNode.x + 45, bufferNode.y);
    ctx.lineTo(coreNode.x - 45, coreNode.y);
    ctx.strokeStyle = '#B4233C';
    ctx.lineWidth = 2.6;
    ctx.stroke();

    const tBuf = (now / 900) % 1;
    const pxBuf = bufferNode.x + 45 + (coreNode.x - 45 - (bufferNode.x + 45)) * tBuf;
    ctx.beginPath();
    ctx.arc(pxBuf, bufferNode.y, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = '#FF4D6D';
    ctx.shadowColor = '#FF0033';
    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.shadowBlur = 0;

    // 3. Tier 3 Core -> Tier 4 Parsers
    parserNodes.forEach((p, idx) => {
      ctx.beginPath();
      ctx.moveTo(coreNode.x + 45, coreNode.y);
      ctx.quadraticCurveTo((coreNode.x + stages[3].x) / 2, p.y, stages[3].x - 45, p.y);
      ctx.strokeStyle = isDark ? 'rgba(180, 35, 60, 0.40)' : 'rgba(180, 35, 60, 0.28)';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      const t = ((now / 1200) + (idx * 0.25)) % 1;
      const px = (1 - t) * (1 - t) * (coreNode.x + 45) + 2 * (1 - t) * t * ((coreNode.x + stages[3].x) / 2) + t * t * (stages[3].x - 45);
      const py = (1 - t) * (1 - t) * coreNode.y + 2 * (1 - t) * t * p.y + t * t * p.y;

      ctx.beginPath();
      ctx.arc(px, py, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#25855A';
      ctx.shadowColor = '#2A9D8F';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // 4. Tier 4 Parsers -> Tier 5 Sinks
    parserNodes.forEach((p) => {
      sinkNodes.forEach((sk) => {
        ctx.beginPath();
        ctx.moveTo(stages[3].x + 40, p.y);
        ctx.quadraticCurveTo((stages[3].x + stages[4].x) / 2, (p.y + sk.y) / 2, stages[4].x - 40, sk.y);
        ctx.strokeStyle = isDark ? 'rgba(37, 133, 90, 0.25)' : 'rgba(37, 133, 90, 0.18)';
        ctx.lineWidth = 1.4;
        ctx.stroke();
      });
    });

    // Draw Helper: Pill Card
    const drawCard = (text, x, y, icon = '', bgGrad = false, isEmerald = false, sub = '') => {
      ctx.font = '700 9px JetBrains Mono, monospace';
      const label = icon ? `${icon} ${text}` : text;
      const tw = ctx.measureText(label).width;
      const wCard = Math.max(tw + 20, 80);
      const hCard = sub ? 30 : 24;

      this.drawBox(ctx, x - wCard / 2, y - hCard / 2, wCard, hCard, 5);
      ctx.fillStyle = bgGrad ? '#74152A' : isEmerald ? '#1B4D3E' : (isDark ? '#231B1E' : '#FFFFFF');
      ctx.fill();
      ctx.strokeStyle = isEmerald ? '#25855A' : '#B4233C';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.fillStyle = bgGrad || isEmerald ? '#FFF8F0' : (isDark ? '#FFF8F0' : '#24191B');
      ctx.textAlign = 'center';
      ctx.fillText(label, x, sub ? y - 2 : y + 3.5);

      if (sub) {
        ctx.font = '700 7.5px JetBrains Mono, monospace';
        ctx.fillStyle = '#C47A16';
        ctx.fillText(sub, x, y + 10);
      }
    };

    // Render Tier 1 Source Cards
    sourcesNodes.forEach(s => drawCard(s.label, stages[0].x, s.y, s.icon, false, false, s.eps));

    // Render Tier 2 Buffer Card
    drawCard(bufferNode.label, bufferNode.x, bufferNode.y, '', false);

    // Render Tier 3 Ingestion Singularity Vortex Core
    const pulse = Math.sin(now / 180) * 3;
    const r = 28 + pulse;

    for (let i = r + 6; i < r + 26; i += 6) {
      ctx.beginPath();
      ctx.arc(coreNode.x, coreNode.y, i, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(180, 35, 60, ${(1 - (i - r) / 26) * 0.4})`;
      ctx.lineWidth = 1.4;
      ctx.stroke();
    }

    const grad = ctx.createRadialGradient(coreNode.x - 4, coreNode.y - 4, 2, coreNode.x, coreNode.y, r);
    grad.addColorStop(0, '#FFFFFF');
    grad.addColorStop(0.3, '#FF3366');
    grad.addColorStop(0.8, '#74152A');
    grad.addColorStop(1, '#2A040C');

    ctx.beginPath();
    ctx.arc(coreNode.x, coreNode.y, r, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.shadowColor = '#FF2255';
    ctx.shadowBlur = 22;
    ctx.fill();
    ctx.shadowBlur = 0;

    ctx.strokeStyle = '#FFF8F0';
    ctx.lineWidth = 2;
    ctx.stroke();

    drawCard('INGESTION SINGULARITY', coreNode.x, coreNode.y + r + 16, '✦', true);

    // Render Tier 4 Parser Cards
    parserNodes.forEach(p => drawCard(p.label, stages[3].x, p.y, p.icon, false, true));

    // Render Tier 5 Sinks Cards
    sinkNodes.forEach(sk => drawCard(sk.label, stages[4].x, sk.y, sk.icon, false, true));

    // Header Stage Labels
    stages.forEach(st => {
      ctx.font = '800 10px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#E8A0AA' : '#756568';
      ctx.textAlign = 'center';
      ctx.fillText(st.name.toUpperCase(), st.x, 26);
    });
  }
};

window.SourcesModule = SourcesModule;
