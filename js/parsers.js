/**
 * LOGVAULT — Parser Engine Registry & Performance Laboratory (Stage 3 Masterpiece)
 * 60 FPS Holographic WASM Compiler Chamber + Real-Time Particle Spark Bars
 * + Live Laser Tokenizer Sandbox + Modular Engine Fleet
 */

const ParsersModule = {
  currentCategory: 'all',
  searchQuery: '',
  animFrameId: null,
  chamberAnimId: null,
  hoveredBar: null,
  mousePos: { x: -1, y: -1 },

  engines: [
    {
      id: 'ENG-CPP-01',
      name: 'C++ Deterministic RFC 5424',
      category: 'os',
      type: 'NATIVE C++ (Zero-Copy)',
      version: 'v2.8 LTS',
      throughput: '142,500 logs/s',
      latency: '0.038 ms',
      memory: '48 KB',
      ocsfClass: 'Class 3002: Authentication',
      status: 'ACTIVE',
      statusClass: 'green',
      compliance: '100% RFC Validated',
      icon: '',
      sample: '<38>1 2026-09-02T19:30:00.120Z server-01 sshd 4102 - - Failed password for invalid user admin from 192.168.1.105 port 52410 ssh2'
    },
    {
      id: 'ENG-WASM-02',
      name: 'WASM CEF ArcSight Engine',
      category: 'network',
      type: 'WASM JIT V8 Bytecode',
      version: 'v1.9.4',
      throughput: '118,200 logs/s',
      latency: '0.075 ms',
      memory: '96 KB',
      ocsfClass: 'Class 4001: Network Activity',
      status: 'ACTIVE',
      statusClass: 'green',
      compliance: 'ArcSight CEF v0.1 Cert',
      icon: '',
      sample: 'CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|drop|7|src=185.220.101.5 dst=10.0.0.15 spt=44120 dpt=22 proto=TCP act=deny'
    },
    {
      id: 'ENG-CPP-03',
      name: 'Nginx / Apache Combined Access',
      category: 'network',
      type: 'NATIVE C++ (SIMD Regex)',
      version: 'v2.4',
      throughput: '124,000 logs/s',
      latency: '0.045 ms',
      memory: '64 KB',
      ocsfClass: 'Class 4002: HTTP Activity',
      status: 'ACTIVE',
      statusClass: 'green',
      compliance: 'W3C Standard',
      icon: '',
      sample: '192.168.1.50 - frank [02/Sep/2026:19:34:02 +0000] "GET /api/v1/auth HTTP/1.1" 200 4522 "-" "Mozilla/5.0"'
    },
    {
      id: 'ENG-WASM-04',
      name: 'AWS CloudTrail S3 JSON Parser',
      category: 'cloud',
      type: 'WASM SIMD JSON Stream',
      version: 'v2.1',
      throughput: '96,400 logs/s',
      latency: '0.110 ms',
      memory: '128 KB',
      ocsfClass: 'Class 3001: Account Change',
      status: 'ACTIVE',
      statusClass: 'green',
      compliance: 'AWS SigV4 & JSON 1.08',
      icon: '',
      sample: '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.19"}'
    },
    {
      id: 'ENG-CPP-05',
      name: 'Windows Security EventLog XML',
      category: 'os',
      type: 'NATIVE C++ (FastXML)',
      version: 'v3.0',
      throughput: '88,000 logs/s',
      latency: '0.088 ms',
      memory: '112 KB',
      ocsfClass: 'Class 3002: Authentication',
      status: 'ACTIVE',
      statusClass: 'green',
      compliance: 'MS EventLog Schema',
      icon: '',
      sample: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID></System><EventData><Data Name="TargetUserName">SYSTEM</Data></EventData></Event>'
    },
    {
      id: 'ENG-WASM-06',
      name: 'Suricata EVE IDS Stream',
      category: 'network',
      type: 'WASM JIT Stream',
      version: 'v1.6',
      throughput: '105,300 logs/s',
      latency: '0.062 ms',
      memory: '80 KB',
      ocsfClass: 'Class 2001: Security Finding',
      status: 'ACTIVE',
      statusClass: 'green',
      compliance: 'Suricata 7.x Verified',
      icon: '',
      sample: '{"timestamp":"2026-09-02T19:30:00Z","event_type":"alert","src_ip":"198.51.100.22","alert":{"signature":"ET SCAN Potential SSH Scan"}}'
    },
    {
      id: 'ENG-AI-07',
      name: 'Dynamic Pattern & Schema Mapper',
      category: 'ai',
      type: 'Pattern Engine / AST Synthesizer',
      version: 'v4.2 Core',
      throughput: '18,420 logs/s',
      latency: '1.200 ms',
      memory: '1.8 MB',
      ocsfClass: 'Dynamic OCSF 1.1 Inferrer',
      status: 'ACTIVE',
      statusClass: 'cherry',
      compliance: 'Pattern Schema Cross-Mapping',
      icon: '',
      sample: '[SCADA_PLC_09] EVT=VALVE_FAIL UNIT=PUMP_WEST PRESS=84.2PSI SRC_IP=172.16.4.18 STATE=CRIT'
    }
  ],

  // Particle System for Bar Graph Sparks
  sparks: [],

  init() {
    this.renderLatencyBars();
    this.renderCatalog();
    this.bindEvents();
    this.startThroughputAnimationLoop();
    this.startCompilerChamberLoop();
    this.runSandboxBenchmark();
  },

  onScreenOpen() {
    this.renderLatencyBars();
    this.renderCatalog();
    this.startThroughputAnimationLoop();
    this.startCompilerChamberLoop();
  },

  bindEvents() {
    // Category filter pills
    document.querySelectorAll('.parser-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.parser-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentCategory = btn.getAttribute('data-cat') || 'all';
        this.renderCatalog();
      });
    });

    // Search filter input
    const searchInput = document.getElementById('parser-catalog-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase();
        this.renderCatalog();
      });
    }

    // Sandbox preset buttons
    document.querySelectorAll('.sandbox-preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const engineId = btn.getAttribute('data-engine-id');
        const found = this.engines.find(e => e.id === engineId);
        if (found) {
          const textarea = document.getElementById('parser-sandbox-input');
          if (textarea) textarea.value = found.sample;
          const select = document.getElementById('parser-sandbox-engine-select');
          if (select) select.value = found.id;
          this.triggerLaserScan();
          this.runSandboxBenchmark();
        }
      });
    });

    // Run benchmark button
    const btnRun = document.getElementById('btn-run-sandbox-bench');
    if (btnRun) {
      btnRun.addEventListener('click', () => {
        this.triggerLaserScan();
        this.runSandboxBenchmark();
      });
    }

    // Export WASM button
    const btnExport = document.getElementById('btn-export-wasm-bytecode');
    if (btnExport) {
      btnExport.addEventListener('click', () => {
        Utils.showToast('✓ Standalone WASM Bytecode binary (< 42 KB) compiled & exported for air-gapped deployment.', 'success');
      });
    }

    // Canvas Hover Events
    const canvas = document.getElementById('parsersThroughputCanvas');
    if (canvas) {
      canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        this.mousePos = {
          x: (e.clientX - rect.left) * (canvas.width / rect.width),
          y: (e.clientY - rect.top) * (canvas.height / rect.height)
        };
      });
      canvas.addEventListener('mouseleave', () => {
        this.mousePos = { x: -1, y: -1 };
        this.hoveredBar = null;
      });
    }
  },

  triggerLaserScan() {
    const scanner = document.querySelector('.sandbox-laser-scanner');
    if (scanner) {
      scanner.classList.remove('scanning');
      void scanner.offsetWidth; // Trigger reflow
      scanner.classList.add('scanning');
      setTimeout(() => scanner.classList.remove('scanning'), 1600);
    }
  },

  // 1. 60 FPS Animated Vertical Throughput Bar Graph Loop
  startThroughputAnimationLoop() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }

    const canvas = document.getElementById('parsersThroughputCanvas');
    if (!canvas) return;

    const loop = () => {
      try {
        this.drawAnimatedThroughputBars(canvas);
      } catch (e) {
        console.error('Throughput canvas error:', e);
      }
      this.animFrameId = requestAnimationFrame(loop);
    };

    this.animFrameId = requestAnimationFrame(loop);
  },

  drawAnimatedThroughputBars(canvas) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    ctx.clearRect(0, 0, w, h);

    const data = [
      { name: 'C++ Syslog', val: 142.5, maxVal: 160, color: '#25855A', tag: '142K/s', simdW: '256-bit AVX2' },
      { name: 'WASM CEF', val: 118.2, maxVal: 160, color: '#74152A', tag: '118K/s', simdW: '128-bit WASM' },
      { name: 'C++ Nginx', val: 124.0, maxVal: 160, color: '#25855A', tag: '124K/s', simdW: '256-bit AVX2' },
      { name: 'WASM AWS', val: 96.4, maxVal: 160, color: '#9C1A30', tag: '96K/s', simdW: '128-bit WASM' },
      { name: 'C++ WinLog', val: 88.0, maxVal: 160, color: '#B4233C', tag: '88K/s', simdW: 'FastXML Tree' },
      { name: 'WASM Suricata', val: 105.3, maxVal: 160, color: '#C47A16', tag: '105K/s', simdW: '128-bit WASM' },
      { name: 'AI Zero-Shot', val: 0, maxVal: 160, color: '#E09F3E', tag: 'Local AI', simdW: 'ONNX INT8' }
    ];

    const barWidth = 36;
    const gap = (w - (data.length * barWidth)) / (data.length + 1);

    // Grid baseline
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.18)' : 'rgba(116, 21, 42, 0.12)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(10, h - 28);
    ctx.lineTo(w - 10, h - 28);
    ctx.stroke();

    // Spawn Particles from Bar Tops
    if (Math.random() < 0.35) {
      const randomBar = data[Math.floor(Math.random() * data.length)];
      const bIdx = data.indexOf(randomBar);
      const bx = gap + bIdx * (barWidth + gap) + Math.random() * barWidth;
      const baseH = (h - 68) * (randomBar.val / randomBar.maxVal);
      const by = h - 28 - baseH;
      this.sparks.push({
        x: bx,
        y: by,
        vx: (Math.random() - 0.5) * 0.8,
        vy: -Math.random() * 1.5 - 0.5,
        alpha: 1,
        color: randomBar.color,
        size: Math.random() * 2.2 + 1.2
      });
    }

    // Update & Draw Sparks
    for (let i = this.sparks.length - 1; i >= 0; i--) {
      const p = this.sparks[i];
      p.x += p.vx;
      p.y += p.vy;
      p.alpha -= 0.025;

      if (p.alpha <= 0) {
        this.sparks.splice(i, 1);
        continue;
      }

      ctx.save();
      ctx.globalAlpha = p.alpha;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.restore();
    }

    this.hoveredBar = null;

    data.forEach((d, i) => {
      const x = gap + i * (barWidth + gap);
      // Subtle organic breathing oscillation
      const oscillation = Math.sin((now / 400) + i) * 2;
      const barH = Math.max(10, (h - 68) * (d.val / d.maxVal) + oscillation);
      const y = h - 28 - barH;

      const isHovered = (
        this.mousePos.x >= x &&
        this.mousePos.x <= x + barWidth &&
        this.mousePos.y >= y - 10 &&
        this.mousePos.y <= h - 28
      );

      if (isHovered) {
        this.hoveredBar = { d, x, y, barWidth, barH };
      }

      // Bar Body (Gradient + Specular Top)
      const grad = ctx.createLinearGradient(x, y, x, h - 28);
      if (isHovered) {
        grad.addColorStop(0, '#FF3366');
        grad.addColorStop(0.5, d.color);
        grad.addColorStop(1, '#2A040C');
      } else {
        grad.addColorStop(0, d.color);
        grad.addColorStop(1, isDark ? '#1F1719' : '#F6EDE3');
      }

      ctx.save();
      if (isHovered) {
        ctx.shadowColor = '#FF3366';
        ctx.shadowBlur = 16;
      }

      ctx.fillStyle = grad;
      ctx.fillRect(x, y, barWidth, barH);

      // Glowing Neon Top Border
      ctx.strokeStyle = isHovered ? '#FFFFFF' : '#FFF8F0';
      ctx.lineWidth = isHovered ? 2.2 : 1.4;
      ctx.beginPath();
      ctx.moveTo(x, y);
      ctx.lineTo(x + barWidth, y);
      ctx.stroke();
      ctx.restore();

      // Top Value Tag
      ctx.font = '700 9px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#FFF8F0' : '#24191B';
      ctx.textAlign = 'center';
      ctx.fillText(d.tag, x + barWidth / 2, y - 6);

      // Bottom Label
      ctx.font = '700 8px Plus Jakarta Sans, sans-serif';
      ctx.fillStyle = isHovered ? '#B4233C' : (isDark ? '#D4A8B0' : '#756568');
      ctx.fillText(d.name, x + barWidth / 2, h - 10);
    });

    // Tooltip HUD for Hovered Bar
    if (this.hoveredBar) {
      const { d, x, y, barWidth } = this.hoveredBar;
      const tx = Math.min(w - 110, Math.max(10, x + barWidth / 2 - 50));
      const ty = Math.max(10, y - 40);

      ctx.save();
      ctx.fillStyle = isDark ? 'rgba(26, 20, 22, 0.95)' : 'rgba(255, 248, 240, 0.95)';
      ctx.strokeStyle = '#B4233C';
      ctx.lineWidth = 1.2;
      this.drawBox(ctx, tx, ty, 100, 32, 4);
      ctx.fill();
      ctx.stroke();

      ctx.font = '800 8px JetBrains Mono, monospace';
      ctx.fillStyle = '#B4233C';
      ctx.textAlign = 'left';
      ctx.fillText(`${d.name}`, tx + 6, ty + 12);

      ctx.font = '600 7px JetBrains Mono, monospace';
      ctx.fillStyle = isDark ? '#FFF8F0' : '#24191B';
      ctx.fillText(`SIMD: ${d.simdW}`, tx + 6, ty + 24);
      ctx.restore();
    }
  },

  // 2. 60 FPS JIT WebAssembly Compiler Chamber Engine
  startCompilerChamberLoop() {
    if (this.chamberAnimId) {
      cancelAnimationFrame(this.chamberAnimId);
      this.chamberAnimId = null;
    }

    const canvas = document.getElementById('wasmCompilerChamberCanvas');
    if (!canvas) return;

    const loop = () => {
      try {
        this.drawCompilerChamber(canvas);
      } catch (e) {
        console.error('Compiler chamber error:', e);
      }
      this.chamberAnimId = requestAnimationFrame(loop);
    };

    this.chamberAnimId = requestAnimationFrame(loop);
  },

  drawCompilerChamber(canvas) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const now = Date.now();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    ctx.clearRect(0, 0, w, h);

    const cx = w / 2;
    const cy = h / 2 - 6;

    // 1. Concentric Rotating Compiler Rings
    const numRings = 3;
    for (let r = 1; r <= numRings; r++) {
      const radius = 32 + r * 22;
      const speed = (now * 0.0008 * (r % 2 === 0 ? 1 : -1));

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(speed);

      ctx.beginPath();
      ctx.arc(0, 0, radius, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(180, 35, 60, ${0.18 + r * 0.08})`;
      ctx.lineWidth = 1.2;
      ctx.setLineDash([8, 12, 16, 8]);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.restore();
    }

    // 2. Arterial Laser Particle Beams
    const nodes = [
      { label: 'LEXER', x: cx - 140, y: cy - 40, color: '#25855A' },
      { label: 'AST MAP', x: cx - 140, y: cy + 40, color: '#C47A16' },
      { label: 'LLVM IR', x: cx + 140, y: cy - 40, color: '#B4233C' },
      { label: 'WASM JIT', x: cx + 140, y: cy + 40, color: '#25855A' }
    ];

    nodes.forEach((n, idx) => {
      // Bezier connector
      ctx.beginPath();
      ctx.moveTo(n.x, n.y);
      ctx.quadraticCurveTo((n.x + cx) / 2, cy + (n.y > cy ? 20 : -20), cx, cy);
      ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.22)' : 'rgba(180, 35, 60, 0.20)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Flowing particle
      const t = ((now * 0.0008) + (idx * 0.25)) % 1;
      const midX = (n.x + cx) / 2;
      const midY = cy + (n.y > cy ? 20 : -20);
      const px = (1 - t) * (1 - t) * n.x + 2 * (1 - t) * t * midX + t * t * cx;
      const py = (1 - t) * (1 - t) * n.y + 2 * (1 - t) * t * midY + t * t * cy;

      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#FF3366';
      ctx.shadowColor = '#FF3366';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Node Box
      this.drawBox(ctx, n.x - 36, n.y - 14, 72, 28, 4);
      ctx.fillStyle = isDark ? 'rgba(26, 20, 22, 0.92)' : 'rgba(255, 248, 240, 0.92)';
      ctx.fill();
      ctx.strokeStyle = n.color;
      ctx.lineWidth = 1.2;
      ctx.stroke();

      ctx.font = '800 8px JetBrains Mono, monospace';
      ctx.fillStyle = n.color;
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + 3);
    });

    // 3. Central WebAssembly JIT Core Pulsing Monolith
    const pulse = Math.sin(now / 200) * 3;
    const rCore = 26 + pulse;

    const coreGrad = ctx.createRadialGradient(cx - 4, cy - 4, 2, cx, cy, rCore);
    coreGrad.addColorStop(0, '#FFFFFF');
    coreGrad.addColorStop(0.3, '#FF3366');
    coreGrad.addColorStop(0.7, '#74152A');
    coreGrad.addColorStop(1, '#2A040C');

    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, rCore, 0, Math.PI * 2);
    ctx.fillStyle = coreGrad;
    ctx.shadowColor = '#FF2255';
    ctx.shadowBlur = 20;
    ctx.fill();
    ctx.strokeStyle = '#FFF8F0';
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.restore();

    ctx.font = '800 8.5px JetBrains Mono, monospace';
    ctx.fillStyle = '#FFFFFF';
    ctx.textAlign = 'center';
    ctx.fillText('WASM', cx, cy - 2);
    ctx.font = '700 7px JetBrains Mono, monospace';
    ctx.fillStyle = '#FFAA00';
    ctx.fillText('JIT CORE', cx, cy + 8);

    // Live Instruction Speedometer Subtext
    ctx.font = '600 8px JetBrains Mono, monospace';
    ctx.fillStyle = isDark ? '#D4A8B0' : '#756568';
    ctx.fillText(`JIT CYCLE RATE: 23,840,000 ops/s • ZERO EGRESS`, cx, h - 8);
  },

  // 3. 2-Column Comparative Performance Matrix
  renderLatencyBars() {
    const container = document.getElementById('parsersLatencyContainer');
    if (!container) return;

    const items = [
      { id: 'ENG-CPP-01', name: 'C++ RFC 5424 Syslog', cat: 'NATIVE C++', latency: '0.038 ms', speed: '26.3M ops/s', pct: 96, mem: '48 KB', color: '#25855A', icon: 'zap' },
      { id: 'ENG-WASM-02', name: 'WASM CEF ArcSight Engine', cat: 'WASM JIT', latency: '0.075 ms', speed: '13.3M ops/s', pct: 84, mem: '96 KB', color: '#25855A', icon: 'cpu' },
      { id: 'ENG-CPP-03', name: 'C++ Nginx/Apache Access', cat: 'NATIVE C++', latency: '0.045 ms', speed: '22.2M ops/s', pct: 92, mem: '64 KB', color: '#25855A', icon: 'terminal' },
      { id: 'ENG-WASM-04', name: 'WASM AWS CloudTrail JSON', cat: 'WASM SIMD', latency: '0.110 ms', speed: '9.1M ops/s', pct: 72, mem: '128 KB', color: '#25855A', icon: 'cloud' },
      { id: 'ENG-CPP-05', name: 'Windows EventLog FastXML', cat: 'NATIVE C++', latency: '0.088 ms', speed: '11.4M ops/s', pct: 80, mem: '112 KB', color: '#25855A', icon: 'server' },
      { id: 'ENG-WASM-06', name: 'WASM Suricata EVE Stream', cat: 'WASM JIT', latency: '0.062 ms', speed: '16.1M ops/s', pct: 88, mem: '80 KB', color: '#25855A', icon: 'shield-alert' },
      { id: 'ENG-AI-07', name: 'Dynamic AI Pattern Inferrer', cat: 'AI SYNTH', latency: '1.200 ms', speed: '833K ops/s', pct: 35, mem: '1.8 MB', color: '#B4233C', icon: 'sparkles' }
    ];

    container.innerHTML = `
      <div class="parser-bench-matrix">
        ${items.map(item => `
          <div class="parser-bench-card">
            <div class="d-flex justify-between align-center mb-1">
              <div class="d-flex align-center gap-2">
                <div class="parser-bench-emblem" style="color:${item.color};">
                  <i data-lucide="${item.icon}"></i>
                </div>
                <div>
                  <strong class="parser-bench-title">${item.name}</strong>
                  <span class="parser-bench-sub">${item.cat} &bull; Static Heap: ${item.mem}</span>
                </div>
              </div>
              <div style="text-align:right;">
                <span class="badge-pill ${item.color === '#B4233C' ? 'cherry' : 'green'}-pill" style="font-size:0.62rem;">${item.latency}</span>
              </div>
            </div>

            <div class="parser-bench-meter-row mt-2">
              <div class="d-flex justify-between align-center mb-1" style="font-size:0.64rem; font-family:var(--font-mono);">
                <span style="color:var(--text-muted);">SPEED VELOCITY</span>
                <strong style="color:${item.color};">${item.speed}</strong>
              </div>
              <div class="latency-bench-bar-track" style="height:7px; background:var(--border-card);">
                <div class="latency-bench-bar-fill" style="width: ${item.pct}%; background-color: ${item.color}; border-radius:4px; box-shadow: 0 0 8px ${item.color}44;"></div>
              </div>
            </div>

            <div class="d-flex justify-between align-center mt-2 pt-2" style="border-top:1px solid var(--border-subtle);">
              <span style="font-size:0.62rem; font-family:var(--font-mono); color:var(--text-muted);">${item.id}</span>
              <button class="btn-cream-action btn-sm" onclick="ParsersModule.testEngine('${item.id}')" style="font-size:0.64rem; padding:2px 8px; font-weight:700;">
                <i data-lucide="play"></i> Test in Sandbox
              </button>
            </div>
          </div>
        `).join('')}
      </div>
    `;

    if (window.lucide) lucide.createIcons();
  },

  // 4. Interactive Sandbox Testing
  runSandboxBenchmark() {
    const inputEl = document.getElementById('parser-sandbox-input');
    const selectEl = document.getElementById('parser-sandbox-engine-select');
    const outSpeedEl = document.getElementById('sandbox-speed-val');
    const outOpsEl = document.getElementById('sandbox-ops-val');
    const outTokensEl = document.getElementById('sandbox-tokens-wrap');
    const outJsonEl = document.getElementById('sandbox-ocsf-json');

    const rawText = inputEl ? inputEl.value : '';
    const engineId = selectEl ? selectEl.value : 'ENG-CPP-01';
    const engine = this.engines.find(e => e.id === engineId) || this.engines[0];

    // Simulate microsecond parse duration
    const simulatedMicros = engine.category === 'ai' ? (1150 + Math.floor(Math.random() * 80)) : (35 + Math.floor(Math.random() * 25));
    const speedMs = (simulatedMicros / 1000).toFixed(3);
    const opsSec = ((1000 / speedMs) * 1000).toLocaleString();

    if (outSpeedEl) outSpeedEl.innerText = `${speedMs} ms`;
    if (outOpsEl) outOpsEl.innerText = `${opsSec} logs/s`;

    // Dynamic Token Chip extraction
    if (outTokensEl) {
      if (rawText.includes('Failed password') || rawText.includes('sshd')) {
        outTokensEl.innerHTML = `
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: TIMESTAMP', 'info')"><i data-lucide="tag"></i> [TIMESTAMP] 2026-09-02T19:30:00.120Z</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: ACTOR', 'info')"><i data-lucide="user"></i> [ACTOR] admin</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: SRC_IP', 'info')"><i data-lucide="globe"></i> [SRC_IP] 192.168.1.105</span>
          <span class="parser-token-chip gold" onclick="Utils.showToast('Copied token: STATUS', 'info')"><i data-lucide="shield-alert"></i> [STATUS] Auth_Failure</span>
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: PORT', 'info')"><i data-lucide="layers"></i> [PORT] 52410 (SSH)</span>
        `;
      } else if (rawText.includes('CEF:0') || rawText.includes('PaloAlto')) {
        outTokensEl.innerHTML = `
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: DEVICE', 'info')"><i data-lucide="shield"></i> [DEVICE] PaloAltoNetworks PAN-OS</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: SRC_IP', 'info')"><i data-lucide="globe"></i> [SRC_IP] 185.220.101.5</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: DST_IP', 'info')"><i data-lucide="server"></i> [DST_IP] 10.0.0.15</span>
          <span class="parser-token-chip gold" onclick="Utils.showToast('Copied token: ACTION', 'info')"><i data-lucide="activity"></i> [ACTION] drop / deny</span>
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: PROTO', 'info')"><i data-lucide="terminal"></i> [PROTO] TCP:22</span>
        `;
      } else if (rawText.includes('CloudTrail') || rawText.includes('eventVersion')) {
        outTokensEl.innerHTML = `
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: CLOUD', 'info')"><i data-lucide="cloud"></i> [CLOUD] AWS CloudTrail 1.08</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: IAM_USER', 'info')"><i data-lucide="user"></i> [IAM_USER] alice</span>
          <span class="parser-token-chip gold" onclick="Utils.showToast('Copied token: EVENT', 'info')"><i data-lucide="key"></i> [EVENT] ConsoleLogin</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: IP', 'info')"><i data-lucide="globe"></i> [IP] 203.0.113.19</span>
        `;
      } else {
        outTokensEl.innerHTML = `
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: SYSTEM', 'info')"><i data-lucide="cpu"></i> [SYSTEM] SCADA_PLC_09</span>
          <span class="parser-token-chip gold" onclick="Utils.showToast('Copied token: EVENT', 'info')"><i data-lucide="alert-circle"></i> [EVENT] VALVE_FAIL</span>
          <span class="parser-token-chip green" onclick="Utils.showToast('Copied token: PRESSURE', 'info')"><i data-lucide="activity"></i> [PRESSURE] 84.2 PSI</span>
          <span class="parser-token-chip cherry" onclick="Utils.showToast('Copied token: SRC_IP', 'info')"><i data-lucide="globe"></i> [SRC_IP] 172.16.4.18</span>
        `;
      }
    }

    // Formatted OCSF JSON
    if (outJsonEl) {
      const ocsfObj = {
        class_uid: engine.ocsfClass.includes('3002') ? 3002 : (engine.ocsfClass.includes('4001') ? 4001 : 2001),
        class_name: engine.ocsfClass,
        severity_id: 4,
        severity: 'High',
        time: Date.now(),
        parser_engine_id: engine.id,
        parser_latency_ms: parseFloat(speedMs),
        metadata: {
          schema_version: '1.1.0',
          air_gapped_verified: true,
          zero_copy_buffer: true
        }
      };
      outJsonEl.innerText = JSON.stringify(ocsfObj, null, 2);
    }

    if (window.lucide) lucide.createIcons();
  },

  // 5. Filterable Engine Catalog Grid with Micro-Sparklines
  renderCatalog() {
    const grid = document.getElementById('parser-catalog-grid');
    if (!grid) return;

    let filtered = this.engines;
    if (this.currentCategory !== 'all') {
      filtered = filtered.filter(e => e.category === this.currentCategory);
    }
    if (this.searchQuery) {
      filtered = filtered.filter(e =>
        e.name.toLowerCase().includes(this.searchQuery) ||
        e.type.toLowerCase().includes(this.searchQuery) ||
        e.ocsfClass.toLowerCase().includes(this.searchQuery)
      );
    }

    grid.innerHTML = filtered.map(e => `
      <div class="parser-engine-card">
        <div>
          <div class="d-flex justify-between align-center mb-2">
            <span style="font-family:var(--font-mono); font-size:0.68rem; font-weight:800; color:var(--cherry-primary);">${e.id}</span>
            <span class="badge-pill ${e.statusClass}-pill" style="font-size:0.58rem;"><span class="pulse-dot"></span> ${e.status}</span>
          </div>

          <h4 style="font-family:var(--font-heading); font-size:0.88rem; font-weight:800; color:var(--text-ink); margin-bottom:4px;">
            ${e.icon} ${e.name}
          </h4>
          <span style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-muted); display:block; margin-bottom:12px;">
            ${e.type} • ${e.version}
          </span>

          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; font-family:var(--font-mono); font-size:0.68rem; margin-bottom:12px;">
            <div style="background:var(--bg-app); padding:6px 8px; border-radius:4px; border:1px solid var(--border-card);"><span style="color:var(--text-muted); font-size:0.60rem; display:block; text-transform:uppercase; font-weight:700;">SPEED</span> <strong style="color:var(--status-green); font-size:0.75rem;">${e.throughput}</strong></div>
            <div style="background:var(--bg-app); padding:6px 8px; border-radius:4px; border:1px solid var(--border-card);"><span style="color:var(--text-muted); font-size:0.60rem; display:block; text-transform:uppercase; font-weight:700;">LATENCY</span> <strong style="color:var(--cherry-primary); font-size:0.75rem;">${e.latency}</strong></div>
            <div style="background:var(--bg-app); padding:6px 8px; border-radius:4px; border:1px solid var(--border-card);"><span style="color:var(--text-muted); font-size:0.60rem; display:block; text-transform:uppercase; font-weight:700;">MEMORY</span> <strong style="color:var(--text-ink); font-size:0.75rem;">${e.memory}</strong></div>
            <div style="background:var(--bg-app); padding:6px 8px; border-radius:4px; border:1px solid var(--border-card);"><span style="color:var(--text-muted); font-size:0.60rem; display:block; text-transform:uppercase; font-weight:700;">OCSF</span> <strong style="color:var(--text-ink); font-size:0.75rem;">${e.ocsfClass.split(':')[0]}</strong></div>
          </div>
        </div>

        <div class="d-flex justify-between align-center pt-2" style="border-top:1px solid var(--border-subtle);">
          <span style="font-size:0.65rem; font-family:var(--font-mono); color:var(--text-muted);">${e.compliance}</span>
          <button class="btn-cream-action btn-sm" onclick="ParsersModule.testEngine('${e.id}')" style="font-size:0.68rem; padding:4px 10px; font-weight:700;">
            <i data-lucide="play"></i> Test Engine
          </button>
        </div>
      </div>
    `).join('');

    if (window.lucide) lucide.createIcons();
  },

  testEngine(engineId) {
    const found = this.engines.find(e => e.id === engineId);
    if (!found) return;

    const textarea = document.getElementById('parser-sandbox-input');
    if (textarea) textarea.value = found.sample;
    const select = document.getElementById('parser-sandbox-engine-select');
    if (select) select.value = found.id;

    this.triggerLaserScan();
    this.runSandboxBenchmark();
    Utils.showToast(`Loaded ${found.name} into Laboratory Sandbox`, 'info');
  },

  drawBox(ctx, x, y, width, height, radius = 4) {
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

window.ParsersModule = ParsersModule;
