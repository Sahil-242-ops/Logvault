/**
 * LOGVAULT — Canvas Charts Module (Spline, Donut, Sparklines)
 * Styled with the Warm Cream & Cherry Editorial Palette
 * High-DPI Crisp Vector Graphics
 */

const Charts = {
  renderDashboardSpline() {
    const canvas = document.getElementById('dashboardSplineCanvas');
    if (!canvas) return;
    
    const scaled = Utils.setupHiDPICanvas(canvas, 220);
    if (!scaled) return;
    const { ctx, width: displayW, height: displayH } = scaled;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    ctx.clearRect(0, 0, displayW, displayH);

    // Grid lines & labels
    const yLabels = ['2.4M', '1.8M', '1.2M', '600K', '0'];
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = isDark ? '#A89094' : '#756568';

    const topPad = 20;
    const bottomPad = 28;
    const leftPad = 48;
    const rightPad = 20;
    const chartHeight = displayH - topPad - bottomPad;
    const chartWidth = displayW - leftPad - rightPad;

    for (let i = 0; i < 5; i++) {
      const y = topPad + (i * (chartHeight / 4));
      ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.12)' : 'rgba(117, 101, 104, 0.15)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(leftPad, y);
      ctx.lineTo(displayW - rightPad, y);
      ctx.stroke();
      ctx.fillText(yLabels[i], 8, y + 3);
    }

    // Spline Points (Ingested: Cherry, Normalized: Rose/Dark Cherry)
    const rawPoints = [
      { x: 0.05, y: 0.78 },
      { x: 0.20, y: 0.65 },
      { x: 0.35, y: 0.48 },
      { x: 0.50, y: 0.22 },
      { x: 0.65, y: 0.38 },
      { x: 0.80, y: 0.14 },
      { x: 0.95, y: 0.28 }
    ];

    const points = rawPoints.map(p => ({
      x: leftPad + p.x * chartWidth,
      y: topPad + p.y * chartHeight
    }));

    // Draw Ingested Area Gradient
    const areaGrad = ctx.createLinearGradient(0, topPad, 0, displayH - bottomPad);
    areaGrad.addColorStop(0, isDark ? 'rgba(212, 56, 83, 0.40)' : 'rgba(180, 35, 60, 0.28)');
    areaGrad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const xc = (points[i].x + points[i + 1].x) / 2;
      const yc = (points[i].y + points[i + 1].y) / 2;
      ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.lineTo(points[points.length - 1].x, displayH - bottomPad);
    ctx.lineTo(points[0].x, displayH - bottomPad);
    ctx.closePath();
    ctx.fillStyle = areaGrad;
    ctx.fill();

    // Draw Spline Line (Primary Cherry)
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const xc = (points[i].x + points[i + 1].x) / 2;
      const yc = (points[i].y + points[i + 1].y) / 2;
      ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
    ctx.strokeStyle = isDark ? '#D43853' : '#B4233C';
    ctx.lineWidth = 2.8;
    ctx.stroke();

    // Draw Spline Dots
    points.forEach((p, idx) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = isDark ? '#FFF8F0' : '#FFF8F0';
      ctx.fill();
      ctx.strokeStyle = isDark ? '#D43853' : '#B4233C';
      ctx.lineWidth = 2.5;
      ctx.stroke();

      // Tooltip pulse on peak point
      if (idx === 5) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 8, 0, Math.PI * 2);
        ctx.strokeStyle = isDark ? 'rgba(212, 56, 83, 0.5)' : 'rgba(180, 35, 60, 0.4)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    });

    // Normalized Line (Subtle Secondary Spline)
    const normPoints = [
      { x: 0.05, y: 0.85 },
      { x: 0.20, y: 0.72 },
      { x: 0.35, y: 0.55 },
      { x: 0.50, y: 0.32 },
      { x: 0.65, y: 0.44 },
      { x: 0.80, y: 0.22 },
      { x: 0.95, y: 0.35 }
    ].map(p => ({
      x: leftPad + p.x * chartWidth,
      y: topPad + p.y * chartHeight
    }));

    ctx.beginPath();
    ctx.moveTo(normPoints[0].x, normPoints[0].y);
    for (let i = 0; i < normPoints.length - 1; i++) {
      const xc = (normPoints[i].x + normPoints[i + 1].x) / 2;
      const yc = (normPoints[i].y + normPoints[i + 1].y) / 2;
      ctx.quadraticCurveTo(normPoints[i].x, normPoints[i].y, xc, yc);
    }
    ctx.lineTo(normPoints[normPoints.length - 1].x, normPoints[normPoints.length - 1].y);
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.65)' : 'rgba(116, 21, 42, 0.55)';
    ctx.lineWidth = 1.8;
    ctx.setLineDash([4, 4]);
    ctx.stroke();
    ctx.setLineDash([]);
  },

  renderSparklines() {
    ['sparkline1', 'sparkline2', 'sparkline3'].forEach((id, idx) => {
      const canvas = document.getElementById(id);
      if (!canvas) return;

      const scaled = Utils.setupHiDPICanvas(canvas, 36);
      if (!scaled) return;
      const { ctx, width: w, height: h } = scaled;

      ctx.clearRect(0, 0, w, h);

      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, 'rgba(180, 35, 60, 0.25)');
      grad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');

      ctx.beginPath();
      ctx.moveTo(0, h * 0.75);
      if (idx === 0) {
        ctx.bezierCurveTo(w * 0.25, h * 0.3, w * 0.6, h * 0.8, w, h * 0.2);
      } else if (idx === 1) {
        ctx.bezierCurveTo(w * 0.3, h * 0.6, w * 0.7, h * 0.2, w, h * 0.15);
      } else {
        ctx.bezierCurveTo(w * 0.4, h * 0.8, w * 0.7, h * 0.4, w, h * 0.3);
      }
      ctx.lineTo(w, h);
      ctx.lineTo(0, h);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.beginPath();
      ctx.moveTo(0, h * 0.75);
      if (idx === 0) {
        ctx.bezierCurveTo(w * 0.25, h * 0.3, w * 0.6, h * 0.8, w, h * 0.2);
      } else if (idx === 1) {
        ctx.bezierCurveTo(w * 0.3, h * 0.6, w * 0.7, h * 0.2, w, h * 0.15);
      } else {
        ctx.bezierCurveTo(w * 0.4, h * 0.8, w * 0.7, h * 0.4, w, h * 0.3);
      }
      ctx.strokeStyle = '#B4233C';
      ctx.lineWidth = 1.8;
      ctx.stroke();
    });

    // Histogram bars on 4th KPI card (Critical Anomalies)
    const chCanvas = document.getElementById('criticalHistCanvas');
    if (chCanvas) {
      const scaled = Utils.setupHiDPICanvas(chCanvas, 36);
      if (!scaled) return;
      const { ctx, width: displayW } = scaled;

      ctx.clearRect(0, 0, displayW, 36);

      const bars = [6, 12, 18, 9, 15, 24, 10, 26, 14, 22, 28, 19, 14, 27, 21, 17, 24, 29];
      const barSpacing = displayW / bars.length;
      const barWidth = Math.max(3, barSpacing - 4);

      bars.forEach((b, i) => {
        ctx.fillStyle = 'rgba(198, 40, 61, 0.75)';
        ctx.fillRect(Math.round(i * barSpacing + 2), 36 - b, Math.round(barWidth), b);
      });
    }
  },

  renderEventDistributionDonut() {
    const canvas = document.getElementById('eventDonutCanvas');
    if (!canvas) return;

    const scaled = Utils.setupHiDPICanvas(canvas, 150);
    if (!scaled) return;
    const { ctx, width, height } = scaled;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

    const size = Math.min(width, height);
    ctx.clearRect(0, 0, width, height);

    const cx = width / 2;
    const cy = height / 2;
    const outerR = size * 0.44;
    const innerR = size * 0.28;

    const segments = [
      { label: 'Firewall', pct: 0.25, color: isDark ? '#D43853' : '#B4233C' },
      { label: 'OKTA Auth', pct: 0.31, color: isDark ? '#9C1A30' : '#74152A' },
      { label: 'Suspicious', pct: 0.24, color: isDark ? '#DD6B20' : '#C47A16' },
      { label: 'Endpoints', pct: 0.13, color: isDark ? '#8A787B' : '#756568' },
      { label: 'Cloud Audit', pct: 0.07, color: isDark ? '#E8A0AA' : '#E8A0AA' }
    ];

    let currentAngle = -Math.PI / 2;
    const gap = 0.045;

    segments.forEach(seg => {
      const sliceAngle = seg.pct * (Math.PI * 2);
      const startAngle = currentAngle + gap / 2;
      const endAngle = currentAngle + sliceAngle - gap / 2;

      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, endAngle, false);
      ctx.arc(cx, cy, innerR, endAngle, startAngle, true);
      ctx.closePath();

      ctx.fillStyle = seg.color;
      ctx.fill();

      currentAngle += sliceAngle;
    });
  }
};

window.Charts = Charts;
