/**
 * LOGVAULT — Dashboard canvas charts (activity spline, KPI sparklines, format donut).
 * All charts draw the data from /api/dashboard (Charts.data); with no data they show an empty state.
 */

const FORMAT_COLORS = ['#8F1127', '#4A0B18', '#924C00', '#6E1B3E', '#3D3537', '#B4233C', '#C47A16', '#756568'];
const FORMAT_LABELS = {
  syslog: 'Syslog', cef: 'ArcSight CEF', apache: 'Apache / Nginx', json: 'JSON / CloudTrail',
  windows: 'Windows Security', generic_kv: 'Key=Value', unknown: 'Unparsed'
};

const Charts = {
  data: null,

  formatLabel(fmt) {
    if (fmt && fmt.startsWith('custom:')) return `Rule: ${fmt.slice(7)}`;
    return FORMAT_LABELS[fmt] || fmt;
  },

  compact(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'K';
    return String(Math.round(n));
  },

  bucketLabel(iso, seconds) {
    const d = new Date(iso);
    if (seconds >= 86400) return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
  },

  drawEmpty(ctx, w, h, text) {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    ctx.fillStyle = isDark ? '#A89094' : '#756568';
    ctx.font = '12px "Inter", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(text, w / 2, h / 2);
    ctx.textAlign = 'left';
  },

  // Smooth curve through every point (Catmull-Rom). Control points are clamped between the two
  // neighbouring values so the line never overshoots, e.g. never dips below zero.
  smoothPath(ctx, points) {
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i - 1] || points[i];
      const p1 = points[i];
      const p2 = points[i + 1];
      const p3 = points[i + 2] || p2;
      const lo = Math.min(p1.y, p2.y), hi = Math.max(p1.y, p2.y);
      const clamp = v => Math.min(hi, Math.max(lo, v));
      ctx.bezierCurveTo(
        p1.x + (p2.x - p0.x) / 6, clamp(p1.y + (p2.y - p0.y) / 6),
        p2.x - (p3.x - p1.x) / 6, clamp(p2.y - (p3.y - p1.y) / 6),
        p2.x, p2.y);
    }
  },

  renderDashboardSpline() {
    const canvas = document.getElementById('dashboardSplineCanvas');
    if (!canvas) return;
    const scaled = Utils.setupHiDPICanvas(canvas, 220);
    if (!scaled) return;
    const { ctx, width: displayW, height: displayH } = scaled;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    ctx.clearRect(0, 0, displayW, displayH);

    const tl = this.data && this.data.timeline;
    const buckets = tl ? tl.buckets : [];
    if (!buckets.length || !buckets.some(b => b.events)) {
      this.drawEmpty(ctx, displayW, displayH, 'No events yet. Upload logs in the Normalizer to see activity.');
      return;
    }

    const topPad = 20, bottomPad = 28, leftPad = 48, rightPad = 20;
    const chartHeight = displayH - topPad - bottomPad;
    const chartWidth = displayW - leftPad - rightPad;
    const max = Math.max(...buckets.map(b => b.events), 1);
    const niceMax = Math.ceil(max / 4) * 4 || 4;

    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = isDark ? '#A89094' : '#756568';
    for (let i = 0; i < 5; i++) {
      const y = topPad + (i * (chartHeight / 4));
      ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.12)' : 'rgba(117, 101, 104, 0.15)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(leftPad, y);
      ctx.lineTo(displayW - rightPad, y);
      ctx.stroke();
      ctx.fillText(this.compact(niceMax * (4 - i) / 4), 8, y + 3);
    }

    const toPoint = (v, i) => ({
      x: leftPad + (buckets.length === 1 ? 0.5 : i / (buckets.length - 1)) * chartWidth,
      y: topPad + (1 - v / niceMax) * chartHeight
    });
    const points = buckets.map((b, i) => toPoint(b.events, i));
    const anomalyPoints = buckets.map((b, i) => toPoint(b.anomalies, i));

    // X-axis labels: first, middle, last bucket
    const labelIdx = [...new Set([0, Math.floor((buckets.length - 1) / 2), buckets.length - 1])];
    labelIdx.forEach(i => {
      const label = this.bucketLabel(buckets[i].start, tl.bucket_seconds);
      const w = ctx.measureText(label).width;
      const x = Math.min(Math.max(points[i].x - w / 2, leftPad), displayW - rightPad - w);
      ctx.fillText(label, x, displayH - 8);
    });

    // Events area + line
    const areaGrad = ctx.createLinearGradient(0, topPad, 0, displayH - bottomPad);
    areaGrad.addColorStop(0, isDark ? 'rgba(212, 56, 83, 0.40)' : 'rgba(180, 35, 60, 0.28)');
    areaGrad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');
    ctx.beginPath();
    this.smoothPath(ctx, points);
    ctx.lineTo(points[points.length - 1].x, displayH - bottomPad);
    ctx.lineTo(points[0].x, displayH - bottomPad);
    ctx.closePath();
    ctx.fillStyle = areaGrad;
    ctx.fill();

    ctx.beginPath();
    this.smoothPath(ctx, points);
    ctx.strokeStyle = isDark ? '#D43853' : '#B4233C';
    ctx.lineWidth = 2.8;
    ctx.stroke();

    // Anomalies (dashed)
    ctx.beginPath();
    this.smoothPath(ctx, anomalyPoints);
    ctx.strokeStyle = isDark ? 'rgba(232, 160, 170, 0.75)' : 'rgba(116, 21, 42, 0.65)';
    ctx.lineWidth = 1.8;
    ctx.setLineDash([4, 4]);
    ctx.stroke();
    ctx.setLineDash([]);

    // Mark the busiest bucket
    const peak = points[buckets.findIndex(b => b.events === max)];
    ctx.beginPath();
    ctx.arc(peak.x, peak.y, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = '#FFF8F0';
    ctx.fill();
    ctx.strokeStyle = isDark ? '#D43853' : '#B4233C';
    ctx.lineWidth = 2.5;
    ctx.stroke();
  },

  // Per-KPI trend over the same time buckets: events, parsed, anomalies
  renderSparklines() {
    const buckets = (this.data && this.data.timeline && this.data.timeline.buckets) || [];
    const series = [
      buckets.map(b => b.events),
      buckets.map(b => b.parsed),
      buckets.map(b => b.anomalies)
    ];

    ['sparkline1', 'sparkline2', 'sparkline3'].forEach((id, idx) => {
      const canvas = document.getElementById(id);
      if (!canvas) return;
      const scaled = Utils.setupHiDPICanvas(canvas, 36);
      if (!scaled) return;
      const { ctx, width: w, height: h } = scaled;
      ctx.clearRect(0, 0, w, h);

      const values = series[idx];
      const max = Math.max(...values, 0);
      if (!values.length || max === 0) {
        ctx.strokeStyle = 'rgba(180, 35, 60, 0.35)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(0, h - 2);
        ctx.lineTo(w, h - 2);
        ctx.stroke();
        return;
      }
      const pts = values.map((v, i) => ({
        x: values.length === 1 ? w / 2 : (i / (values.length - 1)) * w,
        y: h - 3 - (v / max) * (h - 8)
      }));

      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, 'rgba(180, 35, 60, 0.25)');
      grad.addColorStop(1, 'rgba(180, 35, 60, 0.0)');
      ctx.beginPath();
      this.smoothPath(ctx, pts);
      ctx.lineTo(pts[pts.length - 1].x, h);
      ctx.lineTo(pts[0].x, h);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.beginPath();
      this.smoothPath(ctx, pts);
      ctx.strokeStyle = '#B4233C';
      ctx.lineWidth = 1.8;
      ctx.stroke();
    });

    // Critical-anomaly KPI: anomalies per bucket as bars
    const chCanvas = document.getElementById('criticalHistCanvas');
    if (chCanvas) {
      const scaled = Utils.setupHiDPICanvas(chCanvas, 36);
      if (!scaled) return;
      const { ctx, width: displayW } = scaled;
      ctx.clearRect(0, 0, displayW, 36);
      const bars = buckets.map(b => b.anomalies);
      const max = Math.max(...bars, 0);
      if (!bars.length) return;
      const barSpacing = displayW / bars.length;
      const barWidth = Math.max(3, barSpacing - 4);
      bars.forEach((b, i) => {
        const hgt = max ? Math.max(b ? 3 : 1, (b / max) * 32) : 1;
        ctx.fillStyle = b ? 'rgba(198, 40, 61, 0.75)' : 'rgba(198, 40, 61, 0.2)';
        ctx.fillRect(Math.round(i * barSpacing + 2), 36 - hgt, Math.round(barWidth), hgt);
      });
    }
  },

  formatSegments() {
    const formats = (this.data && this.data.formats) || [];
    const top = formats.slice(0, 5);
    const rest = formats.slice(5);
    const segments = top.map((f, i) => ({ key: f.format, label: this.formatLabel(f.format), count: f.count, pct: f.pct, color: FORMAT_COLORS[i] }));
    if (rest.length) {
      const count = rest.reduce((a, f) => a + f.count, 0);
      const pct = rest.reduce((a, f) => a + f.pct, 0);
      segments.push({ key: 'other', label: `Other (${rest.length})`, count, pct, color: FORMAT_COLORS[7] });
    }
    return segments;
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

    const cx = width / 2, cy = height / 2;
    const outerR = size * 0.44, innerR = size * 0.28;
    const segments = this.formatSegments();

    if (!segments.length) {
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
      ctx.arc(cx, cy, innerR, Math.PI * 2, 0, true);
      ctx.fillStyle = isDark ? 'rgba(232, 160, 170, 0.12)' : 'rgba(117, 101, 104, 0.15)';
      ctx.fill();
      return;
    }

    const total = segments.reduce((a, s) => a + s.count, 0);
    let currentAngle = -Math.PI / 2;
    const gap = segments.length > 1 ? 0.045 : 0;
    segments.forEach(seg => {
      const sliceAngle = (seg.count / total) * (Math.PI * 2);
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
  },

  renderAll() {
    this.renderDashboardSpline();
    this.renderSparklines();
    this.renderEventDistributionDonut();
  }
};

window.Charts = Charts;
