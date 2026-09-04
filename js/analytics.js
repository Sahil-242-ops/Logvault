/**
 * LOGVAULT — Event Analytics & Geographic Threat Radar Module
 * Stage 2: Impossible Travel Vectors, 24h Ingestion Heatmap & ASN Telemetry
 */

const AnalyticsModule = {
  init() {
    this.renderHeatmapMatrix();
    this.bindEvents();
  },

  onScreenOpen() {
    this.renderHeatmapMatrix();
  },

  bindEvents() {
    const refreshBtn = document.getElementById('btn-refresh-asn-feed');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        Utils.showToast('ASN threat reputation feed updated (42,190 indicators).', 'success');
      });
    }
  },

  renderHeatmapMatrix() {
    const container = document.getElementById('analytics-heatmap-grid');
    if (!container) return;

    let html = '';
    for (let hour = 0; hour < 24; hour++) {
      for (let segment = 0; segment < 4; segment++) {
        const intensity = Math.random();
        let bg = 'rgba(180, 35, 60, 0.12)';
        if (intensity > 0.4) bg = 'rgba(180, 35, 60, 0.35)';
        if (intensity > 0.7) bg = 'rgba(198, 40, 61, 0.72)';
        if (intensity > 0.9) bg = '#B4233C';

        const eps = (1.2 + intensity * 17.2).toFixed(1);
        const timeSlot = `${String(hour).padStart(2, '0')}:${String(segment * 15).padStart(2, '0')}`;

        html += `
          <div class="heat-tile" style="background-color: ${bg};" title="Time: ${timeSlot} | Rate: ${eps}k EPS" onclick="Utils.showToast('Time: ${timeSlot} &bull; Throughput: ${eps}k EPS')"></div>
        `;
      }
    }
    container.innerHTML = html;
  }
};

window.AnalyticsModule = AnalyticsModule;
