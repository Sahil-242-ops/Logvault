/**
 * LOGVAULT — Event Analytics & Geographic Threat Radar Module
 * Real data only: offline GeoIP threat-origin map, time-of-day heatmap and top sources.
 * The world outline comes from js/world-map-data.js (bundled, no network access).
 */

const AnalyticsModule = {
  geo: null,
  heatmap: null,
  _countryRings: null,

  init() {
    this.renderCountries();
    this.bindEvents();
    this.refresh();
  },

  onScreenOpen() {
    this.refresh();
  },

  bindEvents() {
    const refreshBtn = document.getElementById('btn-refresh-analytics');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        await this.refresh();
        Utils.showToast('Analytics refreshed from local event store.', 'success');
      });
    }
  },

  async refresh() {
    if (!window.LogVaultAPI) return;
    const [geo, heatmap] = await Promise.all([LogVaultAPI.getGeoAnalytics(), LogVaultAPI.getHeatmap()]);
    this.geo = geo;
    this.heatmap = heatmap;
    this.renderGeoMap();
    this.renderGeoStats();
    this.renderTopSources();
    this.renderHeatmapMatrix();
    if (window.lucide) lucide.createIcons();
  },

  // Must match scripts/build_world_map.py (equirectangular, Antarctica cropped)
  project(lat, lon) {
    const m = window.WORLD_MAP || { width: 1000, height: 440, latTop: 84, latBottom: -58 };
    const x = (lon + 180) / 360 * m.width;
    const y = (m.latTop - lat) / (m.latTop - m.latBottom) * m.height;
    return [x, Math.max(0, Math.min(m.height, y))];
  },

  renderCountries() {
    const layer = document.getElementById('geo-countries-layer');
    if (!layer || !window.WORLD_MAP) return;
    layer.innerHTML = WORLD_MAP.countries
      .map((c, i) => `<path class="geo-country" data-country-idx="${i}" d="${c.d}"><title>${Utils.escapeHtml(c.n)}</title></path>`)
      .join('');
  },

  // Parse "M x y L x y ... Z" rings once for point-in-country tests
  getCountryRings() {
    if (this._countryRings || !window.WORLD_MAP) return this._countryRings || [];
    this._countryRings = WORLD_MAP.countries.map(c =>
      c.d.split('Z').filter(Boolean).map(ring =>
        ring.replace('M', '').split('L').map(pt => pt.trim().split(' ').map(Number))
      )
    );
    return this._countryRings;
  },

  countryIndexAt(x, y) {
    const all = this.getCountryRings();
    for (let ci = 0; ci < all.length; ci++) {
      let inside = false;
      for (const ring of all[ci]) {
        for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
          const [xi, yi] = ring[i];
          const [xj, yj] = ring[j];
          if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) inside = !inside;
        }
      }
      if (inside) return ci;
    }
    return -1;
  },

  renderGeoMap() {
    const layer = document.getElementById('geo-points-layer');
    const empty = document.getElementById('geo-empty-state');
    const title = document.getElementById('geo-map-title');
    if (!layer) return;

    document.querySelectorAll('.geo-country.has-anomaly').forEach(el => el.classList.remove('has-anomaly'));
    layer.innerHTML = '';

    const geo = this.geo;
    if (!geo) {
      this.showMapMessage('Backend offline. Start the FastAPI server to load threat origins.');
      if (title) title.innerText = 'Threat Origins';
      return;
    }

    // Group IPs at the same location (many IPs can share one city)
    const groups = new Map();
    geo.points.forEach(p => {
      const key = `${p.lat.toFixed(1)},${p.lon.toFixed(1)}`;
      const g = groups.get(key) || { lat: p.lat, lon: p.lon, city: p.city, country: p.country, ips: [], events: 0, anomalies: 0, max_threat: 0 };
      g.ips.push(p);
      g.events += p.events;
      g.anomalies += p.anomalies;
      g.max_threat = Math.max(g.max_threat, p.max_threat || 0);
      groups.set(key, g);
    });

    const sorted = [...groups.values()].sort((a, b) => b.anomalies - a.anomalies || b.events - a.events);
    const highlighted = new Set();
    const labelled = [];
    const labelFor = new Set();
    sorted.forEach((g, rank) => {
      if (g.anomalies === 0 || rank > 4 || labelled.length >= 3) return;
      const [x, y] = this.project(g.lat, g.lon);
      if (labelled.every(([lx, ly]) => Math.hypot(lx - x, ly - y) > 60)) {
        labelled.push([x, y]);
        labelFor.add(g);
      }
    });
    const svgNs = 'http://www.w3.org/2000/svg';

    // Draw clean points first so anomalous ones sit on top
    [...sorted].reverse().forEach((g, revIdx) => {
      const rank = sorted.length - 1 - revIdx;
      const [x, y] = this.project(g.lat, g.lon);
      const anomalous = g.anomalies > 0;
      const r = Math.min(16, 4 + 2.2 * Math.log2(1 + g.events));

      if (anomalous) {
        const ci = this.countryIndexAt(x, y);
        if (ci >= 0) highlighted.add(ci);
      }

      const grp = document.createElementNS(svgNs, 'g');
      grp.setAttribute('class', `geo-point ${anomalous ? 'anomalous' : 'clean'}`);
      grp.setAttribute('transform', `translate(${x.toFixed(1)}, ${y.toFixed(1)})`);
      grp.setAttribute('tabindex', '0');
      grp.innerHTML = `
        ${anomalous && rank < 5 ? `<circle r="${(r * 2.2).toFixed(1)}" fill="url(#cherryMapGlow)" class="beacon-pulse"></circle>` : ''}
        <circle r="${r.toFixed(1)}" class="geo-point-core"></circle>
        ${labelFor.has(g) ? `<text x="${(r + 5).toFixed(1)}" y="4" class="geo-point-label">${Utils.escapeHtml(g.city || g.country || '')}</text>` : ''}
      `;
      grp.addEventListener('mouseenter', (e) => this.showTooltip(e, g));
      grp.addEventListener('mousemove', (e) => this.moveTooltip(e));
      grp.addEventListener('mouseleave', () => this.hideTooltip());
      grp.addEventListener('focus', (e) => this.showTooltip(e, g));
      grp.addEventListener('blur', () => this.hideTooltip());
      grp.addEventListener('click', () => this.focusSource(g.ips.sort((a, b) => b.anomalies - a.anomalies)[0].ip));
      layer.appendChild(grp);
    });

    highlighted.forEach(ci => {
      const el = document.querySelector(`.geo-country[data-country-idx="${ci}"]`);
      if (el) el.classList.add('has-anomaly');
    });

    const anomalousCountries = geo.countries.filter(c => c.anomalies > 0).length;
    if (title) {
      title.innerText = geo.points.length
        ? `Threat Origins: ${geo.points.filter(p => p.anomalies > 0).length} anomalous external sources in ${anomalousCountries} ${anomalousCountries === 1 ? 'country' : 'countries'}`
        : 'Threat Origins';
    }

    if (!geo.total_sources) {
      this.showMapMessage('No events with source IPs yet. Upload or ingest logs to populate the map.');
    } else if (!geo.points.length) {
      this.showMapMessage(geo.geoip_available
        ? 'All sources in this session are internal (private) addresses. See the Internal network count above.'
        : 'GeoIP database not installed, so external IPs cannot be placed. Run scripts/download_geoip.py.');
    } else if (empty) {
      empty.hidden = true;
    }
  },

  showMapMessage(msg) {
    const empty = document.getElementById('geo-empty-state');
    if (!empty) return;
    empty.textContent = msg;
    empty.hidden = false;
  },

  showTooltip(e, g) {
    const tip = document.getElementById('geo-tooltip');
    if (!tip) return;
    const ipRows = g.ips.slice(0, 5).map(p =>
      `<div class="geo-tip-row"><code>${Utils.escapeHtml(p.ip)}</code><span>${p.anomalies} anom / ${p.events} evt</span></div>`
    ).join('');
    tip.innerHTML = `
      <div class="geo-tip-title">${Utils.escapeHtml([g.city, g.country].filter(Boolean).join(', ') || 'Unknown')}</div>
      <div class="geo-tip-meta">${g.anomalies} anomalies &bull; ${g.events} events &bull; max threat ${g.max_threat}</div>
      ${ipRows}
      ${g.ips.length > 5 ? `<div class="geo-tip-meta">+${g.ips.length - 5} more IPs</div>` : ''}
      <div class="geo-tip-hint">Click to open in Alert Center</div>
    `;
    tip.hidden = false;
    this.moveTooltip(e);
  },

  moveTooltip(e) {
    const tip = document.getElementById('geo-tooltip');
    const box = document.getElementById('geo-map-box');
    if (!tip || !box || tip.hidden) return;
    const rect = box.getBoundingClientRect();
    const src = e.clientX !== undefined && e.clientX !== 0 ? e : null;
    const target = e.currentTarget && e.currentTarget.getBoundingClientRect ? e.currentTarget.getBoundingClientRect() : null;
    let x = src ? src.clientX - rect.left : (target ? target.left - rect.left : 0);
    let y = src ? src.clientY - rect.top : (target ? target.top - rect.top : 0);
    x = Math.min(x + 14, rect.width - tip.offsetWidth - 8);
    y = Math.min(y + 14, rect.height - tip.offsetHeight - 8);
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  },

  hideTooltip() {
    const tip = document.getElementById('geo-tooltip');
    if (tip) tip.hidden = true;
  },

  focusSource(ip) {
    if (window.AnomalyModule && AnomalyModule.focusSource) {
      Navigation.navigateTo('alerts');
      AnomalyModule.focusSource(ip);
    }
  },

  renderGeoStats() {
    const row = document.getElementById('geo-stat-row');
    const badge = document.getElementById('geo-db-badge');
    const badgeText = document.getElementById('geo-db-badge-text');
    const geo = this.geo;

    if (badge && badgeText) {
      const ok = geo && geo.geoip_available;
      badge.className = `header-status-badge ${ok ? 'green' : 'amber'}`;
      badgeText.innerText = !geo ? 'Backend offline' : (ok ? `Offline GeoIP: ${geo.geoip_database}` : 'GeoIP database missing');
      badge.title = ok
        ? 'IP geolocation runs locally from the bundled database. No network lookups. IP geolocation by DB-IP (db-ip.com), CC BY 4.0.'
        : 'Run scripts/download_geoip.py on a connected machine and copy geoip/ to this host.';
    }
    if (!row) return;
    if (!geo) { row.innerHTML = ''; return; }

    const external = geo.points.length;
    const extAnom = geo.points.reduce((s, p) => s + p.anomalies, 0);
    const tiles = [
      { label: 'External sources', val: external, sub: `${extAnom} anomalies` },
      { label: 'Countries', val: geo.countries.length, sub: `${geo.countries.filter(c => c.anomalies > 0).length} with anomalies` },
      { label: 'Internal network', val: geo.internal.ips, sub: `${geo.internal.anomalies} anomalies` },
      { label: 'Unlocated', val: geo.unresolved.ips, sub: `${geo.unresolved.anomalies} anomalies` }
    ];
    row.innerHTML = tiles.map(t => `
      <div class="norm-stat-tile">
        <span class="norm-stat-label">${t.label}</span>
        <span class="norm-stat-val">${t.val}</span>
        <span class="geo-stat-sub">${t.sub}</span>
      </div>`).join('');
  },

  renderTopSources() {
    const list = document.getElementById('top-sources-list');
    if (!list) return;
    const geo = this.geo;
    if (!geo) {
      list.innerHTML = '<div class="analytics-empty">Backend offline.</div>';
      return;
    }
    if (!geo.top_sources.length) {
      list.innerHTML = '<div class="analytics-empty">No sources yet. Ingest logs to rank threat sources.</div>';
      return;
    }
    const maxVal = Math.max(1, ...geo.top_sources.map(s => s.anomalies || 0));
    list.innerHTML = geo.top_sources.map(s => {
      const icon = s.scope === 'internal'
        ? '<i data-lucide="building-2" class="src-scope-icon"></i>'
        : (s.country_code ? `<span class="cc-chip">${Utils.escapeHtml(s.country_code)}</span>` : '<i data-lucide="globe" class="src-scope-icon"></i>');
      const pct = Math.round((s.anomalies / maxVal) * 100);
      return `
        <div class="asn-item-row" role="button" tabindex="0" title="Open ${Utils.escapeHtml(s.ip)} in Alert Center"
          onclick="AnalyticsModule.focusSource('${Utils.escapeHtml(s.ip)}')"
          onkeydown="if(event.key==='Enter')AnalyticsModule.focusSource('${Utils.escapeHtml(s.ip)}')">
          <div class="asn-src">
            <span class="asn-flag">${icon}</span>
            <div>
              <strong>${Utils.escapeHtml(s.ip)}</strong>
              <small>${Utils.escapeHtml(s.location)}</small>
            </div>
          </div>
          <div class="asn-metric">
            <div class="asn-bar-wrap"><div class="asn-bar-fill" style="width:${pct}%"></div></div>
            <strong class="${s.anomalies ? 'asn-hot' : ''}">${s.anomalies} anom</strong>
            <small>${s.events} evt &bull; max ${s.max_threat}</small>
          </div>
        </div>`;
    }).join('');
  },

  renderHeatmapMatrix() {
    const container = document.getElementById('analytics-heatmap-grid');
    if (!container) return;
    const hm = this.heatmap;
    const peakLabel = document.getElementById('heatmap-peak-label');
    const subtitle = document.getElementById('heatmap-subtitle');

    const slots = hm ? hm.slots : Array.from({ length: 96 }, () => ({ total: 0, anomalies: 0 }));
    const peak = hm ? hm.peak : 0;
    if (peakLabel) peakLabel.innerText = `Peak: ${peak} events`;
    if (subtitle) {
      subtitle.innerText = !hm ? 'Backend offline'
        : `${hm.total} events per 15-minute slot, by the log's own timestamp`;
    }

    container.innerHTML = slots.map((s, i) => {
      const hh = String(Math.floor(i / 4)).padStart(2, '0');
      const mm = String((i % 4) * 15).padStart(2, '0');
      const level = s.total === 0 ? 0 : Math.max(0.15, s.total / Math.max(1, peak));
      const label = `${hh}:${mm} - ${s.total} events, ${s.anomalies} anomalous`;
      return `<div class="heat-tile${s.anomalies ? ' has-anom' : ''}" style="--heat:${level.toFixed(3)}" title="${hh}:${mm}: ${s.total} events, ${s.anomalies} anomalous" onclick="Utils.showToast('${label}')"></div>`;
    }).join('');
  }
};

window.AnalyticsModule = AnalyticsModule;
