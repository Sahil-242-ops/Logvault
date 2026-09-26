/**
 * LOGVAULT — API client for the local FastAPI backend.
 * Every /api call carries the operator's sign-in token; a 401 sends the operator back to sign-in.
 */

// Example records for the Normalizer's format buttons. Clicking one runs it through the
// real backend pipeline (preview only, nothing is stored).
const NormalizerExamples = {
  ssh: {
    name: 'Linux SSH Auth',
    raw: 'Aug 28 10:31:02 server01 sshd[1234]: Accepted password for john from 192.168.1.20 port 54210 ssh2'
  },
  cef: {
    name: 'Palo Alto CEF Firewall',
    raw: 'CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|drop|8|src=198.51.100.23 dst=10.0.4.50 spt=44120 dpt=443 proto=TCP act=deny app=ssl cn1=4821'
  },
  apache: {
    name: 'Apache Web Access',
    raw: '192.168.1.45 - apache-admin2 [28/Aug/2026:10:31:05 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 532 "https://vault.corp/login" "Mozilla/5.0"'
  },
  cloudtrail: {
    name: 'AWS CloudTrail JSON',
    raw: '{"eventTime":"2026-08-28T10:31:07Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","userIdentity":{"type":"IAMUser","userName":"sec-admin","accountId":"987654321012"},"sourceIPAddress":"10.24.8.12","userAgent":"aws-cli/2.15.0","errorCode":null}'
  },
  windows: {
    name: 'Windows Security Event 4625',
    raw: 'EventID=4625 AccountName=Administrator Workstation=DC-PROD-01 SourceIP=192.168.1.45 Status=0xC000006D'
  },
  kubernetes: {
    name: 'Kubernetes Ingress NGINX',
    raw: '10.244.0.1 - - [28/Aug/2026:10:31:09 +0000] "POST /api/v1/auth/token HTTP/2.0" 401 89 "ingress-controller/prod" "curl/8.4.0"'
  },
  suricata: {
    name: 'Suricata EVE IDS Alert',
    raw: '{"timestamp":"2026-08-28T10:31:10.512Z","event_type":"alert","src_ip":"192.168.1.45","src_port":51200,"dest_ip":"10.0.4.92","dest_port":22,"alert":{"action":"blocked","signature":"ET SCAN Potential SSH Brute Force Spray","severity":1,"category":"Attempted Administrator Privilege Gain"}}'
  }
};

// The UI is normally served by the backend itself; opened as a file it falls back to the default port.
const API_BASE = location.protocol.startsWith('http') ? location.origin : 'http://127.0.0.1:8000';

// Attach the sign-in token to every backend call (including modules that call fetch directly)
(function installAuthFetch() {
  const nativeFetch = window.fetch.bind(window);
  const PUBLIC = ['/api/health', '/api/auth/login', '/api/auth/demo', '/api/auth/config'];
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    const path = url.startsWith(API_BASE) ? url.slice(API_BASE.length) : url;
    if (!path.startsWith('/api/')) return nativeFetch(input, init);

    const token = sessionStorage.getItem('logvault_token') || localStorage.getItem('logvault_token');
    const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const res = await nativeFetch(input, { ...init, headers });
    if (res.status === 401 && !PUBLIC.some(p => path.startsWith(p)) && window.AuthModule) {
      AuthModule.sessionExpired();
    }
    return res;
  };
})();

const LogVaultAPI = {
  _backendAvailable: null,
  _aiStatus: null,
  _baseURL: API_BASE,

  async checkBackend() {
    try {
      const res = await fetch(`${this._baseURL}/api/health`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        const data = await res.json();
        this._backendAvailable = true;
        this._aiStatus = { mode: data.local_ai ? 'LOCAL AI' : 'FALLBACK', available: data.local_ai, model: data.model, provider: data.ai_provider };
        return data;
      }
    } catch {
      // Backend unavailable
    }
    this._backendAvailable = false;
    return null;
  },

  isBackendAvailable() {
    return this._backendAvailable === true;
  },

  getAIStatus() {
    return this._aiStatus || { mode: 'UNKNOWN', available: false };
  },

  // --- Generic helpers ---
  async _getJSON(path, timeoutMs = 10000) {
    const res = await fetch(`${this._baseURL}${path}`, { signal: AbortSignal.timeout(timeoutMs) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  },

  async _postJSON(path, body, timeoutMs = 10000, method = 'POST') {
    const res = await fetch(`${this._baseURL}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
      signal: AbortSignal.timeout(timeoutMs)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  },

  async _delete(path) {
    const res = await fetch(`${this._baseURL}${path}`, { method: 'DELETE', signal: AbortSignal.timeout(10000) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  },

  // Download a backend file (the token travels in the header, never in the URL)
  async download(path, fallbackName) {
    const res = await fetch(`${this._baseURL}${path}`, { signal: AbortSignal.timeout(300000) });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || `HTTP ${res.status}`);
    }
    const match = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '');
    const name = match ? match[1] : fallbackName;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return { name, bytes: blob.size };
  },

  // --- Sign-in ---
  getAuthConfig() { return this._getJSON('/api/auth/config', 5000); },
  login(email, password) { return this._postJSON('/api/auth/login', { email, password }); },
  demoLogin() { return this._postJSON('/api/auth/demo', {}); },
  logout() { return this._postJSON('/api/auth/logout', {}).catch(() => null); },
  me() { return this._getJSON('/api/auth/me', 5000); },
  updateProfile(name, callsign, org) { return this._postJSON('/api/auth/me', { name, callsign, org }, 10000, 'PUT'); },
  changePassword(current_password, new_password) { return this._postJSON('/api/auth/password', { current_password, new_password }); },

  // --- Dashboard, sources, parsers ---
  async getDashboard() {
    try { return await this._getJSON('/api/dashboard'); } catch { return null; }
  },
  async getCollectors() {
    try { return await this._getJSON('/api/collectors'); } catch { return null; }
  },
  async getParsers() {
    try { return await this._getJSON('/api/parsers'); } catch { return null; }
  },
  benchmarkParser(raw, parser) {
    return this._postJSON('/api/parsers/benchmark', { raw, parser: parser || null }, 30000);
  },

  // --- Schema mapper ---
  mapperInfer(raw, useAi = false) { return this._postJSON('/api/mapper/infer', { raw, use_ai: useAi }, useAi ? 60000 : 10000); },
  getMappingRules() { return this._getJSON('/api/mapper/rules'); },
  saveMappingRule(rule) { return this._postJSON('/api/mapper/rules', rule); },
  deleteMappingRule(id) { return this._delete(`/api/mapper/rules/${encodeURIComponent(id)}`); },

  // --- Containment ---
  getContainment(includeReleased = false) { return this._getJSON(`/api/containment?include_released=${includeReleased}`); },
  contain(kind, value, reason, alertId) { return this._postJSON('/api/containment', { kind, value, reason, alert_id: alertId || null }); },
  releaseContainment(id) { return this._delete(`/api/containment/${encodeURIComponent(id)}`); },

  async getSources() {
    try {
      const res = await fetch(`${this._baseURL}/api/sources`, { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        return await res.json();
      }
    } catch {
       // Silently fail for polling
    }
    return { sources: [], total: 0 };
  },

  async getAnomalies(limit = 100, offset = 0, search = '', severity = 'ALL') {
    try {
      let url = `${this._baseURL}/api/anomalies?limit=${limit}&offset=${offset}`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (severity && severity !== 'ALL') url += `&severity=${encodeURIComponent(severity)}`;

      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        return await res.json();
      }
    } catch {
       // Silently fail for polling
    }
    return { anomalies: [], total: 0 };
  },

  async getAlerts(limit = 100, offset = 0, status = 'ALL') {
    try {
      let url = `${this._baseURL}/api/alerts?limit=${limit}&offset=${offset}`;
      if (status && status !== 'ALL') url += `&status=${encodeURIComponent(status)}`;

      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        return await res.json();
      }
    } catch {
       // Silently fail for polling
    }
    return { alerts: [], total: 0 };
  },

  // --- Alert triage workflow (AI investigation + analyst approval) ---
  investigateAlert(id) {
    return this._postJSON(`/api/alerts/${encodeURIComponent(id)}/investigate`, {}, 120000);
  },

  approveAlert(id, analyst, note, includeRelated = false) {
    return this._postJSON(`/api/alerts/${encodeURIComponent(id)}/approve`, { analyst, note, include_related: includeRelated });
  },

  rejectAlert(id, analyst, note) {
    return this._postJSON(`/api/alerts/${encodeURIComponent(id)}/reject`, { analyst, note });
  },

  setAlertStatus(id, status, analyst) {
    return this._postJSON(`/api/alerts/${encodeURIComponent(id)}/status`, { status, analyst });
  },

  // --- Event analytics (offline GeoIP + time-of-day heatmap) ---
  async getGeoAnalytics() {
    try {
      const res = await fetch(`${this._baseURL}/api/analytics/geo`, { signal: AbortSignal.timeout(10000) });
      if (res.ok) return await res.json();
    } catch {
      // Backend offline: caller renders empty state
    }
    return null;
  },

  async getHeatmap() {
    try {
      const res = await fetch(`${this._baseURL}/api/analytics/heatmap`, { signal: AbortSignal.timeout(10000) });
      if (res.ok) return await res.json();
    } catch {
      // Backend offline: caller renders empty state
    }
    return null;
  },

  async getEvents(limit = 100, offset = 0, search = '', severity = 'ALL', format = 'ALL', sourceIp = '', sinceMinutes = null) {
    try {
      let url = `${this._baseURL}/api/events?limit=${limit}&offset=${offset}`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (severity && severity !== 'ALL') url += `&severity=${encodeURIComponent(severity)}`;
      if (format && format !== 'ALL') url += `&detected_format=${encodeURIComponent(format)}`;
      if (sourceIp) url += `&source_ip=${encodeURIComponent(sourceIp)}`;
      if (sinceMinutes) url += `&since_minutes=${sinceMinutes}`;

      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        return await res.json();
      }
    } catch {
       // Silently fail for polling so we don't spam toasts
    }
    return { events: [], total: 0 };
  },

  // Map a backend event to the Normalizer's view model
  _toNormalizerView(data, rawInput) {
    return {
      raw_log: data.raw_log || rawInput,
      raw: data.raw_log || rawInput,
      format: data.detected_format || 'Unknown',
      parser: data.parser_name || 'Backend Parser',
      parserType: data.parser_type || 'DETERMINISTIC',
      latency: (data.processing_latency_ms || 0).toFixed(2) + ' ms',
      confidence: data.parse_confidence || data.detection_confidence || 0,
      ocsf_class: data.ocsf_class_name || null,
      ocsf_class_uid: data.ocsf_class_uid || null,
      anomaly: data.anomaly || null,
      pii_masked: data.pii_masked || false,
      ai_provider: data.ai_provider || 'none',
      ai_model: data.ai_model || 'none',
      ai_reasoning: data.ai_reasoning || '',
      ai_threat_score: data.ai_threat_score !== undefined ? data.ai_threat_score : (data.anomaly ? data.anomaly.threat_score : 0),
      ai_mitre_techniques: data.ai_mitre_techniques || [],
      ai_is_suspicious: data.ai_is_suspicious || false,
      schema: {
        event_type: data.event_type || 'GENERIC_EVENT',
        user: data.user || 'unknown',
        status: data.status || data.action || 'RECORDED',
        source_ip: data.source_ip || null,
        source_port: data.source_port || null,
        destination_ip: data.destination_ip || null,
        destination_port: data.destination_port || null,
        host: data.host || null,
        process: data.process || null,
        protocol: data.protocol || null,
        timestamp: data.timestamp || null,
        severity: data.severity || 'INFO',
        category: data.category || 'general_telemetry',
        message: data.message || null
      },
      tokens: data.tokens || [],
      _raw_backend: data
    };
  },

  // store=false: run the full pipeline as a preview without saving the event
  async normalizeLog(rawInput, { store = true } = {}) {
    try {
      const res = await fetch(`${this._baseURL}/api/normalize${store ? '' : '?store=false'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw: rawInput }),
        signal: AbortSignal.timeout(30000)
      });
      if (res.ok) {
        this._backendAvailable = true;
        return this._toNormalizerView(await res.json(), rawInput);
      }
      throw new Error(`Server returned ${res.status}`);
    } catch (err) {
      this._backendAvailable = false;
      if (window.Utils) {
        window.Utils.showToast('Python backend unavailable. Please start the FastAPI server on port 8000.', 'error');
      }
      throw new Error('Python backend unavailable. Please start the FastAPI server on port 8000.');
    }
  },

  async detectFormat(rawInput) {
    try {
      const res = await fetch(`${this._baseURL}/api/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw: rawInput }),
        signal: AbortSignal.timeout(5000)
      });
      if (res.ok) return await res.json();
    } catch (err) {
      if (window.Utils) {
        window.Utils.showToast('Python backend unavailable. Please start the FastAPI server on port 8000.', 'error');
      }
    }
    return { format: 'unknown', confidence: 0 };
  },

  async uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch(`${this._baseURL}/api/upload`, {
        method: 'POST',
        body: formData,
        signal: AbortSignal.timeout(180000)
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      if (err.name === 'TimeoutError') {
        throw new Error('processing timed out (file too large for one request)');
      }
      if (err instanceof TypeError && window.Utils) {
        window.Utils.showToast('Python backend unavailable. Please start the FastAPI server on port 8000.', 'error');
      }
      throw err;
    }
  },

  async aiAnalyze(rawInput, task = 'analyze') {
    try {
      const res = await fetch(`${this._baseURL}/api/ai/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw: rawInput, task }),
        signal: AbortSignal.timeout(30000)
      });
      if (res.ok) return await res.json();
    } catch (err) {
      if (window.Utils) {
        window.Utils.showToast('Python backend unavailable. Please start the FastAPI server on port 8000.', 'error');
      }
    }
    return { success: false, source: 'unavailable', result: null };
  }
};

window.NormalizerExamples = NormalizerExamples;
window.LogVaultAPI = LogVaultAPI;
