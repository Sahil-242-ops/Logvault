/**
 * LOGVAULT — Centralized Mock Data & Service Layer
 * SIH26156 Enterprise SOC Platform
 * Designed for immediate mock usage and seamless future FastAPI REST backend swap
 */

const mockNormalizerPresets = {
  ssh: {
    name: 'Linux SSH Auth',
    format: 'Linux / SSH Syslog (RFC 5424)',
    parser: 'SSH PAM Deterministic Parser (Native C++/WASM)',
    parserType: 'DETERMINISTIC',
    latency: '0.04 ms',
    confidence: 1.0,
    raw: 'Aug 28 10:31:02 server01 sshd[1234]: Accepted password for john from 192.168.1.20 port 54210 ssh2',
    tokens: [
      { text: 'Aug 28 10:31:02', type: 'timestamp' },
      { text: 'server01', type: 'host' },
      { text: 'sshd[1234]:', type: 'process' },
      { text: 'Accepted password', type: 'action' },
      { text: 'for john', type: 'user' },
      { text: 'from 192.168.1.20', type: 'src_ip' },
      { text: 'port 54210', type: 'port' },
      { text: 'ssh2', type: 'protocol' }
    ],
    schema: {
      event_type: 'AUTHENTICATION',
      user: 'john',
      status: 'SUCCESS',
      source_ip: '192.168.1.20',
      source_port: 54210,
      host: 'server01',
      process: 'sshd',
      protocol: 'SSHv2',
      timestamp: '2026-08-28T10:31:02Z',
      severity: 'INFO',
      category: 'identity_access',
      ocsf_class_uid: 3002
    }
  },
  cef: {
    name: 'Palo Alto CEF Firewall',
    format: 'Common Event Format (CEF v0.1)',
    parser: 'CEF ArcSight Parser (Deterministic)',
    parserType: 'DETERMINISTIC',
    latency: '0.08 ms',
    confidence: 1.0,
    raw: 'CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|drop|8|src=198.51.100.23 dst=10.0.4.50 spt=44120 dpt=443 proto=TCP act=deny app=ssl cn1=4821',
    tokens: [
      { text: 'CEF:0', type: 'version' },
      { text: 'PaloAltoNetworks|PAN-OS|10.1.0', type: 'vendor' },
      { text: 'TRAFFIC|drop|8', type: 'action' },
      { text: 'src=198.51.100.23', type: 'src_ip' },
      { text: 'dst=10.0.4.50', type: 'dst_ip' },
      { text: 'spt=44120 dpt=443', type: 'ports' },
      { text: 'proto=TCP', type: 'protocol' },
      { text: 'act=deny', type: 'status' }
    ],
    schema: {
      event_type: 'NETWORK_TRAFFIC',
      action: 'DENY_DROP',
      status: 'BLOCKED',
      source_ip: '198.51.100.23',
      source_port: 44120,
      destination_ip: '10.0.4.50',
      destination_port: 443,
      protocol: 'TCP',
      device_vendor: 'PaloAltoNetworks',
      device_product: 'PAN-OS',
      severity: 'HIGH',
      category: 'network_activity',
      ocsf_class_uid: 4001
    }
  },
  apache: {
    name: 'Apache Web Access (W3C)',
    format: 'Apache Combined Log Format (NCSA/W3C)',
    parser: 'W3C HTTP Access Parser (Deterministic)',
    parserType: 'DETERMINISTIC',
    latency: '0.06 ms',
    confidence: 1.0,
    raw: '192.168.1.45 - apache-admin2 [28/Aug/2026:10:31:05 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 532 "https://vault.corp/login" "Mozilla/5.0"',
    tokens: [
      { text: '192.168.1.45', type: 'src_ip' },
      { text: 'apache-admin2', type: 'user' },
      { text: '[28/Aug/2026:10:31:05 +0000]', type: 'timestamp' },
      { text: '"POST /api/v1/auth/login HTTP/1.1"', type: 'http_request' },
      { text: '401', type: 'http_status' },
      { text: '532', type: 'bytes' }
    ],
    schema: {
      event_type: 'HTTP_REQUEST',
      http_method: 'POST',
      url_path: '/api/v1/auth/login',
      http_status_code: 401,
      user: 'apache-admin2',
      source_ip: '192.168.1.45',
      bytes_sent: 532,
      timestamp: '2026-08-28T10:31:05Z',
      severity: 'WARNING',
      category: 'application_activity',
      ocsf_class_uid: 4002
    }
  },
  cloudtrail: {
    name: 'AWS CloudTrail JSON',
    format: 'AWS CloudTrail Audit JSON v1.08',
    parser: 'CloudTrail Schema Parser (Deterministic Native JSON)',
    parserType: 'DETERMINISTIC',
    latency: '0.03 ms',
    confidence: 1.0,
    raw: '{"eventTime":"2026-08-28T10:31:07Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","userIdentity":{"type":"IAMUser","userName":"sec-admin","accountId":"987654321012"},"sourceIPAddress":"10.24.8.12","userAgent":"aws-cli/2.15.0","errorCode":null}',
    tokens: [
      { text: '"eventTime":"2026-08-28T10:31:07Z"', type: 'timestamp' },
      { text: '"eventSource":"iam.amazonaws.com"', type: 'service' },
      { text: '"eventName":"CreateAccessKey"', type: 'action' },
      { text: '"userName":"sec-admin"', type: 'user' },
      { text: '"sourceIPAddress":"10.24.8.12"', type: 'src_ip' }
    ],
    schema: {
      event_type: 'IAM_KEY_CREATION',
      cloud_provider: 'AWS',
      service_name: 'iam.amazonaws.com',
      action: 'CreateAccessKey',
      user: 'sec-admin',
      account_id: '987654321012',
      source_ip: '10.24.8.12',
      user_agent: 'aws-cli/2.15.0',
      status: 'SUCCESS',
      severity: 'INFO',
      category: 'cloud_audit',
      ocsf_class_uid: 3005
    }
  },
  windows: {
    name: 'Windows Security Event 4625',
    format: 'Windows XML Event Log (WinEventLog)',
    parser: 'Windows Security Subsystem Parser (Deterministic)',
    parserType: 'DETERMINISTIC',
    latency: '0.07 ms',
    confidence: 1.0,
    raw: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><TimeCreated SystemTime="2026-08-28T10:31:08Z"/><Computer>DC-PROD-01.corp.local</Computer></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="IpAddress">192.168.1.45</Data><Data Name="Status">0xC000006D</Data></EventData></Event>',
    tokens: [
      { text: '<EventID>4625</EventID>', type: 'action' },
      { text: '<Computer>DC-PROD-01.corp.local</Computer>', type: 'host' },
      { text: 'TargetUserName="Administrator"', type: 'user' },
      { text: 'IpAddress="192.168.1.45"', type: 'src_ip' },
      { text: 'Status="0xC000006D"', type: 'status' }
    ],
    schema: {
      event_type: 'LOGON_FAILURE',
      windows_event_id: 4625,
      target_user: 'Administrator',
      host: 'DC-PROD-01.corp.local',
      source_ip: '192.168.1.45',
      sub_status_code: '0xC000006D (Bad Password)',
      timestamp: '2026-08-28T10:31:08Z',
      severity: 'HIGH',
      category: 'identity_access',
      ocsf_class_uid: 3002
    }
  },
  kubernetes: {
    name: 'Kubernetes Ingress NGINX',
    format: 'Kubernetes Ingress Controller JSON / Log',
    parser: 'K8s Ingress Controller Parser (Deterministic)',
    parserType: 'DETERMINISTIC',
    latency: '0.05 ms',
    confidence: 1.0,
    raw: '10.244.0.1 - [28/Aug/2026:10:31:09 +0000] "POST /api/v1/auth/token HTTP/2.0" 401 89 "ingress-controller/prod" "curl/8.4.0" req_id=k8s-9921',
    tokens: [
      { text: '10.244.0.1', type: 'src_ip' },
      { text: '[28/Aug/2026:10:31:09 +0000]', type: 'timestamp' },
      { text: '"POST /api/v1/auth/token HTTP/2.0"', type: 'action' },
      { text: '401', type: 'status' },
      { text: 'req_id=k8s-9921', type: 'process' }
    ],
    schema: {
      event_type: 'CONTAINER_HTTP_ACCESS',
      http_method: 'POST',
      url_path: '/api/v1/auth/token',
      http_status_code: 401,
      source_ip: '10.244.0.1',
      k8s_cluster: 'prod-cluster-us-east',
      request_id: 'k8s-9921',
      timestamp: '2026-08-28T10:31:09Z',
      severity: 'WARNING',
      category: 'container_activity',
      ocsf_class_uid: 4004
    }
  },
  suricata: {
    name: 'Suricata EVE IDS Alert',
    format: 'Suricata EVE JSON IDS/IPS Telemetry',
    parser: 'Suricata EVE Fast Parser (Deterministic WASM)',
    parserType: 'DETERMINISTIC',
    latency: '0.02 ms',
    confidence: 1.0,
    raw: '{"timestamp":"2026-08-28T10:31:10.512Z","event_type":"alert","src_ip":"192.168.1.45","src_port":51200,"dest_ip":"10.0.4.92","dest_port":22,"alert":{"action":"blocked","signature":"ET SCAN Potential SSH Brute Force Spray","severity":1,"category":"Attempted Administrator Privilege Gain"}}',
    tokens: [
      { text: '"timestamp":"2026-08-28T10:31:10.512Z"', type: 'timestamp' },
      { text: '"src_ip":"192.168.1.45"', type: 'src_ip' },
      { text: '"dest_ip":"10.0.4.92"', type: 'dst_ip' },
      { text: '"signature":"ET SCAN..."', type: 'action' },
      { text: '"action":"blocked"', type: 'status' }
    ],
    schema: {
      event_type: 'INTRUSION_DETECTION_ALERT',
      signature: 'ET SCAN Potential SSH Brute Force Spray',
      action: 'BLOCKED',
      source_ip: '192.168.1.45',
      source_port: 51200,
      destination_ip: '10.0.4.92',
      destination_port: 22,
      alert_severity_id: 1,
      category: 'network_intrusion',
      timestamp: '2026-08-28T10:31:10.512Z',
      severity: 'CRITICAL',
      ocsf_class_uid: 2001
    }
  }
};



const mockParsers = [
  { name: 'JSON / OCSF Native', format: 'JSON / OCSF 1.1', status: 'Active', events: '4.2M', latency: '0.04 ms', engine: 'Deterministic' },
  { name: 'Syslog RFC 5424', format: 'RFC 5424', status: 'Active', events: '2.8M', latency: '0.08 ms', engine: 'Deterministic' },
  { name: 'CEF (ArcSight)', format: 'CEF v0.1', status: 'Active', events: '1.7M', latency: '0.09 ms', engine: 'Deterministic' },
  { name: 'Apache Combined', format: 'W3C Combined', status: 'Active', events: '921K', latency: '0.11 ms', engine: 'Deterministic' },
  { name: 'SSH PAM Linux', format: 'Linux Auth', status: 'Active', events: '640K', latency: '0.06 ms', engine: 'Deterministic' },
  { name: 'Dynamic Schema Mapper', format: 'Custom / Legacy Formats', status: 'Active', events: '182K', latency: '1.20 ms', engine: 'Pattern Engine' }
];



// Service Layer Abstraction — Real Python FastAPI Backend
const LogVaultAPI = {
  _backendAvailable: null,
  _aiStatus: null,
  _baseURL: 'http://127.0.0.1:8000',

  // Check if backend API is reachable
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

  async getDashboardSummary() {
    let logsCount = 'No events processed';
    let anomaliesCount = '0';
    let throughput = 'No events processed';
    let parsedRate = '0%';
    
    try {
        const [eventsRes, anomaliesRes] = await Promise.all([
            fetch(`${this._baseURL}/api/events?limit=1`),
            fetch(`${this._baseURL}/api/anomalies?limit=1`)
        ]);
        
        if (eventsRes.ok && anomaliesRes.ok) {
            const eventsData = await eventsRes.json();
            const anomaliesData = await anomaliesRes.json();
            
            if (eventsData.total === 0) {
                logsCount = 'No events processed';
                anomaliesCount = '0';
                throughput = 'No events processed';
                parsedRate = '0%';
            } else {
                logsCount = eventsData.total.toLocaleString();
                anomaliesCount = anomaliesData.total.toLocaleString();
                throughput = `${eventsData.total} logs processed`;
                parsedRate = '100%';
            }
        }
    } catch {}

    return {
      logsProcessed: logsCount,
      logsTrend: 'Current Session',
      parsedRate: parsedRate,
      parsedReliability: 'Real-time Deterministic',
      suspiciousEvents: anomaliesCount,
      suspiciousTrend: 'Current Session',
      criticalAnomalies: anomaliesCount,
      criticalTrend: 'Current Session',
      throughput: throughput,
      systemConfidence: {
        normalization: 100,
        parser: 100,
        schemaMapping: 100,
        fieldExtraction: 100
      }
    };
  },



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

  async getParsers() {
    return [...mockParsers];
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

  async getEvents(limit = 100, offset = 0, search = '', severity = 'ALL', source = 'ALL') {
    try {
      let url = `${this._baseURL}/api/events?limit=${limit}&offset=${offset}`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (severity && severity !== 'ALL') url += `&severity=${encodeURIComponent(severity)}`;
      // Map frontend 'source' filter to backend 'detected_format' or similar if needed. For now just pass it as event_type if it's not ALL
      if (source && source !== 'ALL') url += `&event_type=${encodeURIComponent(source)}`;

      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        return await res.json();
      }
    } catch {
       // Silently fail for polling so we don't spam toasts
    }
    return { events: [], total: 0 };
  },

  // --- Real Backend API Calls ---

  async normalizeLog(rawInput) {
    try {
      const res = await fetch(`${this._baseURL}/api/normalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw: rawInput }),
        signal: AbortSignal.timeout(30000)
      });
      if (res.ok) {
        const data = await res.json();
        this._backendAvailable = true;
        // Map backend response to UI format
        return {
          raw_log: data.raw_log || rawInput,
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
            timestamp: data.timestamp || new Date().toISOString(),
            severity: data.severity || 'INFO',
            category: data.category || 'general_telemetry',
            message: data.message || null
          },
          tokens: data.tokens || [],
          _raw_backend: data
        };
      } else {
         throw new Error(`Server returned ${res.status}`);
      }
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

window.mockNormalizerPresets = mockNormalizerPresets;

window.LogVaultAPI = LogVaultAPI;
