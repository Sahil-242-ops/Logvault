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

const initialLiveLogs = [
  { id: 101, time: '10:31:09', source: 'FIREWALL', action: 'BLOCKED', ip: '192.168.1.20', user: 'system', sev: 'HIGH', msg: 'Port scan probe detected on perimeter interface eth0 (ports 22, 80, 443, 8080)' },
  { id: 102, time: '10:31:08', source: 'SSH', action: 'LOGIN_FAIL', ip: '10.24.8.12', user: 'root', sev: 'MEDIUM', msg: 'Failed password for root via SSH from 10.24.8.12 port 58921 (attempt 4/5)' },
  { id: 103, time: '10:31:07', source: 'WINDOWS', action: 'PROCESS', ip: '10.0.3.14', user: 'workstation-04', sev: 'LOW', msg: 'Process spawned: powershell.exe -NonInteractive -ExecutionPolicy Bypass' },
  { id: 104, time: '10:31:05', source: 'AWS', action: 'AUTH_SUCCESS', ip: '198.51.100.4', user: 'user@company.com', sev: 'INFO', msg: 'ConsoleLogin: MFA verification successful from trusted origin' },
  { id: 105, time: '10:31:04', source: 'SSH', action: 'LOGIN_FAIL', ip: '10.24.8.12', user: 'admin', sev: 'MEDIUM', msg: 'Failed password for admin via SSH from 10.24.8.12 port 58920 (attempt 3/5)' },
  { id: 106, time: '10:31:02', source: 'LINUX', action: 'LOGIN', ip: '192.168.1.20', user: 'john', sev: 'INFO', msg: 'Accepted publickey for john from 192.168.1.20 port 54210 ssh2: RSA SHA256:4a8f...' },
  { id: 107, time: '10:30:59', source: 'APACHE', action: 'HTTP_401', ip: '192.168.1.45', user: 'apache-admin2', sev: 'HIGH', msg: 'POST /api/v1/auth/login returned HTTP 401 Unauthorized (invalid JWT signature)' },
  { id: 108, time: '10:30:57', source: 'OKTA', action: 'SSO_CHALLENGE', ip: '203.0.113.78', user: 'amrita.lead', sev: 'LOW', msg: 'FIDO2 WebAuthn authentication completed successfully' },
  { id: 109, time: '10:30:54', source: 'FIREWALL', action: 'DROP', ip: '185.220.101.5', user: 'anonymous', sev: 'CRITICAL', msg: 'ACL Drop: Known Tor Exit Relay IP attempting ingress connection on port 3389' },
  { id: 110, time: '10:30:50', source: 'SURICATA', action: 'ALERT', ip: '192.168.1.45', user: 'Server01', sev: 'CRITICAL', msg: 'ET SCAN Potential SSH Brute Force Attack detected (4,821 attempts in 7 mins)' }
];

const mockSources = [
  { id: 'src-1', name: 'server-01', type: 'Linux SSH', rate: '18.2K logs/min', status: 'HEALTHY', lastSeen: '2s ago', eps: 304, reliability: '100%' },
  { id: 'src-2', name: 'firewall-01', type: 'CEF / Palo Alto', rate: '42.1K logs/min', status: 'HEALTHY', lastSeen: '1s ago', eps: 702, reliability: '99.99%' },
  { id: 'src-3', name: 'aws-prod', type: 'AWS CloudTrail', rate: '8.4K logs/min', status: 'HEALTHY', lastSeen: '4s ago', eps: 140, reliability: '100%' },
  { id: 'src-4', name: 'win-domain-01', type: 'Windows EventLog', rate: '12.8K logs/min', status: 'HEALTHY', lastSeen: '3s ago', eps: 213, reliability: '99.95%' },
  { id: 'src-5', name: 'vpn-gateway', type: 'Syslog RFC 5424', rate: '2.1K logs/min', status: 'DELAYED', lastSeen: '28s ago', eps: 35, reliability: '94.20%' },
  { id: 'src-6', name: 'backup-storage-02', type: 'Syslog Storage', rate: '0 logs/min', status: 'OFFLINE', lastSeen: '14m ago', eps: 0, reliability: '0%' }
];

const mockParsers = [
  { name: 'JSON / OCSF Native', format: 'JSON / OCSF 1.1', status: 'Active', events: '4.2M', latency: '0.04 ms', engine: 'Deterministic' },
  { name: 'Syslog RFC 5424', format: 'RFC 5424', status: 'Active', events: '2.8M', latency: '0.08 ms', engine: 'Deterministic' },
  { name: 'CEF (ArcSight)', format: 'CEF v0.1', status: 'Active', events: '1.7M', latency: '0.09 ms', engine: 'Deterministic' },
  { name: 'Apache Combined', format: 'W3C Combined', status: 'Active', events: '921K', latency: '0.11 ms', engine: 'Deterministic' },
  { name: 'SSH PAM Linux', format: 'Linux Auth', status: 'Active', events: '640K', latency: '0.06 ms', engine: 'Deterministic' },
  { name: 'AI Heuristic Mapper', format: 'Unknown Formats', status: 'AI Active', events: '182K', latency: '1.20 ms', engine: 'Local Heuristic' }
];

const mockAnomalies = [
  {
    id: 'ANOM-01',
    title: 'Possible Brute Force Attack',
    detectedAgo: '7 minutes ago',
    severity: 'CRITICAL',
    confidence: 97,
    sourceIp: '192.168.1.45',
    target: 'server-07',
    failedAttempts: 4821,
    duration: '7 minutes',
    timeline: [
      { time: '10:24', failures: 12, note: 'Initial probe and port scan on port 22' },
      { time: '10:25', failures: 184, note: 'Dictionary wordlist spray initiated' },
      { time: '10:26', failures: 621, note: 'Multi-threaded worker spray detected' },
      { time: '10:27', failures: 1104, note: 'Root & service accounts specifically targeted' },
      { time: '10:28', failures: 2900, note: 'Burst rate peak reached (85 req/sec)' },
      { time: '10:31', failures: 4821, note: 'SOC heuristic threshold exceeded; anomaly triggered' }
    ]
  }
];

const mockAlerts = [
  {
    id: 'INC-01',
    title: 'Critical: Possible Brute Force Attack on Server-07',
    srcIp: '192.168.1.45',
    targetIp: 'server-07 (DB Gateway)',
    sev: 'CRITICAL',
    state: 'Active',
    eventType: 'Authentication Spray',
    timeAgo: '7 mins ago',
    desc: 'Correlation heuristic detected 4,821 consecutive authentication failures targeting internal SSH daemon on port 22 within a 7-minute burst window.'
  },
  {
    id: 'INC-02',
    title: 'Geographic Impossible Travel Anomaly',
    srcIp: '203.0.113.78',
    targetIp: 'OKTA SSO Portal',
    sev: 'HIGH',
    state: 'Active',
    eventType: 'Impossible Travel',
    timeAgo: '18 mins ago',
    desc: 'Simultaneous credential sessions authenticated from Mumbai (10:14 UTC), Frankfurt (10:32 UTC), and New York (10:48 UTC) exceeding maximum physical velocity.'
  },
  {
    id: 'INC-03',
    title: 'Tor Exit Relay Ingress & Probe Vector',
    srcIp: '185.220.101.5',
    targetIp: 'VPN Gateway eth0',
    sev: 'CRITICAL',
    state: 'Active',
    eventType: 'Tor Ingress Probe',
    timeAgo: '11 mins ago',
    desc: 'Verified Tor exit node attempted high-volume ingress connection on RDP/SSH ports. Perimeter ACL drop rule automatically engaged.'
  },
  {
    id: 'INC-04',
    title: 'Anomalous DGA Query Handshake',
    srcIp: '192.168.1.88',
    targetIp: 'Core DNS Resolver',
    sev: 'MEDIUM',
    state: 'Investigating',
    eventType: 'DNS Beaconing',
    timeAgo: '42 mins ago',
    desc: 'High-entropy algorithmic domain queries detected from internal finance workstation. Packet capture tagged for forensic review.'
  },
  {
    id: 'INC-05',
    title: 'Kubernetes Pod Privilege Escalation Exec',
    srcIp: '10.244.0.15',
    targetIp: 'payment-gateway-7b9f',
    sev: 'MEDIUM',
    state: 'Investigating',
    eventType: 'K8s Exec Session',
    timeAgo: '1 hour ago',
    desc: 'Interactive container exec session spawned with root privileges on payment cluster pod. SOC lead investigating user authorization.'
  },
  {
    id: 'INC-06',
    title: 'Perimeter Firewall Automated ACL Drop',
    srcIp: '198.51.100.23',
    targetIp: 'Perimeter NGFW',
    sev: 'LOW',
    state: 'Resolved',
    eventType: 'Firewall Block',
    timeAgo: '2 hours ago',
    desc: 'Automated rate-limiting drop rule engaged on perimeter gateway. Source IP contained and quarantined successfully.'
  }
];

// Service Layer Abstraction (Ready for FastAPI integration)
const LogVaultAPI = {
  async getDashboardSummary() {
    return {
      logsProcessed: '12.4M',
      logsTrend: '+12.8% from previous 24h',
      parsedRate: '99.98%',
      parsedReliability: '+99.2% parser accuracy',
      suspiciousEvents: '8,421',
      suspiciousTrend: '+6.2% across 52,000 assets',
      criticalAnomalies: 23,
      criticalTrend: '↑ 14% from previous 24h',
      throughput: '18,420 logs/sec',
      systemConfidence: {
        normalization: 99.8,
        parser: 100,
        schemaMapping: 99,
        fieldExtraction: 100
      }
    };
  },

  async getLiveLogs() {
    return [...initialLiveLogs];
  },

  async getSources() {
    return [...mockSources];
  },

  async getParsers() {
    return [...mockParsers];
  },

  async getAnomalies() {
    return [...mockAnomalies];
  },

  async normalizeLog(rawInput) {
    // Stage 1 Deterministic / Local Heuristic Parser Engine
    const trimmed = rawInput.trim();

    // Check for SSH preset pattern
    if (trimmed.includes('sshd') || trimmed.includes('Accepted password') || trimmed.includes('Failed password')) {
      const isAccepted = trimmed.includes('Accepted');
      const userMatch = trimmed.match(/for\s+([a-zA-Z0-9_\-\.]+)/);
      const ipMatch = trimmed.match(/from\s+([0-9\.]+)/);
      const portMatch = trimmed.match(/port\s+(\d+)/);

      return {
        format: 'Linux / SSH Syslog (RFC 5424)',
        parser: 'SSH PAM Deterministic Parser (Deterministic)',
        parserType: 'DETERMINISTIC',
        latency: '0.04 ms',
        confidence: 1.0,
        schema: {
          event_type: 'AUTHENTICATION',
          user: userMatch ? userMatch[1] : 'john',
          status: isAccepted ? 'SUCCESS' : 'FAILURE',
          source_ip: ipMatch ? ipMatch[1] : '192.168.1.20',
          source_port: portMatch ? parseInt(portMatch[1]) : 54210,
          host: 'server01',
          process: 'sshd',
          timestamp: new Date().toISOString(),
          severity: isAccepted ? 'INFO' : 'HIGH',
          category: 'identity_access'
        }
      };
    }

    // Check for CEF pattern
    if (trimmed.startsWith('CEF:') || trimmed.includes('PaloAlto')) {
      return mockNormalizerPresets.cef;
    }

    // Check for Apache pattern
    if (trimmed.includes('HTTP/1.') || trimmed.includes('"GET ') || trimmed.includes('"POST ')) {
      return mockNormalizerPresets.apache;
    }

    // Check for CloudTrail JSON
    if (trimmed.startsWith('{') && (trimmed.includes('eventSource') || trimmed.includes('userIdentity'))) {
      return mockNormalizerPresets.cloudtrail;
    }

    // Fallback: Generic Key-Value parser
    const kvPairs = {};
    const tokens = trimmed.split(/[\s,]+/);
    tokens.forEach(tok => {
      const parts = tok.split('=');
      if (parts.length === 2) {
        kvPairs[parts[0].toLowerCase()] = parts[1];
      }
    });

    return {
      format: 'Generic Key-Value Telemetry',
      parser: 'Key-Value Delimited Engine (Deterministic)',
      parserType: 'DETERMINISTIC',
      latency: '0.09 ms',
      confidence: 0.94,
      schema: {
        event_type: kvPairs.act || kvPairs.action || kvPairs.event || 'GENERIC_EVENT',
        user: kvPairs.usr || kvPairs.user || kvPairs.username || 'unknown',
        status: kvPairs.res || kvPairs.status || kvPairs.result || 'RECORDED',
        source_ip: kvPairs.src || kvPairs.ip || kvPairs.src_ip || '127.0.0.1',
        raw_attributes: kvPairs,
        timestamp: new Date().toISOString(),
        severity: 'INFO',
        category: 'general_telemetry'
      }
    };
  }
};

window.mockNormalizerPresets = mockNormalizerPresets;
window.initialLiveLogs = initialLiveLogs;
window.mockSources = mockSources;
window.mockParsers = mockParsers;
window.mockAnomalies = mockAnomalies;
window.mockAlerts = mockAlerts;
window.LogVaultAPI = LogVaultAPI;
