/**
 * LOGVAULT — JSON Log Parser
 * Parses structured JSON logs: CloudTrail, Suricata EVE, Kubernetes, generic JSON
 */

export function parse(raw) {
  const trimmed = raw.trim();
  let obj;
  try {
    obj = JSON.parse(trimmed);
  } catch {
    return null;
  }

  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return null;

  const result = {
    format: 'json',
    parser: 'Structured JSON Parser',
    parserType: 'DETERMINISTIC',
    confidence: 1.0,
    raw: trimmed,
    fields: {},
    tokens: []
  };

  // Detect JSON subtype and extract fields accordingly
  if (isCloudTrail(obj)) {
    parseCloudTrail(result, obj);
  } else if (isSuricataEVE(obj)) {
    parseSuricata(result, obj);
  } else if (isKubernetesLog(obj)) {
    parseKubernetes(result, obj);
  } else {
    parseGenericJSON(result, obj);
  }

  return result;
}

function isCloudTrail(obj) {
  return obj.eventSource || obj.eventVersion || obj.userIdentity || obj.awsRegion;
}

function isSuricataEVE(obj) {
  return obj.event_type && (obj.alert || obj.src_ip || obj.flow_id);
}

function isKubernetesLog(obj) {
  return obj.kubernetes || obj.pod || (obj.log && obj.stream) || obj.container_name;
}

function parseCloudTrail(result, obj) {
  result.format = 'json-cloudtrail';
  result.parser = 'AWS CloudTrail JSON Parser';

  const identity = obj.userIdentity || {};
  result.fields = {
    event_type: mapCloudTrailEvent(obj.eventName),
    cloud_provider: 'AWS',
    service_name: obj.eventSource || null,
    action: obj.eventName || null,
    user: identity.userName || identity.arn || null,
    user_type: identity.type || null,
    account_id: identity.accountId || null,
    source_ip: obj.sourceIPAddress || null,
    user_agent: obj.userAgent || null,
    aws_region: obj.awsRegion || null,
    event_version: obj.eventVersion || null,
    error_code: obj.errorCode || null,
    error_message: obj.errorMessage || null,
    timestamp: obj.eventTime || null,
    severity: obj.errorCode ? 'HIGH' : 'INFO',
    category: 'cloud_audit'
  };

  result.tokens = [
    { text: `eventTime: ${obj.eventTime || 'N/A'}`, type: 'timestamp' },
    { text: `eventSource: ${obj.eventSource || 'N/A'}`, type: 'service' },
    { text: `eventName: ${obj.eventName || 'N/A'}`, type: 'action' },
    { text: `userName: ${identity.userName || 'N/A'}`, type: 'user' },
    { text: `sourceIP: ${obj.sourceIPAddress || 'N/A'}`, type: 'src_ip' }
  ];
}

function parseSuricata(result, obj) {
  result.format = 'json-suricata';
  result.parser = 'Suricata EVE JSON Parser';

  const alert = obj.alert || {};
  result.fields = {
    event_type: obj.event_type === 'alert' ? 'INTRUSION_DETECTION_ALERT' : `SURICATA_${(obj.event_type || 'event').toUpperCase()}`,
    source_ip: obj.src_ip || null,
    source_port: obj.src_port || null,
    destination_ip: obj.dest_ip || obj.dst_ip || null,
    destination_port: obj.dest_port || obj.dst_port || null,
    protocol: obj.proto || null,
    flow_id: obj.flow_id || null,
    signature: alert.signature || null,
    signature_id: alert.signature_id || null,
    alert_action: alert.action || null,
    alert_category: alert.category || null,
    alert_severity_id: alert.severity || null,
    timestamp: obj.timestamp || null,
    severity: alert.severity === 1 ? 'CRITICAL' : alert.severity === 2 ? 'HIGH' : 'MEDIUM',
    category: 'network_intrusion'
  };

  result.tokens = [
    { text: `timestamp: ${obj.timestamp || 'N/A'}`, type: 'timestamp' },
    { text: `src_ip: ${obj.src_ip || 'N/A'}`, type: 'src_ip' },
    { text: `dest_ip: ${obj.dest_ip || obj.dst_ip || 'N/A'}`, type: 'dst_ip' },
    { text: `signature: ${alert.signature || 'N/A'}`, type: 'action' },
    { text: `action: ${alert.action || 'N/A'}`, type: 'status' }
  ];
}

function parseKubernetes(result, obj) {
  result.format = 'json-kubernetes';
  result.parser = 'Kubernetes JSON Parser';

  const k8s = obj.kubernetes || {};
  result.fields = {
    event_type: 'CONTAINER_EVENT',
    pod_name: k8s.pod_name || obj.pod || null,
    namespace: k8s.namespace_name || obj.namespace || null,
    container_name: k8s.container_name || obj.container_name || null,
    host: k8s.host || obj.host || null,
    log_message: obj.log || obj.message || null,
    stream: obj.stream || null,
    timestamp: obj.time || obj.timestamp || obj['@timestamp'] || null,
    severity: 'INFO',
    category: 'container_activity'
  };

  result.tokens = [
    { text: `pod: ${result.fields.pod_name || 'N/A'}`, type: 'process' },
    { text: `namespace: ${result.fields.namespace || 'N/A'}`, type: 'host' },
    { text: `log: ${(result.fields.log_message || '').substring(0, 60)}`, type: 'message' }
  ];
}

function parseGenericJSON(result, obj) {
  result.format = 'json-generic';
  result.parser = 'Generic JSON Parser';

  // Extract common field names
  result.fields = {
    event_type: obj.event_type || obj.eventType || obj.type || obj.action || 'JSON_EVENT',
    timestamp: obj.timestamp || obj.time || obj['@timestamp'] || obj.eventTime || obj.ts || null,
    source_ip: obj.source_ip || obj.src_ip || obj.sourceIPAddress || obj.ip || obj.client_ip || null,
    user: obj.user || obj.userName || obj.username || obj.actor || null,
    host: obj.host || obj.hostname || obj.server || obj.node || null,
    message: obj.message || obj.msg || obj.log || obj.description || null,
    severity: obj.severity || obj.level || obj.priority || 'INFO',
    category: 'general_telemetry',
    raw_fields: obj
  };

  const keys = Object.keys(obj).slice(0, 6);
  result.tokens = keys.map(k => ({
    text: `${k}: ${typeof obj[k] === 'object' ? JSON.stringify(obj[k]).substring(0, 40) : String(obj[k]).substring(0, 40)}`,
    type: guessTokenType(k)
  }));
}

function guessTokenType(key) {
  const k = key.toLowerCase();
  if (k.includes('time') || k.includes('date') || k.includes('ts')) return 'timestamp';
  if (k.includes('ip') || k.includes('addr') || k.includes('source')) return 'src_ip';
  if (k.includes('user') || k.includes('name') || k.includes('actor')) return 'user';
  if (k.includes('host') || k.includes('server') || k.includes('node')) return 'host';
  if (k.includes('action') || k.includes('event') || k.includes('type')) return 'action';
  if (k.includes('status') || k.includes('result') || k.includes('code')) return 'status';
  if (k.includes('port')) return 'port';
  if (k.includes('proto')) return 'protocol';
  return 'message';
}

function mapCloudTrailEvent(eventName) {
  if (!eventName) return 'CLOUD_EVENT';
  if (eventName.includes('Login') || eventName.includes('Auth')) return 'CLOUD_AUTHENTICATION';
  if (eventName.includes('Create')) return 'CLOUD_RESOURCE_CREATE';
  if (eventName.includes('Delete')) return 'CLOUD_RESOURCE_DELETE';
  if (eventName.includes('Update') || eventName.includes('Modify')) return 'CLOUD_RESOURCE_MODIFY';
  if (eventName.includes('Get') || eventName.includes('Describe') || eventName.includes('List')) return 'CLOUD_API_READ';
  return 'CLOUD_API_CALL';
}

export function canParse(raw) {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return 0;
  try {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      if (isCloudTrail(parsed)) return 0.95;
      if (isSuricataEVE(parsed)) return 0.95;
      if (isKubernetesLog(parsed)) return 0.90;
      return 0.70; // Generic JSON
    }
  } catch {
    return 0;
  }
  return 0;
}
