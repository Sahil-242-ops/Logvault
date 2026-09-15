/**
 * LOGVAULT — Normalization Pipeline
 * Raw Log → Detect → Parse → Normalize → Clean → PII Mask → OCSF Schema Output
 */

import { detect, parseAuto } from './parsers/detector.js';
import { v4 as uuidv4 } from 'uuid';

// PII patterns to mask
const PII_PATTERNS = [
  { name: 'email', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, mask: '[EMAIL_REDACTED]' },
  { name: 'credit_card', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, mask: '[CC_REDACTED]' },
  { name: 'ssn', regex: /\b\d{3}-\d{2}-\d{4}\b/g, mask: '[SSN_REDACTED]' },
  { name: 'phone', regex: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, mask: '[PHONE_REDACTED]' }
];

// OCSF class mapping based on event type
const OCSF_CLASS_MAP = {
  'AUTHENTICATION_SUCCESS': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'AUTHENTICATION_FAILURE': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'LOGON_SUCCESS': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'LOGON_FAILURE': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'INVALID_USER_ATTEMPT': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'CLOUD_AUTHENTICATION': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'FIREWALL_DENY': { uid: 4001, name: 'Network Activity', category: 'network_activity' },
  'FIREWALL_ALLOW': { uid: 4001, name: 'Network Activity', category: 'network_activity' },
  'FIREWALL_EVENT': { uid: 4001, name: 'Network Activity', category: 'network_activity' },
  'NETWORK_TRAFFIC': { uid: 4001, name: 'Network Activity', category: 'network_activity' },
  'NETWORK_EVENT': { uid: 4001, name: 'Network Activity', category: 'network_activity' },
  'HTTP_REQUEST': { uid: 4002, name: 'HTTP Activity', category: 'application_activity' },
  'HTTP_AUTH_FAILURE': { uid: 4002, name: 'HTTP Activity', category: 'application_activity' },
  'HTTP_SERVER_ERROR': { uid: 4002, name: 'HTTP Activity', category: 'application_activity' },
  'PATH_TRAVERSAL_ATTEMPT': { uid: 2001, name: 'Security Finding', category: 'network_intrusion' },
  'XSS_ATTEMPT': { uid: 2001, name: 'Security Finding', category: 'network_intrusion' },
  'SQL_INJECTION_ATTEMPT': { uid: 2001, name: 'Security Finding', category: 'network_intrusion' },
  'INTRUSION_DETECTION_ALERT': { uid: 2001, name: 'Security Finding', category: 'network_intrusion' },
  'THREAT_DETECTION': { uid: 2001, name: 'Security Finding', category: 'network_intrusion' },
  'CLOUD_RESOURCE_CREATE': { uid: 3001, name: 'Account Change', category: 'cloud_audit' },
  'CLOUD_RESOURCE_DELETE': { uid: 3001, name: 'Account Change', category: 'cloud_audit' },
  'CLOUD_RESOURCE_MODIFY': { uid: 3001, name: 'Account Change', category: 'cloud_audit' },
  'CLOUD_API_CALL': { uid: 3005, name: 'IAM Activity', category: 'cloud_audit' },
  'CLOUD_API_READ': { uid: 3005, name: 'IAM Activity', category: 'cloud_audit' },
  'PROCESS_CREATED': { uid: 1001, name: 'Process Activity', category: 'system_activity' },
  'PRIVILEGE_ESCALATION': { uid: 1001, name: 'Process Activity', category: 'system_activity' },
  'CONTAINER_EVENT': { uid: 4004, name: 'Container Activity', category: 'container_activity' },
  'CONTAINER_HTTP_ACCESS': { uid: 4004, name: 'Container Activity', category: 'container_activity' },
  'SERVICE_INSTALLED': { uid: 1001, name: 'Process Activity', category: 'system_activity' },
  'SPECIAL_PRIVILEGES': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'ACCOUNT_LOCKOUT': { uid: 3002, name: 'Authentication', category: 'identity_access' },
  'USER_ACCOUNT_CREATED': { uid: 3001, name: 'Account Change', category: 'identity_access' },
  'PASSWORD_RESET': { uid: 3001, name: 'Account Change', category: 'identity_access' }
};

/**
 * Run the full normalization pipeline on a single raw log line.
 */
export function normalize(rawLog, options = {}) {
  const startTime = performance.now();

  // Step 1: Detection
  const detection = detect(rawLog);

  // Step 2: Parse
  let parsed = parseAuto(rawLog);

  // Step 3: Handle parse failure
  if (!parsed) {
    parsed = {
      format: 'unknown',
      parser: 'None (Parse Failed)',
      parserType: 'NONE',
      confidence: 0,
      raw: rawLog.trim(),
      fields: {
        event_type: 'UNPARSEABLE',
        message: rawLog.trim().substring(0, 500),
        severity: 'INFO',
        category: 'unknown'
      },
      tokens: [{ text: rawLog.trim().substring(0, 80), type: 'message' }]
    };
  }

  // Step 4: Normalize timestamp
  const normalizedTimestamp = normalizeTimestamp(parsed.fields.timestamp);

  // Step 5: Map to OCSF
  const eventType = parsed.fields.event_type || 'GENERIC_EVENT';
  const ocsfClass = OCSF_CLASS_MAP[eventType] || { uid: 0, name: 'Unknown', category: 'uncategorized' };

  // Step 6: PII Masking (if enabled)
  let maskedFields = { ...parsed.fields };
  let piiDetected = [];
  if (options.enablePiiMasking !== false) {
    const maskResult = maskPII(maskedFields);
    maskedFields = maskResult.fields;
    piiDetected = maskResult.detected;
  }

  // Step 7: Clean & assemble normalized output
  const latency = (performance.now() - startTime).toFixed(3);

  const normalizedOutput = {
    // Meta
    id: uuidv4(),
    ingested_at: new Date().toISOString(),
    processing_latency_ms: parseFloat(latency),

    // Detection & Parsing
    detected_format: parsed.format || detection.format,
    detection_confidence: parsed.detection_confidence || detection.confidence,
    parser_name: parsed.parser,
    parser_type: parsed.parserType,
    parse_confidence: parsed.confidence,

    // OCSF Schema
    ocsf_class_uid: ocsfClass.uid,
    ocsf_class_name: ocsfClass.name,
    ocsf_category: ocsfClass.category,

    // Normalized fields
    event_type: eventType,
    timestamp: normalizedTimestamp,
    severity: normalizeSeverity(maskedFields.severity),
    source_ip: maskedFields.source_ip || null,
    source_port: maskedFields.source_port || null,
    destination_ip: maskedFields.destination_ip || null,
    destination_port: maskedFields.destination_port || null,
    user: maskedFields.user || null,
    host: maskedFields.host || null,
    process: maskedFields.app_name || maskedFields.process_name || null,
    protocol: maskedFields.protocol || null,
    action: maskedFields.action || maskedFields.event_type || null,
    status: maskedFields.status || maskedFields.status_code || null,
    message: maskedFields.message || maskedFields.event_description || null,
    category: maskedFields.category || ocsfClass.category,

    // Additional context
    additional_fields: extractAdditionalFields(maskedFields),

    // PII
    pii_detected: piiDetected,
    pii_masked: piiDetected.length > 0,

    // Raw data
    raw_log: options.includeRaw !== false ? rawLog.trim() : undefined,
    tokens: parsed.tokens || []
  };

  return normalizedOutput;
}

/**
 * Normalize a batch of log lines.
 */
export function normalizeBatch(lines, options = {}) {
  const startTime = performance.now();
  const results = [];
  const formatStats = {};
  const severityStats = {};
  let errorCount = 0;

  for (const line of lines) {
    if (!line || line.trim().length === 0) continue;
    try {
      const result = normalize(line, options);
      results.push(result);

      const fmt = result.detected_format || 'unknown';
      formatStats[fmt] = (formatStats[fmt] || 0) + 1;

      const sev = result.severity || 'INFO';
      severityStats[sev] = (severityStats[sev] || 0) + 1;
    } catch (err) {
      errorCount++;
      results.push({
        id: uuidv4(),
        error: err.message,
        raw_log: line.substring(0, 200),
        event_type: 'PARSE_ERROR',
        severity: 'LOW'
      });
    }
  }

  const totalLatency = (performance.now() - startTime).toFixed(3);

  return {
    results,
    summary: {
      total_lines: lines.length,
      processed: results.length,
      errors: errorCount,
      total_latency_ms: parseFloat(totalLatency),
      avg_latency_ms: results.length > 0 ? parseFloat((parseFloat(totalLatency) / results.length).toFixed(3)) : 0,
      format_distribution: formatStats,
      severity_distribution: severityStats
    }
  };
}

// --- Helpers ---

function normalizeTimestamp(ts) {
  if (!ts) return new Date().toISOString();

  // Already ISO
  if (/^\d{4}-\d{2}-\d{2}T/.test(ts)) {
    try { return new Date(ts).toISOString(); } catch { return ts; }
  }

  // BSD syslog: "Sep 14 09:21:31"
  const bsdMatch = ts.match(/^(\w{3})\s+(\d{1,2})\s+([\d:]+)$/);
  if (bsdMatch) {
    const year = new Date().getFullYear();
    try {
      const d = new Date(`${bsdMatch[1]} ${bsdMatch[2]}, ${year} ${bsdMatch[3]}`);
      if (!isNaN(d.getTime())) return d.toISOString();
    } catch { /* fall through */ }
  }

  // Apache: "14/Sep/2026:10:31:02 +0000"
  const apacheMatch = ts.match(/^(\d{2})\/(\w{3})\/(\d{4}):([\d:]+)\s+([+-]\d{4})$/);
  if (apacheMatch) {
    try {
      const d = new Date(`${apacheMatch[2]} ${apacheMatch[1]}, ${apacheMatch[3]} ${apacheMatch[4]} ${apacheMatch[5]}`);
      if (!isNaN(d.getTime())) return d.toISOString();
    } catch { /* fall through */ }
  }

  // Unix epoch
  if (/^\d{10,13}$/.test(ts)) {
    const num = parseInt(ts);
    const d = new Date(num > 9999999999 ? num : num * 1000);
    if (!isNaN(d.getTime())) return d.toISOString();
  }

  return ts; // Return as-is if we can't parse
}

function normalizeSeverity(sev) {
  if (!sev) return 'INFO';
  const s = sev.toUpperCase();
  const map = {
    'CRITICAL': 'CRITICAL', 'CRIT': 'CRITICAL', 'FATAL': 'CRITICAL', 'EMERGENCY': 'CRITICAL', 'EMERG': 'CRITICAL',
    'HIGH': 'HIGH', 'ERROR': 'HIGH', 'ERR': 'HIGH', 'SEVERE': 'HIGH',
    'MEDIUM': 'MEDIUM', 'WARN': 'MEDIUM', 'WARNING': 'MEDIUM',
    'LOW': 'LOW', 'NOTICE': 'LOW',
    'INFO': 'INFO', 'INFORMATION': 'INFO', 'DEBUG': 'INFO', 'TRACE': 'INFO'
  };
  return map[s] || 'INFO';
}

function maskPII(fields) {
  const detected = [];
  const masked = { ...fields };

  for (const [key, value] of Object.entries(masked)) {
    if (typeof value !== 'string') continue;
    for (const pattern of PII_PATTERNS) {
      if (pattern.regex.test(value)) {
        detected.push({ field: key, type: pattern.name });
        // Reset regex lastIndex
        pattern.regex.lastIndex = 0;
        masked[key] = value.replace(pattern.regex, pattern.mask);
        // Reset again after replace
        pattern.regex.lastIndex = 0;
      }
    }
  }

  return { fields: masked, detected };
}

function extractAdditionalFields(fields) {
  const coreFields = new Set([
    'event_type', 'timestamp', 'severity', 'source_ip', 'source_port',
    'destination_ip', 'destination_port', 'user', 'host', 'process',
    'protocol', 'action', 'status', 'message', 'category',
    'app_name', 'process_name', 'event_description', 'status_code'
  ]);

  const additional = {};
  for (const [key, value] of Object.entries(fields)) {
    if (!coreFields.has(key) && value !== null && value !== undefined) {
      additional[key] = value;
    }
  }
  return Object.keys(additional).length > 0 ? additional : undefined;
}
