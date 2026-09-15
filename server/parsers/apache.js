/**
 * LOGVAULT — Apache/Nginx Web Access Log Parser
 * Parses W3C Combined, Common, and Nginx extended log formats
 */

// Combined Log Format: IP - USER [TIMESTAMP] "METHOD URL PROTO" STATUS BYTES "REFERER" "USER-AGENT"
const COMBINED_REGEX = /^([\d.]+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+(HTTP\/[\d.]+)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/;

// Common Log Format: IP - USER [TIMESTAMP] "METHOD URL PROTO" STATUS BYTES
const COMMON_REGEX = /^([\d.]+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+(HTTP\/[\d.]+)"\s+(\d{3})\s+(\d+|-)/;

// Nginx error log
const NGINX_ERROR_REGEX = /^(\d{4}\/\d{2}\/\d{2}\s+[\d:]+)\s+\[(\w+)\]\s+(\d+)#(\d+):\s*(.*)/;

export function parse(raw) {
  const trimmed = raw.trim();

  // Try Combined format first
  let match = trimmed.match(COMBINED_REGEX);
  if (match) {
    return parseCombined(trimmed, match, true);
  }

  // Try Common format
  match = trimmed.match(COMMON_REGEX);
  if (match) {
    return parseCombined(trimmed, match, false);
  }

  // Try Nginx error log
  match = trimmed.match(NGINX_ERROR_REGEX);
  if (match) {
    return parseNginxError(trimmed, match);
  }

  return null;
}

function parseCombined(raw, match, hasCombinedFields) {
  const [, ip, ident, user, timestamp, method, url, httpVersion, statusStr, bytesStr] = match;
  const referer = hasCombinedFields ? match[10] : '-';
  const userAgent = hasCombinedFields ? match[11] : '-';
  const status = parseInt(statusStr);
  const bytes = bytesStr === '-' ? 0 : parseInt(bytesStr);

  let severity = 'INFO';
  if (status >= 500) severity = 'HIGH';
  else if (status >= 400) severity = 'MEDIUM';
  else if (status >= 300) severity = 'LOW';

  let eventType = 'HTTP_REQUEST';
  if (status === 401 || status === 403) eventType = 'HTTP_AUTH_FAILURE';
  if (status >= 500) eventType = 'HTTP_SERVER_ERROR';

  // Detect potential attacks from URL
  const urlLower = url.toLowerCase();
  if (urlLower.includes('..%2f') || urlLower.includes('../') || urlLower.includes('..\\')) {
    eventType = 'PATH_TRAVERSAL_ATTEMPT';
    severity = 'CRITICAL';
  }
  if (urlLower.includes('<script') || urlLower.includes('javascript:') || urlLower.includes('%3cscript')) {
    eventType = 'XSS_ATTEMPT';
    severity = 'CRITICAL';
  }
  if (urlLower.includes("'") || urlLower.includes('union+select') || urlLower.includes('or+1=1') || urlLower.includes('%27')) {
    eventType = 'SQL_INJECTION_ATTEMPT';
    severity = 'CRITICAL';
  }

  return {
    format: 'apache',
    parser: 'Apache/Nginx Combined Log Parser',
    parserType: 'DETERMINISTIC',
    confidence: 1.0,
    raw,
    fields: {
      event_type: eventType,
      source_ip: ip,
      ident: ident !== '-' ? ident : null,
      user: user !== '-' ? user : null,
      timestamp,
      http_method: method,
      url_path: url,
      http_version: httpVersion,
      http_status_code: status,
      bytes_sent: bytes,
      referer: referer !== '-' ? referer : null,
      user_agent: userAgent !== '-' ? userAgent : null,
      severity,
      category: 'application_activity'
    },
    tokens: [
      { text: ip, type: 'src_ip' },
      { text: user !== '-' ? user : ident, type: 'user' },
      { text: `[${timestamp}]`, type: 'timestamp' },
      { text: `"${method} ${url} ${httpVersion}"`, type: 'http_request' },
      { text: statusStr, type: 'http_status' },
      { text: bytesStr, type: 'bytes' }
    ]
  };
}

function parseNginxError(raw, match) {
  const [, timestamp, level, pid, tid, message] = match;

  let severity = 'INFO';
  if (level === 'emerg' || level === 'alert' || level === 'crit') severity = 'CRITICAL';
  else if (level === 'error') severity = 'HIGH';
  else if (level === 'warn') severity = 'MEDIUM';

  return {
    format: 'nginx-error',
    parser: 'Nginx Error Log Parser',
    parserType: 'DETERMINISTIC',
    confidence: 1.0,
    raw,
    fields: {
      event_type: 'WEB_SERVER_ERROR',
      timestamp,
      log_level: level,
      process_id: parseInt(pid),
      thread_id: parseInt(tid),
      message,
      severity,
      category: 'application_activity'
    },
    tokens: [
      { text: timestamp, type: 'timestamp' },
      { text: `[${level}]`, type: 'status' },
      { text: `pid:${pid}`, type: 'process' },
      { text: message.substring(0, 80), type: 'message' }
    ]
  };
}

export function canParse(raw) {
  const trimmed = raw.trim();
  if (COMBINED_REGEX.test(trimmed)) return 0.95;
  if (COMMON_REGEX.test(trimmed)) return 0.90;
  if (NGINX_ERROR_REGEX.test(trimmed)) return 0.85;
  // Loose detection: starts with IP and has HTTP method
  if (/^[\d.]+\s+\S+\s+\S+\s+\[/.test(trimmed) && /\"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/.test(trimmed)) return 0.75;
  return 0;
}
