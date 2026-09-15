/**
 * LOGVAULT — Generic Key-Value Fallback Parser
 * Handles any delimiter-separated key=value log formats, positional fields, and unstructured text
 */

const KV_PAIR_REGEX = /([A-Za-z_][\w.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/g;

export function parse(raw) {
  const trimmed = raw.trim();
  const pairs = extractKVPairs(trimmed);
  const pairCount = Object.keys(pairs).length;

  if (pairCount === 0) {
    // Try space/tab delimited positional parsing
    return parsePositional(trimmed);
  }

  const fields = mapKVToSchema(pairs);

  return {
    format: 'generic-kv',
    parser: 'Generic Key-Value Parser',
    parserType: 'HEURISTIC',
    confidence: Math.min(0.60 + pairCount * 0.05, 0.90),
    raw: trimmed,
    fields: {
      event_type: fields.event_type || 'GENERIC_EVENT',
      timestamp: fields.timestamp || null,
      source_ip: fields.source_ip || null,
      destination_ip: fields.destination_ip || null,
      user: fields.user || null,
      host: fields.host || null,
      action: fields.action || null,
      status: fields.status || null,
      protocol: fields.protocol || null,
      port: fields.port || null,
      severity: fields.severity || 'INFO',
      message: fields.message || trimmed.substring(0, 200),
      category: 'general_telemetry',
      raw_pairs: pairs
    },
    tokens: Object.entries(pairs).slice(0, 10).map(([k, v]) => ({
      text: `${k}=${v}`,
      type: guessFieldType(k)
    }))
  };
}

function extractKVPairs(str) {
  const pairs = {};
  let match;
  const regex = new RegExp(KV_PAIR_REGEX.source, 'g');
  while ((match = regex.exec(str)) !== null) {
    pairs[match[1]] = match[2] || match[3] || match[4];
  }
  return pairs;
}

function mapKVToSchema(pairs) {
  const result = {};
  for (const [key, value] of Object.entries(pairs)) {
    const k = key.toLowerCase();

    // Timestamp
    if (k === 'ts' || k === 'time' || k === 'timestamp' || k === 'datetime' || k === 'date') {
      result.timestamp = value;
    }
    // Source IP
    else if (k === 'src' || k === 'src_ip' || k === 'source' || k === 'sourceip' || k === 'sip' || k === 'client_ip') {
      result.source_ip = value;
    }
    // Destination IP
    else if (k === 'dst' || k === 'dst_ip' || k === 'dest' || k === 'destip' || k === 'dip' || k === 'target_ip') {
      result.destination_ip = value;
    }
    // User
    else if (k === 'usr' || k === 'user' || k === 'username' || k === 'uname' || k === 'uid' || k === 'account') {
      result.user = value;
    }
    // Host
    else if (k === 'host' || k === 'hostname' || k === 'dev' || k === 'device' || k === 'node' || k === 'server') {
      result.host = value;
    }
    // Action / Event type
    else if (k === 'act' || k === 'action' || k === 'event' || k === 'evt' || k === 'type' || k === 'op' || k === 'operation') {
      result.action = value;
      result.event_type = value.toUpperCase().replace(/\s+/g, '_');
    }
    // Status
    else if (k === 'res' || k === 'result' || k === 'status' || k === 'stat' || k === 'state' || k === 'outcome') {
      result.status = value;
    }
    // Protocol
    else if (k === 'proto' || k === 'protocol' || k === 'prot') {
      result.protocol = value;
    }
    // Port
    else if (k === 'port' || k === 'dpt' || k === 'spt' || k === 'dst_port' || k === 'src_port') {
      result.port = value;
    }
    // Severity
    else if (k === 'sev' || k === 'severity' || k === 'level' || k === 'priority' || k === 'pri') {
      result.severity = mapSeverity(value);
    }
    // Message
    else if (k === 'msg' || k === 'message' || k === 'desc' || k === 'description' || k === 'log') {
      result.message = value;
    }
  }
  return result;
}

function parsePositional(raw) {
  // Try to find any IPs, timestamps, or known tokens in unstructured text
  const ipMatch = raw.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  const timestampMatch = raw.match(/\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}/) ||
                          raw.match(/\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/);
  const words = raw.split(/\s+/);

  return {
    format: 'unstructured',
    parser: 'Unstructured Text Fallback Parser',
    parserType: 'HEURISTIC',
    confidence: 0.30,
    raw,
    fields: {
      event_type: 'UNSTRUCTURED_EVENT',
      timestamp: timestampMatch ? timestampMatch[0] : null,
      source_ip: ipMatch ? ipMatch[1] : null,
      message: raw.substring(0, 500),
      word_count: words.length,
      severity: 'INFO',
      category: 'unknown'
    },
    tokens: [
      ...(timestampMatch ? [{ text: timestampMatch[0], type: 'timestamp' }] : []),
      ...(ipMatch ? [{ text: ipMatch[1], type: 'src_ip' }] : []),
      { text: raw.substring(0, 60), type: 'message' }
    ]
  };
}

function guessFieldType(key) {
  const k = key.toLowerCase();
  if (k.includes('ip') || k === 'src' || k === 'dst' || k === 'source' || k === 'dest') return 'src_ip';
  if (k.includes('time') || k === 'ts' || k === 'date') return 'timestamp';
  if (k.includes('user') || k === 'usr' || k === 'uid') return 'user';
  if (k.includes('host') || k === 'dev' || k === 'server') return 'host';
  if (k.includes('act') || k.includes('event') || k === 'op') return 'action';
  if (k.includes('status') || k === 'res' || k === 'result') return 'status';
  if (k.includes('port')) return 'port';
  if (k.includes('proto')) return 'protocol';
  return 'message';
}

function mapSeverity(val) {
  const v = val.toUpperCase();
  if (['CRITICAL', 'CRIT', 'FATAL', 'EMERGENCY', 'EMERG', 'ALERT'].includes(v)) return 'CRITICAL';
  if (['HIGH', 'ERROR', 'ERR', 'SEVERE'].includes(v)) return 'HIGH';
  if (['MEDIUM', 'WARN', 'WARNING', 'CAUTION'].includes(v)) return 'MEDIUM';
  if (['LOW', 'NOTICE', 'NOTE'].includes(v)) return 'LOW';
  if (['INFO', 'INFORMATION', 'DEBUG', 'TRACE'].includes(v)) return 'INFO';
  return 'INFO';
}

export function canParse(raw) {
  // This is the fallback parser — it always returns a low score
  const trimmed = raw.trim();
  const pairs = extractKVPairs(trimmed);
  const pairCount = Object.keys(pairs).length;
  if (pairCount >= 3) return 0.50;
  if (pairCount >= 1) return 0.30;
  return 0.15; // Can always attempt unstructured parsing
}
