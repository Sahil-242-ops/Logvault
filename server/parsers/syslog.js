/**
 * LOGVAULT — Syslog Parser (RFC 5424 / RFC 3164 BSD)
 * Parses Linux syslog, SSH PAM, kernel, and daemon logs
 */

// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
const RFC5424_REGEX = /^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/;

// RFC 3164 BSD: <PRI> TIMESTAMP HOSTNAME TAG: MSG  or  TIMESTAMP HOSTNAME TAG: MSG
const RFC3164_REGEX = /^(?:<(\d{1,3})>)?(\w{3}\s+\d{1,2}\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)/;

// SSH-specific patterns
const SSH_ACCEPTED = /(?:Accepted|Failed)\s+(\w+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)\s*(\w*)/;
const SSH_DISCONNECT = /Disconnected\s+from\s+(?:user\s+)?(\S+)\s+([\d.]+)\s+port\s+(\d+)/;
const SSH_INVALID_USER = /Invalid\s+user\s+(\S+)\s+from\s+([\d.]+)/;

// Sudo pattern
const SUDO_PATTERN = /(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/;

// Kernel / iptables
const IPTABLES_PATTERN = /IN=(\S*)\s+OUT=(\S*)\s+.*?SRC=([\d.]+)\s+DST=([\d.]+).*?PROTO=(\w+)(?:.*?SPT=(\d+)\s+DPT=(\d+))?/;

export function parse(raw) {
  const trimmed = raw.trim();
  const result = {
    format: 'syslog',
    parser: 'Syslog RFC 5424/3164 Parser',
    parserType: 'DETERMINISTIC',
    confidence: 1.0,
    raw: trimmed,
    fields: {},
    tokens: []
  };

  // Try RFC 5424 first
  let match = trimmed.match(RFC5424_REGEX);
  if (match) {
    const [, pri, version, timestamp, hostname, appName, procId, msgId, msg] = match;
    const facility = Math.floor(parseInt(pri) / 8);
    const severityVal = parseInt(pri) % 8;

    result.fields = {
      priority: parseInt(pri),
      facility,
      syslog_severity: severityVal,
      version: parseInt(version),
      timestamp,
      host: hostname,
      app_name: appName,
      process_id: procId !== '-' ? procId : null,
      message_id: msgId !== '-' ? msgId : null,
      message: msg
    };
    result.tokens = [
      { text: `<${pri}>`, type: 'priority' },
      { text: timestamp, type: 'timestamp' },
      { text: hostname, type: 'host' },
      { text: `${appName}[${procId}]`, type: 'process' },
      { text: msg, type: 'message' }
    ];
    parseMessageContent(result, msg, appName, hostname);
    return result;
  }

  // Try RFC 3164 BSD
  match = trimmed.match(RFC3164_REGEX);
  if (match) {
    const [, pri, timestamp, hostname, tag, pid, msg] = match;

    result.fields = {
      priority: pri ? parseInt(pri) : null,
      timestamp,
      host: hostname,
      app_name: tag,
      process_id: pid || null,
      message: msg
    };
    result.tokens = [
      { text: timestamp, type: 'timestamp' },
      { text: hostname, type: 'host' },
      { text: pid ? `${tag}[${pid}]` : tag, type: 'process' },
      { text: msg, type: 'message' }
    ];
    parseMessageContent(result, msg, tag, hostname);
    return result;
  }

  return null; // Not a syslog line
}

function parseMessageContent(result, msg, appName, hostname) {
  // SSH authentication
  const sshMatch = msg.match(SSH_ACCEPTED);
  if (sshMatch || appName === 'sshd') {
    if (sshMatch) {
      const isAccepted = msg.includes('Accepted');
      result.fields.event_type = isAccepted ? 'AUTHENTICATION_SUCCESS' : 'AUTHENTICATION_FAILURE';
      result.fields.auth_method = sshMatch[1];
      result.fields.user = sshMatch[2];
      result.fields.source_ip = sshMatch[3];
      result.fields.source_port = parseInt(sshMatch[4]);
      result.fields.protocol = sshMatch[5] || 'ssh2';
      result.fields.severity = isAccepted ? 'INFO' : 'HIGH';
      result.tokens.push(
        { text: isAccepted ? 'Accepted' : 'Failed', type: 'action' },
        { text: `for ${sshMatch[2]}`, type: 'user' },
        { text: `from ${sshMatch[3]}`, type: 'src_ip' },
        { text: `port ${sshMatch[4]}`, type: 'port' }
      );
    }

    const disconnectMatch = msg.match(SSH_DISCONNECT);
    if (disconnectMatch) {
      result.fields.event_type = 'SESSION_DISCONNECT';
      result.fields.user = disconnectMatch[1];
      result.fields.source_ip = disconnectMatch[2];
      result.fields.source_port = parseInt(disconnectMatch[3]);
      result.fields.severity = 'INFO';
    }

    const invalidMatch = msg.match(SSH_INVALID_USER);
    if (invalidMatch) {
      result.fields.event_type = 'INVALID_USER_ATTEMPT';
      result.fields.user = invalidMatch[1];
      result.fields.source_ip = invalidMatch[2];
      result.fields.severity = 'HIGH';
    }
    return;
  }

  // Sudo
  const sudoMatch = msg.match(SUDO_PATTERN);
  if (sudoMatch || appName === 'sudo') {
    if (sudoMatch) {
      result.fields.event_type = 'PRIVILEGE_ESCALATION';
      result.fields.user = sudoMatch[1];
      result.fields.tty = sudoMatch[2];
      result.fields.working_dir = sudoMatch[3];
      result.fields.target_user = sudoMatch[4];
      result.fields.command = sudoMatch[5];
      result.fields.severity = 'MEDIUM';
    }
    return;
  }

  // iptables / netfilter
  const iptMatch = msg.match(IPTABLES_PATTERN);
  if (iptMatch) {
    result.fields.event_type = 'FIREWALL_EVENT';
    result.fields.interface_in = iptMatch[1] || null;
    result.fields.interface_out = iptMatch[2] || null;
    result.fields.source_ip = iptMatch[3];
    result.fields.destination_ip = iptMatch[4];
    result.fields.protocol = iptMatch[5];
    result.fields.source_port = iptMatch[6] ? parseInt(iptMatch[6]) : null;
    result.fields.destination_port = iptMatch[7] ? parseInt(iptMatch[7]) : null;
    result.fields.severity = 'MEDIUM';
    return;
  }

  // Generic syslog message
  if (!result.fields.event_type) {
    result.fields.event_type = 'SYSTEM_EVENT';
    result.fields.severity = result.fields.severity || 'INFO';
  }
}

export function canParse(raw) {
  const trimmed = raw.trim();
  if (RFC5424_REGEX.test(trimmed)) return 0.95;
  if (RFC3164_REGEX.test(trimmed)) return 0.90;
  // Loose syslog detection
  if (/^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+/.test(trimmed)) return 0.80;
  if (/^<\d{1,3}>/.test(trimmed)) return 0.85;
  return 0;
}
