/**
 * LOGVAULT — Windows Event Log Parser
 * Parses Windows Security XML Event Log and KV-style EventLog formats
 */

// Windows XML Event Log patterns
const EVENT_ID_XML = /<EventID[^>]*>(\d+)<\/EventID>/;
const COMPUTER_XML = /<Computer>([^<]+)<\/Computer>/;
const TIME_CREATED_XML = /SystemTime="([^"]+)"/;
const PROVIDER_XML = /<Provider\s+Name="([^"]+)"/;
const CHANNEL_XML = /<Channel>([^<]+)<\/Channel>/;
const LEVEL_XML = /<Level>(\d+)<\/Level>/;
const DATA_XML = /<Data\s+Name="([^"]+)"[^>]*>([^<]*)<\/Data>/g;

// Windows KV-style format
const WINDOWS_KV_REGEX = /EventID=(\d+)\s+/;

// Well-known Windows Security Event IDs
const EVENT_ID_MAP = {
  4624: { type: 'LOGON_SUCCESS', severity: 'INFO', description: 'Successful account logon' },
  4625: { type: 'LOGON_FAILURE', severity: 'HIGH', description: 'Failed account logon' },
  4634: { type: 'LOGOFF', severity: 'INFO', description: 'Account logoff' },
  4648: { type: 'EXPLICIT_LOGON', severity: 'MEDIUM', description: 'Logon using explicit credentials' },
  4656: { type: 'OBJECT_ACCESS_REQUEST', severity: 'MEDIUM', description: 'Handle to object requested' },
  4663: { type: 'OBJECT_ACCESS', severity: 'MEDIUM', description: 'Attempt to access object' },
  4672: { type: 'SPECIAL_PRIVILEGES', severity: 'HIGH', description: 'Special privileges assigned to new logon' },
  4688: { type: 'PROCESS_CREATED', severity: 'INFO', description: 'New process created' },
  4689: { type: 'PROCESS_TERMINATED', severity: 'INFO', description: 'Process exited' },
  4697: { type: 'SERVICE_INSTALLED', severity: 'HIGH', description: 'Service installed in system' },
  4698: { type: 'SCHEDULED_TASK_CREATED', severity: 'MEDIUM', description: 'Scheduled task created' },
  4720: { type: 'USER_ACCOUNT_CREATED', severity: 'MEDIUM', description: 'User account created' },
  4722: { type: 'USER_ACCOUNT_ENABLED', severity: 'MEDIUM', description: 'User account enabled' },
  4724: { type: 'PASSWORD_RESET', severity: 'MEDIUM', description: 'Password reset attempt' },
  4728: { type: 'MEMBER_ADDED_SECURITY_GROUP', severity: 'HIGH', description: 'Member added to security-enabled global group' },
  4732: { type: 'MEMBER_ADDED_LOCAL_GROUP', severity: 'HIGH', description: 'Member added to security-enabled local group' },
  4740: { type: 'ACCOUNT_LOCKOUT', severity: 'HIGH', description: 'User account locked out' },
  4768: { type: 'KERBEROS_TGT_REQUEST', severity: 'INFO', description: 'Kerberos TGT requested' },
  4769: { type: 'KERBEROS_SERVICE_TICKET', severity: 'INFO', description: 'Kerberos service ticket requested' },
  4776: { type: 'CREDENTIAL_VALIDATION', severity: 'INFO', description: 'Domain controller credential validation' },
  7045: { type: 'SERVICE_INSTALLED', severity: 'HIGH', description: 'New service installed' }
};

export function parse(raw) {
  const trimmed = raw.trim();

  // Try XML format first
  if (trimmed.includes('<Event') || trimmed.includes('<EventID')) {
    return parseXML(trimmed);
  }

  // Try KV format
  if (WINDOWS_KV_REGEX.test(trimmed)) {
    return parseKV(trimmed);
  }

  return null;
}

function parseXML(raw) {
  const eventIdMatch = raw.match(EVENT_ID_XML);
  if (!eventIdMatch) return null;

  const eventId = parseInt(eventIdMatch[1]);
  const computerMatch = raw.match(COMPUTER_XML);
  const timeMatch = raw.match(TIME_CREATED_XML);
  const providerMatch = raw.match(PROVIDER_XML);
  const channelMatch = raw.match(CHANNEL_XML);
  const levelMatch = raw.match(LEVEL_XML);

  // Extract all Data fields
  const dataFields = {};
  let dataMatch;
  const dataRegex = /<Data\s+Name="([^"]+)"[^>]*>([^<]*)<\/Data>/g;
  while ((dataMatch = dataRegex.exec(raw)) !== null) {
    dataFields[dataMatch[1]] = dataMatch[2];
  }

  const eventInfo = EVENT_ID_MAP[eventId] || { type: `WINDOWS_EVENT_${eventId}`, severity: 'INFO', description: `Windows Event ${eventId}` };

  const result = {
    format: 'windows',
    parser: 'Windows Security EventLog XML Parser',
    parserType: 'DETERMINISTIC',
    confidence: 1.0,
    raw,
    fields: {
      event_type: eventInfo.type,
      windows_event_id: eventId,
      event_description: eventInfo.description,
      host: computerMatch ? computerMatch[1] : null,
      timestamp: timeMatch ? timeMatch[1] : null,
      provider_name: providerMatch ? providerMatch[1] : null,
      channel: channelMatch ? channelMatch[1] : null,
      level: levelMatch ? parseInt(levelMatch[1]) : null,
      target_user: dataFields.TargetUserName || dataFields.SubjectUserName || null,
      target_domain: dataFields.TargetDomainName || dataFields.SubjectDomainName || null,
      source_ip: dataFields.IpAddress || dataFields.SourceAddress || null,
      source_port: dataFields.IpPort ? parseInt(dataFields.IpPort) : null,
      logon_type: dataFields.LogonType ? parseInt(dataFields.LogonType) : null,
      status_code: dataFields.Status || null,
      sub_status: dataFields.SubStatus || null,
      process_name: dataFields.ProcessName || dataFields.NewProcessName || null,
      process_id: dataFields.ProcessId || dataFields.NewProcessId || null,
      command_line: dataFields.CommandLine || null,
      service_name: dataFields.ServiceName || null,
      severity: eventInfo.severity,
      category: 'identity_access',
      data_fields: dataFields
    },
    tokens: [
      { text: `EventID:${eventId}`, type: 'action' },
      { text: computerMatch ? computerMatch[1] : 'N/A', type: 'host' },
      { text: `User:${dataFields.TargetUserName || dataFields.SubjectUserName || 'N/A'}`, type: 'user' },
      ...(dataFields.IpAddress ? [{ text: `IP:${dataFields.IpAddress}`, type: 'src_ip' }] : []),
      ...(dataFields.Status ? [{ text: `Status:${dataFields.Status}`, type: 'status' }] : [])
    ]
  };

  return result;
}

function parseKV(raw) {
  const pairs = {};
  const kvRegex = /(\w+)=([^\s]+)/g;
  let m;
  while ((m = kvRegex.exec(raw)) !== null) {
    pairs[m[1]] = m[2];
  }

  const eventId = parseInt(pairs.EventID);
  const eventInfo = EVENT_ID_MAP[eventId] || { type: `WINDOWS_EVENT_${eventId}`, severity: 'INFO', description: `Windows Event ${eventId}` };

  return {
    format: 'windows-kv',
    parser: 'Windows EventLog KV Parser',
    parserType: 'DETERMINISTIC',
    confidence: 0.95,
    raw,
    fields: {
      event_type: eventInfo.type,
      windows_event_id: eventId,
      event_description: eventInfo.description,
      user: pairs.AccountName || pairs.TargetUserName || pairs.SubjectUserName || null,
      host: pairs.Workstation || pairs.Computer || null,
      source_ip: pairs.SourceIP || pairs.IpAddress || null,
      status_code: pairs.Status || null,
      severity: eventInfo.severity,
      category: 'identity_access',
      raw_pairs: pairs
    },
    tokens: [
      { text: `EventID=${eventId}`, type: 'action' },
      { text: `Account=${pairs.AccountName || 'N/A'}`, type: 'user' },
      { text: `Workstation=${pairs.Workstation || 'N/A'}`, type: 'host' },
      ...(pairs.SourceIP ? [{ text: `SourceIP=${pairs.SourceIP}`, type: 'src_ip' }] : []),
      ...(pairs.Status ? [{ text: `Status=${pairs.Status}`, type: 'status' }] : [])
    ]
  };
}

export function canParse(raw) {
  const trimmed = raw.trim();
  if (trimmed.includes('<EventID') && trimmed.includes('</Event')) return 0.95;
  if (trimmed.includes('<Event xmlns="http://schemas.microsoft.com/win')) return 0.98;
  if (WINDOWS_KV_REGEX.test(trimmed) && (trimmed.includes('AccountName') || trimmed.includes('Workstation'))) return 0.85;
  if (/EventID=\d+/.test(trimmed)) return 0.70;
  return 0;
}
