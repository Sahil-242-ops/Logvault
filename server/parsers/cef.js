/**
 * LOGVAULT — CEF Parser (ArcSight Common Event Format)
 * Parses CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
 */

const CEF_HEADER_REGEX = /^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)/;

// Extension key=value pairs (handles quoted values and spaces)
function parseExtensions(extStr) {
  const extensions = {};
  const regex = /(\w+)=((?:[^\s=]+(?:\s+(?!\w+=))?)*)/g;
  let m;
  while ((m = regex.exec(extStr)) !== null) {
    extensions[m[1]] = m[2].trim();
  }
  return extensions;
}

export function parse(raw) {
  const trimmed = raw.trim();
  const match = trimmed.match(CEF_HEADER_REGEX);
  if (!match) return null;

  const [, version, vendor, product, prodVersion, signatureId, name, severity, extStr] = match;
  const extensions = parseExtensions(extStr);

  const sevNum = parseInt(severity);
  let sevLabel = 'INFO';
  if (sevNum >= 9) sevLabel = 'CRITICAL';
  else if (sevNum >= 7) sevLabel = 'HIGH';
  else if (sevNum >= 4) sevLabel = 'MEDIUM';
  else if (sevNum >= 1) sevLabel = 'LOW';

  const result = {
    format: 'cef',
    parser: 'CEF ArcSight Parser',
    parserType: 'DETERMINISTIC',
    confidence: 1.0,
    raw: trimmed,
    fields: {
      cef_version: parseInt(version),
      device_vendor: vendor,
      device_product: product,
      device_version: prodVersion,
      signature_id: signatureId,
      event_name: name,
      cef_severity: sevNum,
      severity: sevLabel,
      event_type: mapCefEventType(signatureId, name),
      source_ip: extensions.src || extensions.sourceAddress || null,
      destination_ip: extensions.dst || extensions.destinationAddress || null,
      source_port: extensions.spt ? parseInt(extensions.spt) : null,
      destination_port: extensions.dpt ? parseInt(extensions.dpt) : null,
      protocol: extensions.proto || extensions.transportProtocol || null,
      action: extensions.act || extensions.deviceAction || null,
      user: extensions.suser || extensions.duser || null,
      application: extensions.app || null,
      bytes_in: extensions.bytesIn ? parseInt(extensions.bytesIn) : null,
      bytes_out: extensions.bytesOut ? parseInt(extensions.bytesOut) : null,
      message: extensions.msg || name,
      extensions
    },
    tokens: [
      { text: `CEF:${version}`, type: 'version' },
      { text: `${vendor}|${product}|${prodVersion}`, type: 'vendor' },
      { text: `${signatureId}|${name}|${severity}`, type: 'action' },
      ...(extensions.src ? [{ text: `src=${extensions.src}`, type: 'src_ip' }] : []),
      ...(extensions.dst ? [{ text: `dst=${extensions.dst}`, type: 'dst_ip' }] : []),
      ...(extensions.spt ? [{ text: `spt=${extensions.spt}`, type: 'port' }] : []),
      ...(extensions.dpt ? [{ text: `dpt=${extensions.dpt}`, type: 'port' }] : []),
      ...(extensions.act ? [{ text: `act=${extensions.act}`, type: 'status' }] : []),
      ...(extensions.proto ? [{ text: `proto=${extensions.proto}`, type: 'protocol' }] : [])
    ]
  };

  return result;
}

function mapCefEventType(sigId, name) {
  const nameLower = (name || '').toLowerCase();
  if (nameLower.includes('drop') || nameLower.includes('deny') || nameLower.includes('block')) return 'FIREWALL_DENY';
  if (nameLower.includes('allow') || nameLower.includes('accept') || nameLower.includes('permit')) return 'FIREWALL_ALLOW';
  if (nameLower.includes('traffic')) return 'NETWORK_TRAFFIC';
  if (nameLower.includes('threat') || nameLower.includes('alert')) return 'THREAT_DETECTION';
  if (nameLower.includes('auth') || nameLower.includes('login')) return 'AUTHENTICATION';
  return 'NETWORK_EVENT';
}

export function canParse(raw) {
  const trimmed = raw.trim();
  if (CEF_HEADER_REGEX.test(trimmed)) return 0.98;
  if (trimmed.startsWith('CEF:')) return 0.90;
  return 0;
}
