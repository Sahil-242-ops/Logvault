/**
 * LOGVAULT — Rule-Based Anomaly Detection Engine
 * Shannon entropy, regex threat rules, rate analysis, MITRE ATT&CK tagging
 */

// --- Shannon Entropy Calculator ---
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(4));
}

// --- Threat Detection Rules ---
const THREAT_RULES = [
  {
    id: 'RULE-001',
    name: 'SQL Injection Attempt',
    severity: 'CRITICAL',
    mitre_tactic: 'Initial Access',
    mitre_technique: 'T1190 - Exploit Public-Facing Application',
    patterns: [
      /(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)/i,
      /(?:'|\%27)\s*(?:or|and)\s+/i,
      /(?:1\s*=\s*1|1\s*=\s*'1')/i,
      /(?:exec\s*\(|execute\s+|xp_cmdshell)/i
    ]
  },
  {
    id: 'RULE-002',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'CRITICAL',
    mitre_tactic: 'Initial Access',
    mitre_technique: 'T1189 - Drive-by Compromise',
    patterns: [
      /<script[^>]*>/i,
      /javascript\s*:/i,
      /on(?:error|load|click|mouseover)\s*=/i,
      /%3cscript/i
    ]
  },
  {
    id: 'RULE-003',
    name: 'Path Traversal / Directory Traversal',
    severity: 'HIGH',
    mitre_tactic: 'Collection',
    mitre_technique: 'T1005 - Data from Local System',
    patterns: [
      /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)/i,
      /(?:\/etc\/passwd|\/etc\/shadow|\/proc\/self)/i,
      /(?:c:\\windows\\|c:\\boot\.ini)/i
    ]
  },
  {
    id: 'RULE-004',
    name: 'Brute Force Authentication',
    severity: 'HIGH',
    mitre_tactic: 'Credential Access',
    mitre_technique: 'T1110 - Brute Force',
    patterns: [
      /(?:failed\s+password|authentication\s+failure|login\s+fail)/i,
      /(?:invalid\s+user|illegal\s+user|unknown\s+user)/i,
      /(?:account\s+locked|too\s+many\s+attempts)/i
    ]
  },
  {
    id: 'RULE-005',
    name: 'Suspicious Command Execution',
    severity: 'HIGH',
    mitre_tactic: 'Execution',
    mitre_technique: 'T1059 - Command and Scripting Interpreter',
    patterns: [
      /(?:powershell|cmd\.exe|bash\s+-c|sh\s+-c)/i,
      /(?:wget|curl|nc\s+-|netcat)/i,
      /(?:base64\s+-d|echo\s+.*\|\s*base64)/i,
      /(?:chmod\s+777|chmod\s+\+x)/i
    ]
  },
  {
    id: 'RULE-006',
    name: 'Privilege Escalation Attempt',
    severity: 'CRITICAL',
    mitre_tactic: 'Privilege Escalation',
    mitre_technique: 'T1548 - Abuse Elevation Control Mechanism',
    patterns: [
      /(?:sudo\s+su|su\s+-\s+root)/i,
      /(?:EventID[=:]?\s*4672|EventID[=:]?\s*4728)/i,
      /(?:\/etc\/sudoers|visudo)/i
    ]
  },
  {
    id: 'RULE-007',
    name: 'Data Exfiltration Indicator',
    severity: 'HIGH',
    mitre_tactic: 'Exfiltration',
    mitre_technique: 'T1041 - Exfiltration Over C2 Channel',
    patterns: [
      /(?:scp\s+.*@|rsync\s+.*@)/i,
      /(?:\.zip|\.tar\.gz|\.7z|\.rar)\s/i
    ]
  },
  {
    id: 'RULE-008',
    name: 'Known Malicious IP / Tor Exit Node',
    severity: 'CRITICAL',
    mitre_tactic: 'Command and Control',
    mitre_technique: 'T1090 - Proxy',
    patterns: [
      /(?:185\.220\.101\.\d+|198\.51\.100\.\d+)/,  // Example known-bad ranges
      /(?:tor\s+exit|onion\s+routing|anonymi)/i
    ]
  },
  {
    id: 'RULE-009',
    name: 'DNS Beaconing / DGA Detection',
    severity: 'HIGH',
    mitre_tactic: 'Command and Control',
    mitre_technique: 'T1568 - Dynamic Resolution',
    patterns: [
      /(?:dns.*query.*[a-z0-9]{20,})/i
    ]
  },
  {
    id: 'RULE-010',
    name: 'Service Installation / Persistence',
    severity: 'HIGH',
    mitre_tactic: 'Persistence',
    mitre_technique: 'T1543 - Create or Modify System Process',
    patterns: [
      /(?:EventID[=:]?\s*7045|EventID[=:]?\s*4697)/i,
      /(?:systemctl\s+enable|crontab\s+-e|at\s+\d)/i
    ]
  }
];

/**
 * Analyze a normalized log event for anomalies.
 */
export function detectAnomalies(normalizedEvent) {
  const findings = [];

  // 1. Rule-based threat detection
  const raw = normalizedEvent.raw_log || '';
  const message = normalizedEvent.message || '';
  const combined = `${raw} ${message}`;

  for (const rule of THREAT_RULES) {
    for (const pattern of rule.patterns) {
      if (pattern.test(combined)) {
        findings.push({
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          mitre_tactic: rule.mitre_tactic,
          mitre_technique: rule.mitre_technique,
          matched_pattern: pattern.source.substring(0, 60),
          type: 'threat_rule'
        });
        break; // One match per rule is sufficient
      }
    }
  }

  // 2. Shannon entropy analysis (detect encoded/obfuscated content)
  const entropy = shannonEntropy(raw);
  if (entropy > 5.5) {
    findings.push({
      rule_id: 'ENTROPY-001',
      rule_name: 'High Entropy Content Detected',
      severity: entropy > 6.5 ? 'CRITICAL' : 'HIGH',
      entropy_score: entropy,
      type: 'entropy',
      mitre_tactic: 'Defense Evasion',
      mitre_technique: 'T1027 - Obfuscated Files or Information'
    });
  }

  // 3. URL-based anomalies
  const url = normalizedEvent.url_path || normalizedEvent.additional_fields?.url_path || '';
  if (url) {
    const urlEntropy = shannonEntropy(url);
    if (urlEntropy > 4.5 && url.length > 50) {
      findings.push({
        rule_id: 'URL-ENTROPY-001',
        rule_name: 'Suspicious High-Entropy URL',
        severity: 'MEDIUM',
        entropy_score: urlEntropy,
        url: url.substring(0, 100),
        type: 'url_anomaly'
      });
    }
  }

  // 4. Severity escalation check
  const eventType = (normalizedEvent.event_type || '').toUpperCase();
  if (eventType.includes('FAILURE') || eventType.includes('DENIED') || eventType.includes('BLOCKED')) {
    const existingFailure = findings.find(f => f.rule_id === 'RULE-004');
    if (!existingFailure) {
      findings.push({
        rule_id: 'SEV-001',
        rule_name: 'Access Denial Event',
        severity: 'LOW',
        type: 'severity_flag',
        mitre_tactic: null,
        mitre_technique: null
      });
    }
  }

  // 5. Compute overall threat score
  const maxSeverityScore = Math.max(
    ...findings.map(f => ({ 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 }[f.severity] || 0)),
    0
  );

  return {
    event_id: normalizedEvent.id,
    is_anomalous: findings.length > 0 && maxSeverityScore >= 3,
    threat_score: Math.min(maxSeverityScore * 20, 100),
    findings_count: findings.length,
    max_severity: findings.length > 0 ? findings[0].severity : 'NONE',
    entropy: shannonEntropy(raw),
    findings
  };
}

/**
 * Analyze a batch of normalized events.
 */
export function detectBatchAnomalies(normalizedEvents) {
  const results = normalizedEvents.map(event => detectAnomalies(event));
  const anomalous = results.filter(r => r.is_anomalous);

  return {
    results,
    summary: {
      total: results.length,
      anomalous: anomalous.length,
      clean: results.length - anomalous.length,
      critical: results.filter(r => r.max_severity === 'CRITICAL').length,
      high: results.filter(r => r.max_severity === 'HIGH').length,
      medium: results.filter(r => r.max_severity === 'MEDIUM').length
    }
  };
}
