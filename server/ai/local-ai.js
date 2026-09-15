/**
 * LOGVAULT — Local AI Orchestrator
 * Coordinates AI tasks: log analysis, schema inference, event classification, explanation
 * Falls back to deterministic rules when no local model is available
 */

import modelAdapter from './model-adapter.js';
import { PROMPTS } from './prompts.js';

class LocalAI {
  constructor() {
    this.initialized = false;
  }

  /**
   * Initialize: probe for local AI models.
   */
  async init() {
    const status = await modelAdapter.probe();
    this.initialized = true;
    return status;
  }

  /**
   * Get current AI status.
   */
  getStatus() {
    return modelAdapter.getStatus();
  }

  /**
   * Analyze an unknown log line using local AI.
   * Falls back to heuristic analysis if AI is unavailable.
   */
  async analyzeLog(rawLog) {
    if (!modelAdapter.isAvailable()) {
      return this._fallbackAnalyze(rawLog);
    }

    try {
      const prompt = PROMPTS.analyzeLog(rawLog);
      const response = await modelAdapter.generate(prompt, {
        temperature: 0.1,
        maxTokens: 1024
      });

      if (response && response.text) {
        const parsed = this._safeParseJSON(response.text);
        if (parsed) {
          return {
            success: true,
            source: 'local_ai',
            model: response.model,
            provider: response.provider,
            result: parsed,
            latency_ms: response.total_duration ? Math.round(response.total_duration / 1000000) : null
          };
        }
      }

      // AI returned non-JSON — fall back
      return this._fallbackAnalyze(rawLog);
    } catch (err) {
      console.error(`[LocalAI] analyzeLog error: ${err.message}`);
      return this._fallbackAnalyze(rawLog);
    }
  }

  /**
   * Infer schema mapping for unknown format.
   */
  async inferSchema(rawLog) {
    if (!modelAdapter.isAvailable()) {
      return this._fallbackInferSchema(rawLog);
    }

    try {
      const prompt = PROMPTS.inferSchema(rawLog);
      const response = await modelAdapter.generate(prompt, {
        temperature: 0.1,
        maxTokens: 1500
      });

      if (response && response.text) {
        const parsed = this._safeParseJSON(response.text);
        if (parsed) {
          return {
            success: true,
            source: 'local_ai',
            model: response.model,
            provider: response.provider,
            result: parsed
          };
        }
      }

      return this._fallbackInferSchema(rawLog);
    } catch (err) {
      console.error(`[LocalAI] inferSchema error: ${err.message}`);
      return this._fallbackInferSchema(rawLog);
    }
  }

  /**
   * Classify a normalized event.
   */
  async classifyEvent(normalizedFields) {
    if (!modelAdapter.isAvailable()) {
      return this._fallbackClassify(normalizedFields);
    }

    try {
      const prompt = PROMPTS.classifyEvent(normalizedFields);
      const response = await modelAdapter.generate(prompt, {
        temperature: 0.1,
        maxTokens: 800
      });

      if (response && response.text) {
        const parsed = this._safeParseJSON(response.text);
        if (parsed) {
          return {
            success: true,
            source: 'local_ai',
            model: response.model,
            result: parsed
          };
        }
      }

      return this._fallbackClassify(normalizedFields);
    } catch (err) {
      return this._fallbackClassify(normalizedFields);
    }
  }

  /**
   * Explain a log entry in plain language.
   */
  async explainLog(rawLog) {
    if (!modelAdapter.isAvailable()) {
      return this._fallbackExplain(rawLog);
    }

    try {
      const prompt = PROMPTS.explainLog(rawLog);
      const response = await modelAdapter.generate(prompt, {
        temperature: 0.3,
        maxTokens: 600
      });

      if (response && response.text) {
        const parsed = this._safeParseJSON(response.text);
        if (parsed) {
          return {
            success: true,
            source: 'local_ai',
            model: response.model,
            result: parsed
          };
        }
      }

      return this._fallbackExplain(rawLog);
    } catch (err) {
      return this._fallbackExplain(rawLog);
    }
  }

  // --- Fallback Deterministic Methods ---

  _fallbackAnalyze(rawLog) {
    const trimmed = rawLog.trim();
    const ipMatch = trimmed.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const tsMatch = trimmed.match(/(\w{3}\s+\d{1,2}\s+[\d:]+)/) ||
                    trimmed.match(/(\d{4}[-/]\d{2}[-/]\d{2}[T\s][\d:]+)/);
    const userMatch = trimmed.match(/(?:user|usr|for)\s+(\S+)/i);

    let eventType = 'UNKNOWN_EVENT';
    let severity = 'INFO';
    const lower = trimmed.toLowerCase();

    if (lower.includes('fail') || lower.includes('denied') || lower.includes('error')) {
      severity = 'HIGH';
      eventType = 'FAILURE_EVENT';
    }
    if (lower.includes('success') || lower.includes('accepted') || lower.includes('granted')) {
      eventType = 'SUCCESS_EVENT';
    }
    if (lower.includes('login') || lower.includes('auth') || lower.includes('password') || lower.includes('sshd')) {
      eventType = lower.includes('fail') ? 'LOGIN_FAILURE' : 'LOGIN_SUCCESS';
    }
    if (lower.includes('drop') || lower.includes('block') || lower.includes('deny')) {
      eventType = 'FIREWALL_BLOCK';
      severity = 'MEDIUM';
    }
    if (lower.includes('alert') || lower.includes('attack') || lower.includes('intrusion') || lower.includes('scan')) {
      eventType = 'SECURITY_ALERT';
      severity = 'CRITICAL';
    }

    return {
      success: true,
      source: 'deterministic_fallback',
      model: null,
      provider: null,
      result: {
        timestamp: tsMatch ? tsMatch[1] : null,
        source: this._guessSource(trimmed),
        event_type: eventType,
        severity,
        username: userMatch ? userMatch[1] : null,
        source_ip: ipMatch ? ipMatch[1] : null,
        destination_ip: null,
        port: null,
        protocol: null,
        action: eventType.toLowerCase().replace(/_/g, ' '),
        message: trimmed.substring(0, 200),
        confidence: 0.45,
        mitre_tactic: null,
        additional_fields: {}
      }
    };
  }

  _fallbackInferSchema(rawLog) {
    const trimmed = rawLog.trim();
    const kvRegex = /([A-Za-z_]\w*)\s*=\s*(?:"([^"]*)"|(\S+))/g;
    const mappings = [];
    let m;

    while ((m = kvRegex.exec(trimmed)) !== null) {
      const key = m[1];
      const value = m[2] || m[3];
      mappings.push({
        raw_field: key,
        raw_value: value,
        ocsf_field: this._guessOCSFField(key),
        data_type: this._guessDataType(value),
        confidence: 0.50
      });
    }

    return {
      success: true,
      source: 'deterministic_fallback',
      model: null,
      result: {
        detected_format: 'Unknown / Custom Key-Value',
        field_mappings: mappings,
        suggested_ocsf_class: 'Generic Event',
        suggested_ocsf_class_uid: 0,
        overall_confidence: mappings.length > 0 ? 0.50 : 0.20,
        recommended_parser: 'generic-kv'
      }
    };
  }

  _fallbackClassify(fields) {
    let threatLevel = 'none';
    const reasons = [];

    const sev = (fields.severity || '').toUpperCase();
    if (sev === 'CRITICAL') { threatLevel = 'critical'; reasons.push('Critical severity event'); }
    else if (sev === 'HIGH') { threatLevel = 'high'; reasons.push('High severity event'); }
    else if (sev === 'MEDIUM') { threatLevel = 'medium'; }

    const et = (fields.event_type || '').toUpperCase();
    if (et.includes('FAILURE') || et.includes('DENIED')) {
      if (threatLevel === 'none') threatLevel = 'low';
      reasons.push('Authentication or access failure detected');
    }
    if (et.includes('INJECTION') || et.includes('XSS') || et.includes('TRAVERSAL')) {
      threatLevel = 'critical';
      reasons.push('Web application attack pattern detected');
    }

    return {
      success: true,
      source: 'deterministic_fallback',
      model: null,
      result: {
        threat_level: threatLevel,
        event_category: fields.category || 'general',
        is_anomalous: threatLevel === 'high' || threatLevel === 'critical',
        anomaly_reasons: reasons,
        mitre_tactics: [],
        mitre_techniques: [],
        recommended_actions: threatLevel !== 'none' ? ['Review event details', 'Check source IP reputation'] : [],
        explanation: `Deterministic rule-based classification: ${threatLevel} threat level`,
        confidence: 0.50
      }
    };
  }

  _fallbackExplain(rawLog) {
    const trimmed = rawLog.trim();
    const lower = trimmed.toLowerCase();
    let summary = 'Log entry recorded.';
    let severity = 'INFO';

    if (lower.includes('fail') || lower.includes('error')) {
      summary = 'A failure or error event was logged.';
      severity = 'MEDIUM';
    }
    if (lower.includes('password') || lower.includes('auth')) {
      summary = 'An authentication-related event occurred.';
    }
    if (lower.includes('denied') || lower.includes('blocked') || lower.includes('drop')) {
      summary = 'A network or access denial event occurred.';
      severity = 'HIGH';
    }

    return {
      success: true,
      source: 'deterministic_fallback',
      model: null,
      result: {
        summary,
        detailed_explanation: `This log entry was analyzed using deterministic rules. The raw content is: "${trimmed.substring(0, 100)}..."`,
        security_relevance: 'Requires manual review for full assessment.',
        recommended_action: 'Review in context with surrounding events.',
        severity_assessment: severity,
        false_positive_likelihood: 'medium'
      }
    };
  }

  _guessSource(raw) {
    const lower = raw.toLowerCase();
    if (lower.includes('sshd') || lower.includes('ssh')) return 'ssh';
    if (lower.includes('apache') || lower.includes('nginx') || lower.includes('http/')) return 'web';
    if (lower.includes('firewall') || lower.includes('iptables') || lower.includes('paloalto')) return 'firewall';
    if (lower.includes('windows') || lower.includes('eventid')) return 'windows';
    if (lower.includes('aws') || lower.includes('cloudtrail')) return 'cloud';
    if (lower.includes('suricata') || lower.includes('snort')) return 'ids';
    if (lower.includes('docker') || lower.includes('kubernetes') || lower.includes('k8s')) return 'container';
    return 'unknown';
  }

  _guessOCSFField(key) {
    const k = key.toLowerCase();
    if (k.includes('ip') || k === 'src' || k === 'dst') return 'source_ip';
    if (k.includes('user') || k === 'usr' || k === 'uid') return 'user';
    if (k.includes('time') || k === 'ts') return 'timestamp';
    if (k.includes('host') || k === 'dev' || k === 'server') return 'host';
    if (k.includes('port')) return 'source_port';
    if (k.includes('proto')) return 'protocol';
    if (k.includes('act') || k === 'op') return 'action';
    if (k.includes('status') || k === 'res') return 'status';
    return key;
  }

  _guessDataType(value) {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return 'IP Address';
    if (/^\d+$/.test(value)) return 'Integer';
    if (/^\d+\.\d+$/.test(value)) return 'Float';
    if (/\d{4}[-/]\d{2}[-/]\d{2}/.test(value)) return 'Timestamp';
    return 'String';
  }

  // --- JSON parsing helper ---
  _safeParseJSON(text) {
    try {
      // Try direct parse
      return JSON.parse(text);
    } catch {
      // Try extracting JSON from markdown code block
      const match = text.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (match) {
        try { return JSON.parse(match[1].trim()); } catch { /* fall through */ }
      }
      // Try finding first { ... } block
      const braceMatch = text.match(/\{[\s\S]*\}/);
      if (braceMatch) {
        try { return JSON.parse(braceMatch[0]); } catch { /* fall through */ }
      }
      return null;
    }
  }
}

// Singleton
const localAI = new LocalAI();
export default localAI;
