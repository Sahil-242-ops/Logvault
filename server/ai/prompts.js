/**
 * LOGVAULT — AI Prompt Templates
 * Structured prompts for local LLM log analysis
 * All prompts return structured JSON — no free-form chat
 */

export const PROMPTS = {
  /**
   * Analyze an unknown log line and extract structured fields.
   */
  analyzeLog: (rawLog) => `You are a cybersecurity log analysis engine. Analyze the following log entry and extract structured fields.

RULES:
1. Return ONLY valid JSON, no markdown, no explanation.
2. Extract all identifiable fields.
3. Classify the event type.
4. Assign a severity level: INFO, LOW, MEDIUM, HIGH, or CRITICAL.
5. If a field cannot be determined, set it to null.

LOG ENTRY:
${rawLog}

Return JSON with this exact structure:
{
  "timestamp": "<ISO 8601 or extracted timestamp>",
  "source": "<log source system>",
  "event_type": "<classified event type>",
  "severity": "<INFO|LOW|MEDIUM|HIGH|CRITICAL>",
  "username": "<extracted username or null>",
  "source_ip": "<extracted source IP or null>",
  "destination_ip": "<extracted destination IP or null>",
  "port": <extracted port number or null>,
  "protocol": "<extracted protocol or null>",
  "action": "<what happened>",
  "message": "<human readable summary>",
  "confidence": <0.0 to 1.0>,
  "mitre_tactic": "<MITRE ATT&CK tactic if applicable or null>",
  "additional_fields": {}
}`,

  /**
   * Infer schema mapping for unknown log format fields.
   */
  inferSchema: (rawLog) => `You are a log schema mapping engine. Given the following unknown log format, infer the field names and their OCSF (Open Cybersecurity Schema Framework) mappings.

RULES:
1. Return ONLY valid JSON, no markdown, no explanation.
2. Map each detected field to an OCSF standard field name.
3. Assign confidence to each mapping.

LOG ENTRY:
${rawLog}

Return JSON with this exact structure:
{
  "detected_format": "<format description>",
  "field_mappings": [
    {
      "raw_field": "<field name or position>",
      "raw_value": "<extracted value>",
      "ocsf_field": "<mapped OCSF field name>",
      "data_type": "<String|Integer|IP Address|Timestamp|Enum|Float>",
      "confidence": <0.0 to 1.0>
    }
  ],
  "suggested_ocsf_class": "<OCSF class name>",
  "suggested_ocsf_class_uid": <class UID number>,
  "overall_confidence": <0.0 to 1.0>,
  "recommended_parser": "<parser type recommendation>"
}`,

  /**
   * Classify an event and provide threat assessment.
   */
  classifyEvent: (normalizedFields) => `You are a SOC threat classification engine. Given the following normalized log event fields, classify the threat level and provide assessment.

RULES:
1. Return ONLY valid JSON, no markdown, no explanation.
2. Assess based on the fields provided.

EVENT FIELDS:
${JSON.stringify(normalizedFields, null, 2)}

Return JSON with this exact structure:
{
  "threat_level": "<none|low|medium|high|critical>",
  "event_category": "<category>",
  "is_anomalous": <true|false>,
  "anomaly_reasons": ["<reason1>", "<reason2>"],
  "mitre_tactics": ["<tactic1>"],
  "mitre_techniques": ["<technique1>"],
  "recommended_actions": ["<action1>", "<action2>"],
  "explanation": "<brief human-readable explanation>",
  "confidence": <0.0 to 1.0>
}`,

  /**
   * Explain a log entry in plain language.
   */
  explainLog: (rawLog) => `You are a cybersecurity analyst. Explain the following log entry in clear, plain language suitable for a security operations center analyst.

RULES:
1. Return ONLY valid JSON, no markdown, no explanation.
2. Be concise but thorough.

LOG ENTRY:
${rawLog}

Return JSON with this exact structure:
{
  "summary": "<one-line summary>",
  "detailed_explanation": "<2-3 sentence explanation>",
  "security_relevance": "<why this matters for security>",
  "recommended_action": "<what should an analyst do>",
  "severity_assessment": "<INFO|LOW|MEDIUM|HIGH|CRITICAL>",
  "false_positive_likelihood": "<low|medium|high>"
}`
};
