INVESTIGATE_PROMPT = """You are a SOC Tier-2 analyst investigating a security alert from an air-gapped network.
Use ONLY the evidence below. Decide if the alert is a real attack.
Return ONLY valid JSON, no markdown, with exactly these keys:
{
  "verdict": "TRUE_POSITIVE" | "SUSPICIOUS" | "FALSE_POSITIVE",
  "confidence": number between 0 and 1,
  "summary": "one or two sentences describing what happened",
  "root_cause": "one sentence on the likely cause",
  "attack_stage": "MITRE ATT&CK tactic name or 'None'",
  "recommended_actions": ["short imperative action", "..."]
}

ALERT:
{alert}

RULE FINDINGS:
{findings}

CORRELATED ACTIVITY (same source IP / user / host):
{correlation}

RECENT RELATED EVENTS:
{related}
"""

PARSE_PROMPT = """You are a cybersecurity log parsing assistant.
Analyze the following raw log and extract fields into JSON format.
Only return valid JSON, nothing else. Do not wrap in markdown blocks.

Raw Log: {raw_log}

JSON Schema:
{
    "event_type": "string",
    "user": "string",
    "source_ip": "string",
    "destination_ip": "string",
    "action": "string",
    "status": "string",
    "process": "string",
    "message": "string"
}
"""
