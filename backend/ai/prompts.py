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
