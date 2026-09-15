import json
from typing import Dict, Any

class JSONParser:
    def parse(self, raw_log: str) -> Dict[str, Any]:
        try:
            data = json.loads(raw_log)
            if isinstance(data, dict):
                # Basic mapping for known cloud schemas (CloudTrail etc)
                if 'eventName' in data:
                    data['action'] = data['eventName']
                if 'sourceIPAddress' in data:
                    data['source_ip'] = data['sourceIPAddress']
                if 'userIdentity' in data and isinstance(data['userIdentity'], dict):
                    data['user'] = data['userIdentity'].get('userName', 'unknown')
                    
                data['event_type'] = "JSON_EVENT"
                return data
            return None
        except json.JSONDecodeError:
            return None
