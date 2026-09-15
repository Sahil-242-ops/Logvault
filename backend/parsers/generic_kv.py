import re
from typing import Dict, Any

class GenericKVParser:
    def __init__(self):
        # Match key=value where value can be quoted
        self.kv_pattern = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|(\S+))')

    def parse(self, raw_log: str) -> Dict[str, Any]:
        matches = self.kv_pattern.findall(raw_log)
        if not matches:
            return None
            
        data = {}
        for match in matches:
            key = match[0].lower()
            val = match[1] if match[1] else match[2]
            
            if key in ['src', 'ip', 'src_ip']: data['source_ip'] = val
            elif key in ['dst', 'dst_ip']: data['destination_ip'] = val
            elif key in ['usr', 'user', 'username']: data['user'] = val
            elif key in ['act', 'action', 'event']: data['action'] = val
            elif key in ['res', 'status', 'result']: data['status'] = val
            else: data[key] = val
            
        data['event_type'] = "GENERIC_EVENT"
        return data
