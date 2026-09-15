import re
from typing import Dict, Any

class ApacheParser:
    def __init__(self):
        self.pattern = re.compile(
            r'^(?P<source_ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/(?P<http_version>[\d.]+)"\s+(?P<status_code>\d+)\s+(?P<bytes>\d+)'
        )

    def parse(self, raw_log: str) -> Dict[str, Any]:
        match = self.pattern.match(raw_log)
        if not match:
            return None
            
        data = match.groupdict()
        data['action'] = data.get('method')
        data['status'] = int(data.get('status_code')) if data.get('status_code') else None
        data['event_type'] = "HTTP_ACTIVITY"
        data['category'] = "network"
        return data
