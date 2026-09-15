import re
from typing import Dict, Any

class WindowsParser:
    def __init__(self):
        self.pattern = re.compile(r'EventID=(?P<event_id>\d+)')
        self.kv_pattern = re.compile(r'([a-zA-Z0-9_]+)=([^\s;]+)')

    def parse(self, raw_log: str) -> Dict[str, Any]:
        if not self.pattern.search(raw_log):
            return None
            
        data = {}
        for k, v in self.kv_pattern.findall(raw_log):
            if k == 'EventID': data['event_id'] = v
            elif k == 'AccountName': data['user'] = v
            elif k == 'Workstation': data['host'] = v
            elif k == 'SourceIP': data['source_ip'] = v
            elif k == 'Status': data['status'] = v
            else: data[k] = v
            
        data['event_type'] = "WINDOWS_EVENT"
        data['category'] = "system"
        return data
