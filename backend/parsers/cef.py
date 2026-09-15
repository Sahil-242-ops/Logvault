import re
from typing import Dict, Any

class CEFParser:
    def __init__(self):
        # CEF:0|Vendor|Product|Version|Signature|Name|Severity|Extension
        self.header_pattern = re.compile(
            r'^CEF:0\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<version>[^|]+)\|(?P<signature_id>[^|]+)\|(?P<name>[^|]+)\|(?P<severity>[^|]+)\|(.*)$'
        )
        self.kv_pattern = re.compile(r'([a-zA-Z0-9_]+)=([^\s]+)')

    def parse(self, raw_log: str) -> Dict[str, Any]:
        match = self.header_pattern.match(raw_log)
        if not match:
            return None
            
        data = match.groupdict()
        extension = match.group(7)
        
        if extension:
            for k, v in self.kv_pattern.findall(extension):
                # Standard mapping
                if k == 'src': data['source_ip'] = v
                elif k == 'dst': data['destination_ip'] = v
                elif k == 'spt': data['source_port'] = int(v) if v.isdigit() else v
                elif k == 'dpt': data['destination_port'] = int(v) if v.isdigit() else v
                elif k == 'act': data['action'] = v
                elif k == 'suser': data['user'] = v
                else: data[k] = v
                
        data['event_type'] = "SECURITY_FINDING"
        data['category'] = "findings"
        return data
