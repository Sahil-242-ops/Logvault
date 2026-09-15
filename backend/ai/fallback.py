from typing import Dict, Any
from ..parsers.detector import detector

class DeterministicFallback:
    def analyze(self, raw_log: str) -> Dict[str, Any]:
        fmt, parsed, conf = detector.detect_and_parse(raw_log)
        
        if not parsed:
            parsed = {}
            
        return {
            "fallback_used": True,
            "detected_format": fmt,
            "confidence": conf,
            "parsed_data": parsed
        }
