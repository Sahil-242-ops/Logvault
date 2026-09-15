import time
import uuid
from typing import Dict, Any, List
from .parsers.detector import detector
from .ai.local_ai import local_ai
from .pii_masker import PIIMasker
from .anomaly_detector import anomaly_detector
from .schema.ocsf import get_ocsf_class_uid, OCSF_CATEGORIES

class Normalizer:
    def __init__(self):
        self.pii_masker = PIIMasker()

    async def normalize(self, raw_log: str) -> Dict[str, Any]:
        start_time = time.time()
        
        # 1. Format Detection & Parsing
        fmt, parsed, confidence = detector.detect_and_parse(raw_log)
        parser_type = "DETERMINISTIC"
        
        if not parsed:
            parsed = {}
            fmt = "unknown"

        # 2. Genuine AI Intelligence Enrichment
        ai_intelligence = await local_ai.analyze(raw_log)
        
        parsed["ai_provider"] = ai_intelligence.get("ai_provider", "none")
        parsed["ai_model"] = ai_intelligence.get("ai_model", "none")
        
        ai_sev = ai_intelligence.get("severity")
        if ai_sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            current_sev_rank = sev_order.get(parsed.get("severity", "LOW"), 0)
            ai_sev_rank = sev_order.get(ai_sev, 0)
            if ai_sev_rank > current_sev_rank or "severity" not in parsed:
                parsed["severity"] = ai_sev
                
        if "event_type" not in parsed or parsed["event_type"] == "GENERIC_EVENT":
            parsed["event_type"] = ai_intelligence.get("semantic_classification", "GENERIC_EVENT")

        # Ensure raw log is preserved in the base parsed data for downstream
        parsed["raw_log"] = raw_log

        # 3. Anomaly Detection (pre-masking, using full data context)
        anomaly_results = anomaly_detector.detect(parsed)
        
        # Merge AI threat findings if suspicious or threat_score > 50 or MITRE technique identified
        ai_mitre = ai_intelligence.get("mitre_techniques") or []
        ai_score = ai_intelligence.get("threat_score", 0)
        ai_suspicious = ai_intelligence.get("is_suspicious", False)
        
        if ai_suspicious or ai_score > 50 or ai_mitre:
            anomaly_results["is_anomalous"] = True
            if ai_score > anomaly_results.get("threat_score", 0):
                anomaly_results["threat_score"] = ai_score
            
            primary_mitre = ai_mitre[0] if (ai_mitre and ai_mitre[0] != "null") else None
            anomaly_results["findings"].append({
                "rule_name": f"Ollama AI ({ai_intelligence.get('ai_model', 'local')})",
                "description": ai_intelligence.get("reasoning", "Suspicious pattern identified by local AI model."),
                "mitre_technique": primary_mitre
            })
            
        parsed["ai_threat_reasoning"] = ai_intelligence.get("reasoning", "")

        # 4. PII Masking
        masked_data, pii_detected = self.pii_masker.mask_dict(parsed)
        
        # 5. OCSF Schema Mapping
        category_name = masked_data.get("category", "other")
        event_class_name = "Unknown"
        event_type = masked_data.get("event_type", "GENERIC_EVENT")
        
        if "AUTHENTICATION" in event_type:
            event_class_name = "Authentication"
        elif "HTTP" in event_type:
            event_class_name = "HTTP Activity"
        elif "SECURITY_FINDING" in event_type:
            event_class_name = "Security Finding"
        
        class_uid = get_ocsf_class_uid(event_class_name)
        ocsf_category = OCSF_CATEGORIES.get(event_class_name, "other")

        latency_ms = (time.time() - start_time) * 1000

        # Construct final output
        result = {
            "id": str(uuid.uuid4()),
            "processing_latency_ms": round(latency_ms, 3),
            "detected_format": fmt,
            "detection_confidence": confidence,
            "parser_name": f"{fmt.upper()} Parser",
            "parser_type": parser_type,
            "parse_confidence": confidence,
            "ocsf_class_uid": class_uid,
            "ocsf_class_name": event_class_name,
            "ocsf_category": ocsf_category,
            "event_type": event_type,
            "timestamp": masked_data.get("timestamp"),
            "severity": masked_data.get("severity", "INFO"),
            "source_ip": masked_data.get("source_ip"),
            "source_port": masked_data.get("source_port"),
            "destination_ip": masked_data.get("destination_ip"),
            "destination_port": masked_data.get("destination_port"),
            "user": masked_data.get("user"),
            "host": masked_data.get("host"),
            "process": masked_data.get("process"),
            "protocol": masked_data.get("protocol"),
            "action": masked_data.get("action"),
            "status": masked_data.get("status"),
            "message": masked_data.get("message", raw_log),
            "category": category_name,
            "pii_detected": pii_detected,
            "pii_masked": len(pii_detected) > 0,
            "raw_log": raw_log,
            "anomaly": anomaly_results,
            "ai_provider": ai_intelligence.get("ai_provider", "none"),
            "ai_model": ai_intelligence.get("ai_model", "none"),
            "ai_reasoning": ai_intelligence.get("reasoning", ""),
            "ai_threat_score": ai_intelligence.get("threat_score", 0),
            "ai_mitre_techniques": ai_intelligence.get("mitre_techniques", []),
            "ai_is_suspicious": ai_intelligence.get("is_suspicious", False)
        }
        
        return result

    async def batch_normalize(self, raw_logs: List[str]) -> List[Dict[str, Any]]:
        results = []
        for log in raw_logs:
            if log.strip():
                results.append(await self.normalize(log.strip()))
        return results

normalizer = Normalizer()
