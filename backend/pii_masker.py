import re
from typing import Dict, Any, Tuple, List

class PIIMasker:
    """
    Masks PII like IP addresses (optionally if not relevant to security), 
    emails, and credit cards.
    """
    
    EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    # Simple regex for IPs, though in security logs we often keep them.
    # IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
    
    def __init__(self):
        pass
        
    def mask_string(self, text: str) -> Tuple[str, List[str]]:
        if not text:
            return text, []
            
        detected = []
        original_text = text
        
        # Mask Emails
        if self.EMAIL_REGEX.search(text):
            detected.append("EMAIL")
            text = self.EMAIL_REGEX.sub('[EMAIL_REDACTED]', text)
            
        # Mask SSN
        if self.SSN_REGEX.search(text):
            detected.append("SSN")
            text = self.SSN_REGEX.sub('[SSN_REDACTED]', text)
            
        # Mask Credit Card
        if self.CREDIT_CARD_REGEX.search(text):
            detected.append("CREDIT_CARD")
            text = self.CREDIT_CARD_REGEX.sub('[CC_REDACTED]', text)
            
        return text, detected

    def mask_dict(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """
        Recursively mask fields in a dictionary.
        Leaves security-relevant fields like 'source_ip' intact.
        """
        masked_data = {}
        all_detected = set()
        
        # Fields to skip masking because they are essential for SIEM
        skip_fields = {"source_ip", "destination_ip", "host", "user", "username", "process"}
        
        for k, v in data.items():
            if k in skip_fields:
                masked_data[k] = v
                continue
                
            if isinstance(v, str):
                masked_val, detected = self.mask_string(v)
                masked_data[k] = masked_val
                all_detected.update(detected)
            elif isinstance(v, dict):
                masked_val, detected = self.mask_dict(v)
                masked_data[k] = masked_val
                all_detected.update(detected)
            elif isinstance(v, list):
                new_list = []
                for item in v:
                    if isinstance(item, str):
                        m_item, d_item = self.mask_string(item)
                        new_list.append(m_item)
                        all_detected.update(d_item)
                    elif isinstance(item, dict):
                        m_item, d_item = self.mask_dict(item)
                        new_list.append(m_item)
                        all_detected.update(d_item)
                    else:
                        new_list.append(item)
                masked_data[k] = new_list
            else:
                masked_data[k] = v
                
        return masked_data, list(all_detected)
