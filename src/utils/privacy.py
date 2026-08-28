"""
Privacy Manager
===============
Handle privacy and data protection in OSINT analysis.
"""

import re
import hashlib
from typing import Dict
from datetime import datetime


class PrivacyManager:
    """Manage privacy and data protection in OSINT results."""
    
    def __init__(self, anonymize: bool = True, mask_sensitive: bool = True):
        self.anonymize = anonymize
        self.mask_sensitive = mask_sensitive
        self.sensitive_patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "phone": r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}',
            "ip_address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        }
    
    def mask_email(self, email: str) -> str:
        if not self.mask_sensitive: return email
        parts = email.split("@")
        if len(parts) != 2: return email
        username, domain = parts[0], parts[1]
        masked_username = username[0] + "***" if len(username) <= 2 else username[0] + "***" + username[-1]
        return f"{masked_username}@{domain}"
    
    def mask_ip(self, ip: str) -> str:
        if not self.mask_sensitive: return ip
        parts = ip.split(".")
        if len(parts) != 4: return ip
        return f"{parts[0]}.{parts[1]}.*.*"
    
    def mask_wallet_address(self, address: str) -> str:
        if not self.mask_sensitive: return address
        if len(address) <= 10: return address[:3] + "***" + address[-3:]
        return address[:6] + "***" + address[-4:]
    
    def anonymize_string(self, text: str) -> str:
        if not self.anonymize: return text
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    def sanitize_output(self, data: Dict) -> Dict:
        if not self.mask_sensitive: return data
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                if re.fullmatch(self.sensitive_patterns["email"], value):
                    sanitized[key] = self.mask_email(value)
                elif re.fullmatch(self.sensitive_patterns["ip_address"], value):
                    sanitized[key] = self.mask_ip(value)
                elif (value.startswith("0x") and len(value) == 42) or (value.startswith(("1", "3", "bc1")) and len(value) > 20):
                    sanitized[key] = self.mask_wallet_address(value)
                else:
                    sanitized[key] = value
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_output(value)
            elif isinstance(value, list):
                sanitized[key] = [self.sanitize_output(item) if isinstance(item, dict) else item for item in value]
            else:
                sanitized[key] = value
        return sanitized
    
    def create_audit_log(self, action: str, target: str, result: str) -> Dict:
        return {"timestamp": datetime.now().isoformat(), "action": action,
                "target": self.anonymize_string(target), "result": result, "anonymized": self.anonymize}