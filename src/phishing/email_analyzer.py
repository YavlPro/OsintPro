"""
Email Analyzer
==============
Analyzes emails for phishing indicators and checks for breaches.
"""

import re
import requests
from typing import Dict, Optional
from datetime import datetime


class EmailAnalyzer:
    """Analyzes email addresses for potential security concerns."""
    
    def __init__(self, hibp_api_key: Optional[str] = None):
        self.hibp_api_key = hibp_api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
        self.disposable_domains = [
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "mailinator.com", "yopmail.com", "temp-mail.org",
            "fakeinbox.com", "sharklasers.com", "10minutemail.com"
        ]
    
    def validate_email(self, email: str) -> Dict:
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(email_regex, email))
        domain = email.split('@')[1] if '@' in email else ""
        
        indicators = []
        if not is_valid: indicators.append("Invalid email format")
        is_disposable = domain.lower() in self.disposable_domains
        if is_disposable: indicators.append("Uses disposable email provider")
        
        # Check for brand impersonation
        brand_patterns = [r'paypal', r'amazon', r'apple', r'google', r'microsoft']
        for pattern in brand_patterns:
            if re.search(pattern, domain.lower()) and not domain.endswith('.com'):
                indicators.append(f"Possible brand impersonation: {domain}")
        
        return {
            "email": email, "domain": domain, "is_valid_format": is_valid,
            "is_disposable": is_disposable, "suspicious_indicators": indicators,
            "risk_score": len(indicators)
        }
    
    def check_breaches(self, email: str) -> Dict:
        if not self.hibp_api_key:
            return {"status": "skipped", "message": "HIBP API key not configured"}
        try:
            response = self.session.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": self.hibp_api_key, "User-Agent": "EthicalOSINT/1.0"},
                timeout=10
            )
            if response.status_code == 200:
                breaches = response.json()
                return {"found": True, "breach_count": len(breaches),
                        "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate"), "data_classes": b.get("DataClasses", [])} for b in breaches]}
            elif response.status_code == 404:
                return {"found": False, "breach_count": 0}
            return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def comprehensive_analysis(self, email: str) -> Dict:
        print(f"[*] Analyzing email: {email}")
        validation = self.validate_email(email)
        breaches = self.check_breaches(email)
        
        if breaches.get("found") and breaches.get("breach_count", 0) > 5:
            overall_risk = "HIGH"
        elif validation.get("is_disposable") or breaches.get("found"):
            overall_risk = "MEDIUM"
        elif validation.get("risk_score", 0) > 0:
            overall_risk = "LOW"
        else:
            overall_risk = "MINIMAL"
        
        return {
            "email": email, "analysis_timestamp": datetime.now().isoformat(),
            "validation": validation, "breach_check": breaches, "overall_risk": overall_risk
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "EMAIL SECURITY ANALYSIS", "=" * 60,
                 f"Email: {analysis['email']}", f"Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60,
                 f"Overall Risk: {analysis.get('overall_risk', 'UNKNOWN')}", "-" * 60]
        
        validation = analysis.get("validation", {})
        lines.append(f"Valid Format: {'Yes' if validation.get('is_valid_format') else 'No'}")
        lines.append(f"Disposable: {'Yes' if validation.get('is_disposable') else 'No'}")
        
        indicators = validation.get("suspicious_indicators", [])
        if indicators:
            lines.append("-" * 60)
            lines.append("SUSPICIOUS INDICATORS:")
            for ind in indicators:
                lines.append(f"  - {ind}")
        
        breaches = analysis.get("breach_check", {})
        lines.append("-" * 60)
        if breaches.get("found"):
            lines.append(f"Found in {breaches.get('breach_count', 0)} data breaches!")
            for b in breaches.get("breaches", [])[:5]:
                lines.append(f"  - {b.get('name')} ({b.get('date')})")
        else:
            lines.append("Not found in known breaches")
        
        lines.append("=" * 60)
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python email_analyzer.py <email>")
        sys.exit(1)
    analyzer = EmailAnalyzer()
    result = analyzer.comprehensive_analysis(sys.argv[1])
    print(analyzer.format_analysis(result))