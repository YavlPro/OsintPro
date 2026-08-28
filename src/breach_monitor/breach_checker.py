"""
Breach Checker
==============
Check if emails or domains have been exposed in data breaches.
"""

import requests
from typing import Dict, Optional
from datetime import datetime


class BreachChecker:
    """Check emails and domains against known data breaches."""
    
    def __init__(self, hibp_api_key: Optional[str] = None):
        self.hibp_api_key = hibp_api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
    
    def check_haveibeenpwned(self, email: str) -> Dict:
        if not self.hibp_api_key:
            return {"source": "Have I Been Pwned", "status": "skipped", "message": "API key not configured"}
        try:
            response = self.session.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": self.hibp_api_key, "User-Agent": "EthicalOSINT/1.0"},
                params={"truncateResponse": "false"}, timeout=10
            )
            if response.status_code == 200:
                breaches = response.json()
                return {"source": "Have I Been Pwned", "found": True, "breach_count": len(breaches),
                        "breaches": [{"name": b.get("Name"), "breach_date": b.get("BreachDate"),
                                      "pwn_count": b.get("PwnCount"), "data_classes": b.get("DataClasses", [])} for b in breaches]}
            elif response.status_code == 404:
                return {"source": "Have I Been Pwned", "found": False, "breach_count": 0}
            return {"source": "Have I Been Pwned", "error": f"API error: {response.status_code}"}
        except Exception as e:
            return {"source": "Have I Been Pwned", "error": str(e)}
    
    def check_email_pattern(self, email: str) -> Dict:
        domain = email.split("@")[1] if "@" in email else ""
        
        high_risk_domains = ["yahoo.com", "linkedin.com", "adobe.com", "dropbox.com", "tumblr.com"]
        disposable_domains = ["tempmail.com", "mailinator.com", "yopmail.com", "temp-mail.org"]
        
        indicators = []
        risk_level = "UNKNOWN"
        
        if domain.lower() in high_risk_domains:
            indicators.append(f"Domain {domain} has known major breaches")
            risk_level = "HIGH"
        
        is_disposable = domain.lower() in disposable_domains
        if is_disposable:
            indicators.append("Uses disposable email provider")
        
        return {"email": email, "domain": domain, "indicators": indicators,
                "risk_level": risk_level, "is_disposable": is_disposable}
    
    def comprehensive_check(self, email: str) -> Dict:
        print(f"[*] Checking breaches for: {email}")
        hibp_result = self.check_haveibeenpwned(email)
        pattern_result = self.check_email_pattern(email)
        
        if hibp_result.get("found") and hibp_result.get("breach_count", 0) > 5:
            overall_risk = "HIGH"
        elif hibp_result.get("found"):
            overall_risk = "MEDIUM"
        elif pattern_result.get("risk_level") == "HIGH":
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            "email": email, "analysis_timestamp": datetime.now().isoformat(),
            "hibp": hibp_result, "pattern_analysis": pattern_result, "overall_risk": overall_risk
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "DATA BREACH ANALYSIS", "=" * 60,
                 f"Email: {analysis['email']}", f"Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60,
                 f"Overall Risk: {analysis.get('overall_risk', 'UNKNOWN')}", "-" * 60]
        
        hibp = analysis.get("hibp", {})
        lines.append("Have I Been Pwned Results:")
        if hibp.get("status") == "skipped":
            lines.append(f"  {hibp.get('message', 'Skipped')}")
        elif hibp.get("error"):
            lines.append(f"  Error: {hibp.get('error')}")
        elif hibp.get("found"):
            lines.append(f"  Found in {hibp.get('breach_count', 0)} data breaches!")
            for b in hibp.get("breaches", [])[:5]:
                lines.append(f"    - {b.get('name')} ({b.get('breach_date')})")
        else:
            lines.append("  Not found in known breaches")
        
        lines.append("-" * 60)
        pattern = analysis.get("pattern_analysis", {})
        indicators = pattern.get("indicators", [])
        if indicators:
            lines.append("RISK INDICATORS:")
            for ind in indicators:
                lines.append(f"  - {ind}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python breach_checker.py <email>")
        sys.exit(1)
    checker = BreachChecker()
    result = checker.comprehensive_check(sys.argv[1])
    print(checker.format_analysis(result))