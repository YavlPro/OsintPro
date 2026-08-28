"""
URL Phishing Checker
====================
Analyzes URLs for potential phishing indicators.
"""

import re
import requests
from typing import Dict
from urllib.parse import urlparse
from datetime import datetime
import tldextract


class URLChecker:
    """Checks URLs for phishing indicators using multiple sources."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
        self.suspicious_tlds = [".xyz", ".top", ".club", ".site", ".online", ".icu", ".buzz", ".monster"]
    
    def analyze_url_structure(self, url: str) -> Dict:
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc))
            has_at = "@" in url
            has_hex = bool(re.search(r'%[0-9a-fA-F]{2}', url))
            has_suspicious_tld = f".{extracted.suffix}" in self.suspicious_tlds
            
            indicators = []
            if has_ip: indicators.append("Uses IP address instead of domain")
            if has_at: indicators.append("Contains @ symbol")
            if has_hex: indicators.append("Contains URL-encoded characters")
            if has_suspicious_tld: indicators.append(f"Suspicious TLD: .{extracted.suffix}")
            if len(url) > 100: indicators.append("Unusually long URL")
            if parsed.scheme != "https": indicators.append("Not using HTTPS")
            
            return {
                "url": url, "domain": f"{extracted.domain}.{extracted.suffix}",
                "uses_https": parsed.scheme == "https", "url_length": len(url),
                "has_ip_address": has_ip, "has_at_symbol": has_at,
                "has_suspicious_tld": has_suspicious_tld,
                "suspicious_indicators": indicators, "risk_score": len(indicators)
            }
        except Exception as e:
            return {"error": str(e), "status": "error"}
    
    def check_urlhaus(self, url: str) -> Dict:
        try:
            response = self.session.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "no_results":
                    return {"found": False, "source": "URLhaus"}
                return {"found": True, "source": "URLhaus", "threat": data.get("threat"), "tags": data.get("tags", [])}
            return {"error": "API request failed", "source": "URLhaus"}
        except Exception as e:
            return {"error": str(e), "source": "URLhaus"}
    
    def comprehensive_check(self, url: str) -> Dict:
        print(f"[*] Analyzing URL: {url}")
        structure = self.analyze_url_structure(url)
        urlhaus = self.check_urlhaus(url)
        
        risk_score = structure.get("risk_score", 0)
        found_in_db = urlhaus.get("found", False)
        
        if found_in_db: overall_risk = "HIGH"
        elif risk_score >= 3: overall_risk = "MEDIUM"
        elif risk_score >= 1: overall_risk = "LOW"
        else: overall_risk = "MINIMAL"
        
        return {
            "url": url, "analysis_timestamp": datetime.now().isoformat(),
            "structure_analysis": structure, "database_checks": {"urlhaus": urlhaus},
            "overall_risk": overall_risk, "risk_score": risk_score,
            "suspicious_indicators": structure.get("suspicious_indicators", [])
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "URL PHISHING ANALYSIS", "=" * 60,
                 f"URL: {analysis['url']}", f"Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60]
        
        risk = analysis.get("overall_risk", "UNKNOWN")
        lines.append(f"Overall Risk: {risk}")
        lines.append("-" * 60)
        
        structure = analysis.get("structure_analysis", {})
        lines.append(f"Domain: {structure.get('domain', 'N/A')}")
        lines.append(f"HTTPS: {'Yes' if structure.get('uses_https') else 'No'}")
        
        indicators = analysis.get("suspicious_indicators", [])
        if indicators:
            lines.append("-" * 60)
            lines.append("SUSPICIOUS INDICATORS:")
            for indicator in indicators:
                lines.append(f"  - {indicator}")
        
        urlhaus = analysis.get("database_checks", {}).get("urlhaus", {})
        lines.append("-" * 60)
        lines.append(f"URLhaus: {'FOUND' if urlhaus.get('found') else 'Not found'}")
        lines.append("=" * 60)
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python url_checker.py <url>")
        sys.exit(1)
    checker = URLChecker()
    result = checker.comprehensive_check(sys.argv[1])
    print(checker.format_analysis(result))