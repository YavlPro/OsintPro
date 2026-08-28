"""
Domain Checker
==============
Analyzes domains for phishing indicators and security concerns.
"""

import requests
import whois
from typing import Dict
from datetime import datetime
import tldextract
import re
import ssl
import socket


class DomainChecker:
    """Checks domains for phishing indicators and security concerns."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
    
    def get_whois_info(self, domain: str) -> Dict:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            domain_age_days = (datetime.now() - creation_date).days if creation_date else None
            
            return {
                "domain": domain, "registrar": w.registrar,
                "creation_date": str(creation_date), "expiration_date": str(w.expiration_date),
                "domain_age_days": domain_age_days,
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
                "registrant": getattr(w, "org", None) or getattr(w, "name", None),
                "country": getattr(w, "country", None), "status_code": "success"
            }
        except Exception as e:
            return {"domain": domain, "error": str(e), "status_code": "error"}
    
    def check_ssl_certificate(self, domain: str) -> Dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (not_after - datetime.now()).days
                    return {"valid": True, "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "not_after": cert.get("notAfter"), "days_until_expiry": days_until_expiry,
                            "is_expired": days_until_expiry < 0}
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def analyze_domain_reputation(self, domain: str) -> Dict:
        extracted = tldextract.extract(domain)
        indicators = []
        
        suspicious_patterns = [
            (r'\d{5,}', "Contains multiple consecutive numbers"),
            (r'-{2,}', "Contains multiple consecutive hyphens"),
            (r'(login|verify|account|secure|update)', "Contains common phishing keywords")
        ]
        
        for pattern, message in suspicious_patterns:
            if re.search(pattern, domain.lower()):
                indicators.append(message)
        
        suspicious_tlds = [".xyz", ".top", ".club", ".site", ".online", ".icu", ".buzz"]
        if f".{extracted.suffix}" in suspicious_tlds:
            indicators.append(f"Suspicious TLD: .{extracted.suffix}")
        
        return {"domain": domain, "suffix": f".{extracted.suffix}", "indicators": indicators, "risk_score": len(indicators)}
    
    def comprehensive_check(self, domain: str) -> Dict:
        print(f"[*] Analyzing domain: {domain}")
        if "://" in domain: domain = domain.split("://")[1]
        if domain.startswith("www."): domain = domain[4:]
        
        whois_info = self.get_whois_info(domain)
        ssl_info = self.check_ssl_certificate(domain)
        reputation = self.analyze_domain_reputation(domain)
        
        risk_factors = []
        if whois_info.get("domain_age_days") and whois_info["domain_age_days"] < 30:
            risk_factors.append("Domain registered less than 30 days ago")
        if not ssl_info.get("valid"):
            risk_factors.append("No valid SSL certificate")
        elif ssl_info.get("is_expired"):
            risk_factors.append("SSL certificate is expired")
        risk_factors.extend(reputation.get("indicators", []))
        
        if len(risk_factors) >= 3: overall_risk = "HIGH"
        elif len(risk_factors) >= 1: overall_risk = "MEDIUM"
        else: overall_risk = "LOW"
        
        return {
            "domain": domain, "analysis_timestamp": datetime.now().isoformat(),
            "whois": whois_info, "ssl": ssl_info, "reputation": reputation,
            "risk_factors": risk_factors, "overall_risk": overall_risk
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "DOMAIN SECURITY ANALYSIS", "=" * 60,
                 f"Domain: {analysis['domain']}", f"Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60,
                 f"Overall Risk: {analysis.get('overall_risk', 'UNKNOWN')}", "-" * 60]
        
        whois_info = analysis.get("whois", {})
        if whois_info.get("status_code") == "success":
            lines.append(f"Registrar: {whois_info.get('registrar', 'N/A')}")
            lines.append(f"Created: {whois_info.get('creation_date', 'N/A')}")
            lines.append(f"Age: {whois_info.get('domain_age_days', 'N/A')} days")
        
        lines.append("-" * 60)
        ssl_info = analysis.get("ssl", {})
        if ssl_info.get("valid"):
            lines.append(f"SSL: {'Valid' if not ssl_info.get('is_expired') else 'Expired'}")
        else:
            lines.append(f"SSL: {ssl_info.get('error', 'No SSL')}")
        
        lines.append("-" * 60)
        risk_factors = analysis.get("risk_factors", [])
        if risk_factors:
            lines.append("RISK FACTORS:")
            for factor in risk_factors:
                lines.append(f"  - {factor}")
        else:
            lines.append("No significant risk factors detected")
        
        lines.append("=" * 60)
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python domain_checker.py <domain>")
        sys.exit(1)
    checker = DomainChecker()
    result = checker.comprehensive_check(sys.argv[1])
    print(checker.format_analysis(result))