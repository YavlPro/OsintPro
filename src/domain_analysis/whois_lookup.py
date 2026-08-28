"""
WHOIS Lookup
============
Perform WHOIS lookups and domain analysis.
"""

import whois
from typing import Dict
from datetime import datetime
import tldextract


class WHOISLookup:
    """Perform WHOIS lookups and domain information retrieval."""
    
    def lookup(self, domain: str) -> Dict:
        if "://" in domain: domain = domain.split("://")[1]
        if domain.startswith("www."): domain = domain[4:]
        domain = domain.rstrip("/")
        
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if isinstance(expiration_date, list): expiration_date = expiration_date[0]
            
            domain_age_days = (datetime.now() - creation_date).days if creation_date else None
            days_until_expiry = (expiration_date - datetime.now()).days if expiration_date else None
            extracted = tldextract.extract(domain)
            
            return {
                "domain": domain, "registered_domain": f"{extracted.domain}.{extracted.suffix}",
                "tld": f".{extracted.suffix}", "registrar": w.registrar,
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "domain_age_days": domain_age_days, "days_until_expiry": days_until_expiry,
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                "registrant": {"name": getattr(w, "name", None), "org": getattr(w, "org", None),
                               "country": getattr(w, "country", None)},
                "status_code": "success"
            }
        except Exception as e:
            return {"domain": domain, "error": str(e), "status_code": "error"}
    
    def format_lookup(self, whois_data: Dict) -> str:
        lines = ["=" * 60, "WHOIS LOOKUP RESULTS", "=" * 60,
                 f"Domain: {whois_data.get('domain', 'N/A')}", "-" * 60]
        
        if whois_data.get("status_code") == "error":
            lines.append(f"Error: {whois_data.get('error', 'Unknown error')}")
            lines.append("=" * 60)
            return "\n".join(lines)
        
        lines.append(f"Registrar: {whois_data.get('registrar', 'N/A')}")
        lines.append(f"TLD: {whois_data.get('tld', 'N/A')}")
        lines.append("-" * 60)
        lines.append(f"Created: {whois_data.get('creation_date', 'N/A')}")
        lines.append(f"Expires: {whois_data.get('expiration_date', 'N/A')}")
        
        if whois_data.get("domain_age_days") is not None:
            lines.append(f"Age: {whois_data['domain_age_days']} days ({whois_data['domain_age_days'] // 365} years)")
        
        if whois_data.get("days_until_expiry") is not None:
            days = whois_data["days_until_expiry"]
            lines.append(f"Expires in: {days} days" if days > 0 else f"EXPIRED ({abs(days)} days ago)")
        
        lines.append("-" * 60)
        registrant = whois_data.get("registrant", {})
        lines.append(f"Registrant: {registrant.get('name', 'N/A')}")
        lines.append(f"Organization: {registrant.get('org', 'N/A')}")
        lines.append(f"Country: {registrant.get('country', 'N/A')}")
        
        name_servers = whois_data.get("name_servers", [])
        if name_servers:
            lines.append("-" * 60)
            lines.append("Name Servers:")
            for ns in name_servers[:5]:
                lines.append(f"  - {ns}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python whois_lookup.py <domain>")
        sys.exit(1)
    lookup = WHOISLookup()
    result = lookup.lookup(sys.argv[1])
    print(lookup.format_lookup(result))