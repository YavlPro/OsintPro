"""
Project Analyzer
================
Analyzes online projects for legitimacy and potential risks.
"""

import requests
from typing import Dict
from datetime import datetime


class ProjectAnalyzer:
    """Analyzes online projects for due diligence and legitimacy checks."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
    
    def analyze_website(self, url: str) -> Dict:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            content = response.text.lower()
            
            indicators = []
            if "login" in content and "verify" in content: indicators.append("Contains login verification patterns")
            if "urgent" in content and "action" in content: indicators.append("Contains urgency language")
            if "guaranteed" in content and "return" in content: indicators.append("Contains guaranteed return promises")
            
            return {
                "url": url, "final_url": response.url, "status_code": response.status_code,
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "uses_https": url.startswith("https"), "has_terms": "terms of service" in content,
                "has_privacy_policy": "privacy policy" in content, "has_contact_info": "contact" in content,
                "indicators": indicators, "risk_score": len(indicators)
            }
        except Exception as e:
            return {"url": url, "error": str(e), "status": "error"}
    
    def analyze_github(self, github_url: str) -> Dict:
        parts = github_url.rstrip("/").split("/")
        if len(parts) < 2: return {"error": "Invalid GitHub URL"}
        
        owner, repo = parts[-2], parts[-1]
        try:
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            response = self.session.get(api_url, timeout=10)
            if response.status_code != 200:
                return {"error": f"GitHub API error: {response.status_code}"}
            
            data = response.json()
            readme_response = self.session.get(f"https://api.github.com/repos/{owner}/{repo}/readme", timeout=10)
            commits_response = self.session.get(f"https://api.github.com/repos/{owner}/{repo}/commits", timeout=10)
            
            return {
                "owner": owner, "repo": repo, "description": data.get("description"),
                "stars": data.get("stargazers_count", 0), "forks": data.get("forks_count", 0),
                "open_issues": data.get("open_issues_count", 0), "language": data.get("language"),
                "created_at": data.get("created_at"), "updated_at": data.get("updated_at"),
                "has_readme": readme_response.status_code == 200,
                "recent_commits": len(commits_response.json()) if commits_response.status_code == 200 else 0,
                "license": data.get("license", {}).get("name") if data.get("license") else None
            }
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_crypto_project(self, project_info: Dict) -> Dict:
        name = project_info.get("name", "Unknown")
        website = project_info.get("website", "")
        github = project_info.get("github", "")
        
        print(f"[*] Analyzing crypto project: {name}")
        
        red_flags, green_flags = [], []
        
        if website:
            website_result = self.analyze_website(website)
            if website_result.get("error"):
                red_flags.append("Website unreachable or error")
            else:
                if website_result.get("uses_https"): green_flags.append("Uses HTTPS")
                else: red_flags.append("Does not use HTTPS")
                if website_result.get("has_terms"): green_flags.append("Has Terms of Service")
                else: red_flags.append("Missing Terms of Service")
                if website_result.get("has_privacy_policy"): green_flags.append("Has Privacy Policy")
                else: red_flags.append("Missing Privacy Policy")
        
        if github:
            github_result = self.analyze_github(github)
            if github_result.get("error"):
                red_flags.append("GitHub repository unreachable")
            else:
                if github_result.get("has_readme"): green_flags.append("Has README documentation")
                else: red_flags.append("Missing README documentation")
                if github_result.get("recent_commits", 0) > 10: green_flags.append("Active development history")
                else: red_flags.append("Limited development history")
        
        risk_score = len(red_flags) - len(green_flags)
        if risk_score >= 3: overall_risk = "HIGH"
        elif risk_score >= 1: overall_risk = "MEDIUM"
        else: overall_risk = "LOW"
        
        return {
            "project_name": name, "analysis_timestamp": datetime.now().isoformat(),
            "website_analysis": website_result if website else {},
            "github_analysis": github_result if github else {},
            "red_flags": red_flags, "green_flags": green_flags,
            "risk_score": risk_score, "overall_risk": overall_risk
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "PROJECT ANALYSIS", "=" * 60,
                 f"Project: {analysis.get('project_name', 'N/A')}",
                 f"Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60,
                 f"Overall Risk: {analysis.get('overall_risk', 'UNKNOWN')}",
                 f"Risk Score: {analysis.get('risk_score', 0)}", "-" * 60]
        
        github = analysis.get("github_analysis", {})
        if github and not github.get("error"):
            lines.append(f"GitHub Stars: {github.get('stars', 0)}")
            lines.append(f"Language: {github.get('language', 'N/A')}")
        
        lines.append("-" * 60)
        green = analysis.get("green_flags", [])
        if green:
            lines.append("POSITIVE INDICATORS:")
            for flag in green: lines.append(f"  + {flag}")
        
        red = analysis.get("red_flags", [])
        if red:
            lines.append("RED FLAGS:")
            for flag in red: lines.append(f"  - {flag}")
        
        lines.append("=" * 60)
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python project_analyzer.py <name> <website> [github]")
        sys.exit(1)
    project_info = {"name": sys.argv[1], "website": sys.argv[2], "github": sys.argv[3] if len(sys.argv) > 3 else ""}
    analyzer = ProjectAnalyzer()
    result = analyzer.analyze_crypto_project(project_info)
    print(analyzer.format_analysis(result))