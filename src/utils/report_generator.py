"""
Report Generator
================
Generate reports from OSINT analysis results.
"""

import json
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generate formatted reports from analysis results."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_markdown(self, title: str, data: Dict, filename: Optional[str] = None) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [f"# {title}", "", f"**Generated:** {timestamp}", "", "---", ""]
        
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"## {key.replace('_', ' ').title()}")
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, list):
                        lines.append(f"### {sub_key.replace('_', ' ').title()}")
                        for item in sub_value:
                            lines.append(f"- {item}" if not isinstance(item, dict) else str(item))
                    else:
                        lines.append(f"**{sub_key.replace('_', ' ').title()}:** {sub_value}")
                lines.append("")
            elif isinstance(value, list):
                lines.append(f"## {key.replace('_', ' ').title()}")
                for item in value:
                    lines.append(f"- {item}")
                lines.append("")
            else:
                lines.append(f"**{key.replace('_', ' ').title()}:** {value}")
                lines.append("")
        
        content = "\n".join(lines)
        if filename:
            (self.output_dir / filename).write_text(content, encoding="utf-8")
        return content
    
    def generate_json(self, title: str, data: Dict, filename: Optional[str] = None) -> str:
        report = {"title": title, "generated": datetime.now().isoformat(), "data": data}
        content = json.dumps(report, indent=2, ensure_ascii=False)
        if filename:
            (self.output_dir / filename).write_text(content, encoding="utf-8")
        return content
    
    def generate_summary(self, analyses: List[Dict]) -> str:
        lines = ["# OSINT Analysis Summary", "", f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 f"**Total Analyses:** {len(analyses)}", "", "---", ""]
        
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for analysis in analyses:
            risk = analysis.get("overall_risk", "UNKNOWN")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        lines.append("## Risk Distribution")
        for risk, count in risk_counts.items():
            if count > 0:
                lines.append(f"- **{risk}:** {count}")
        lines.append("")
        
        lines.append("## Individual Analyses")
        for i, analysis in enumerate(analyses, 1):
            lines.append(f"### Analysis {i}")
            for key, value in analysis.items():
                if not isinstance(value, (dict, list)):
                    lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            lines.append("")
        
        return "\n".join(lines)