"""
Ethical OSINT Project - Phishing Detection Module
==================================================
Tools for detecting and analyzing phishing attempts.
"""

from .url_checker import URLChecker
from .email_analyzer import EmailAnalyzer
from .domain_checker import DomainChecker

__all__ = ["URLChecker", "EmailAnalyzer", "DomainChecker"]