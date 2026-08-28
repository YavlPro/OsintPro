#!/usr/bin/env python3
"""
Ethical OSINT Project - Main CLI
=================================
Command-line interface for OSINT analysis tools.
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main():
    parser = argparse.ArgumentParser(
        description="Ethical OSINT Project - Open Source Intelligence Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s crypto check 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e
  %(prog)s phishing url https://suspicious-site.com
  %(prog)s phishing email user@example.com
  %(prog)s domain example.com
  %(prog)s breach user@email.com
  %(prog)s project MyProject https://example.com https://github.com/user/repo
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Crypto command
    crypto_parser = subparsers.add_parser("crypto", help="Cryptocurrency analysis")
    crypto_subparsers = crypto_parser.add_subparsers(dest="crypto_action")
    crypto_check = crypto_subparsers.add_parser("check", help="Check a wallet address")
    crypto_check.add_argument("address", help="Wallet address (0x... for ETH, 1.../3.../bc1... for BTC)")
    
    # Phishing command
    phishing_parser = subparsers.add_parser("phishing", help="Phishing detection")
    phishing_subparsers = phishing_parser.add_subparsers(dest="phishing_action")
    phishing_url = phishing_subparsers.add_parser("url", help="Check a URL")
    phishing_url.add_argument("url", help="URL to check")
    phishing_email = phishing_subparsers.add_parser("email", help="Check an email")
    phishing_email.add_argument("email", help="Email to check")
    phishing_domain = phishing_subparsers.add_parser("domain", help="Check a domain")
    phishing_domain.add_argument("domain", help="Domain to check")
    
    # Domain analysis command
    domain_parser = subparsers.add_parser("domain", help="Domain analysis")
    domain_parser.add_argument("domain", help="Domain to analyze")
    
    # Breach check command
    breach_parser = subparsers.add_parser("breach", help="Data breach check")
    breach_parser.add_argument("email", help="Email to check")
    
    # Project analysis command
    project_parser = subparsers.add_parser("project", help="Project analysis")
    project_parser.add_argument("name", help="Project name")
    project_parser.add_argument("website", help="Project website")
    project_parser.add_argument("--github", help="GitHub repository URL")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == "crypto":
        handle_crypto(args)
    elif args.command == "phishing":
        handle_phishing(args)
    elif args.command == "domain":
        handle_domain(args)
    elif args.command == "breach":
        handle_breach(args)
    elif args.command == "project":
        handle_project(args)


def handle_crypto(args):
    from src.crypto import WalletChecker
    checker = WalletChecker(etherscan_api_key=_env_key("ETHERSCAN_API_KEY"))
    result = checker.check_wallet(args.address)
    print(checker.format_result(result))


def handle_phishing(args):
    if args.phishing_action == "url":
        from src.phishing import URLChecker
        checker = URLChecker()
        result = checker.comprehensive_check(args.url)
        print(checker.format_analysis(result))
    elif args.phishing_action == "email":
        from src.phishing import EmailAnalyzer
        analyzer = EmailAnalyzer(hibp_api_key=_env_key("HIBP_API_KEY"))
        result = analyzer.comprehensive_analysis(args.email)
        print(analyzer.format_analysis(result))
    elif args.phishing_action == "domain":
        from src.phishing import DomainChecker
        checker = DomainChecker()
        result = checker.comprehensive_check(args.domain)
        print(checker.format_analysis(result))
    else:
        print("Please specify a phishing action: url, email, or domain")


def handle_domain(args):
    from src.domain_analysis import WHOISLookup
    lookup = WHOISLookup()
    result = lookup.lookup(args.domain)
    print(lookup.format_lookup(result))


def handle_breach(args):
    from src.breach_monitor import BreachChecker
    checker = BreachChecker(hibp_api_key=_env_key("HIBP_API_KEY"))
    result = checker.comprehensive_check(args.email)
    print(checker.format_analysis(result))


def handle_project(args):
    from src.domain_analysis import ProjectAnalyzer
    analyzer = ProjectAnalyzer()
    project_info = {"name": args.name, "website": args.website, "github": args.github or ""}
    result = analyzer.analyze_crypto_project(project_info)
    print(analyzer.format_analysis(result))


def _env_key(name: str):
    """Read an API key from the environment, returning None if not set."""
    import os
    return os.environ.get(name, "").strip() or None


if __name__ == "__main__":
    main()