"""
Wallet Checker
==============
Unified wallet analysis across multiple blockchains.
"""

from typing import Dict, Optional
from .eth_analyzer import EthereumAnalyzer
from .btc_analyzer import BitcoinAnalyzer


class WalletChecker:
    """Unified interface for checking wallets across different blockchains."""
    
    def __init__(self, etherscan_api_key: Optional[str] = None):
        self.eth_analyzer = EthereumAnalyzer(api_key=etherscan_api_key)
        self.btc_analyzer = BitcoinAnalyzer()
    
    def detect_network(self, address: str) -> str:
        if address.startswith("0x") and len(address) == 42:
            return "ethereum"
        if address.startswith(("1", "3", "bc1")):
            return "bitcoin"
        return "unknown"
    
    def check_wallet(self, address: str) -> Dict:
        network = self.detect_network(address)
        if network == "ethereum":
            return self.eth_analyzer.analyze_address(address)
        elif network == "bitcoin":
            return self.btc_analyzer.analyze_address(address)
        return {"error": f"Unable to detect network for address: {address}", "status": "error"}
    
    def format_result(self, analysis: Dict) -> str:
        network = self.detect_network(analysis.get("address", ""))
        if network == "ethereum":
            return self.eth_analyzer.format_analysis(analysis)
        elif network == "bitcoin":
            return self.btc_analyzer.format_analysis(analysis)
        return f"Error: {analysis.get('error', 'Unknown error')}"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python wallet_checker.py <address>")
        sys.exit(1)
    checker = WalletChecker()
    result = checker.check_wallet(sys.argv[1])
    print(checker.format_result(result))