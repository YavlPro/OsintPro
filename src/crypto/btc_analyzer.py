"""
Bitcoin Blockchain Analyzer
===========================
Analyzes Bitcoin addresses and transactions using public APIs.
"""

import requests
from typing import Dict, List
from datetime import datetime


class BitcoinAnalyzer:
    """Analyzes Bitcoin blockchain data using public explorers."""
    
    def __init__(self):
        self.base_url = "https://blockstream.info/api"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
    
    def _make_request(self, endpoint: str) -> Dict:
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}
    
    def get_address_info(self, address: str) -> Dict:
        result = self._make_request(f"/address/{address}")
        if "error" in result:
            return {"error": result["error"], "status": "error"}
        chain_stats = result.get("chain_stats", {})
        funded = chain_stats.get("funded_txo_sum", 0)
        spent = chain_stats.get("spent_txo_sum", 0)
        return {
            "address": address, "funded_txo_count": chain_stats.get("funded_txo_count", 0),
            "funded_txo_sum": funded / 10**8, "spent_txo_count": chain_stats.get("spent_txo_count", 0),
            "spent_txo_sum": spent / 10**8, "balance_btc": (funded - spent) / 10**8,
            "tx_count": chain_stats.get("tx_count", 0), "status": "success"
        }
    
    def get_transactions(self, address: str, limit: int = 10) -> List[Dict]:
        result = self._make_request(f"/address/{address}/txs")
        if isinstance(result, list):
            transactions = []
            for tx in result[:limit]:
                transactions.append({
                    "txid": tx.get("txid", ""), "fee": tx.get("fee", 0) / 10**8,
                    "confirmed": tx.get("status", {}).get("confirmed", False),
                    "block_height": tx.get("status", {}).get("block_height"),
                    "timestamp": datetime.fromtimestamp(tx.get("status", {}).get("block_time", 0)).isoformat() if tx.get("status", {}).get("block_time") else None
                })
            return transactions
        return []
    
    def analyze_address(self, address: str) -> Dict:
        print(f"[*] Analyzing Bitcoin address: {address}")
        address_info = self.get_address_info(address)
        transactions = self.get_transactions(address)
        
        risk_indicators = []
        if address_info.get("tx_count", 0) == 0:
            risk_indicators.append("New address with no transaction history")
        if address_info.get("balance_btc", 0) == 0 and address_info.get("tx_count", 0) > 10:
            risk_indicators.append("Address has been emptied - possible fund movement")
        
        return {
            "address": address, "network": "Bitcoin",
            "analysis_timestamp": datetime.now().isoformat(),
            "address_info": address_info, "recent_transactions": transactions,
            "risk_indicators": risk_indicators
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "BITCOIN ADDRESS ANALYSIS", "=" * 60,
                 f"Address: {analysis['address']}", f"Network: {analysis.get('network', 'Bitcoin')}",
                 f"Analysis Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60]
        
        info = analysis.get("address_info", {})
        if info.get("status") == "success":
            lines.append(f"Balance: {info.get('balance_btc', 0):.8f} BTC")
            lines.append(f"Total Received: {info.get('funded_txo_sum', 0):.8f} BTC")
            lines.append(f"Total Sent: {info.get('spent_txo_sum', 0):.8f} BTC")
            lines.append(f"Transaction Count: {info.get('tx_count', 0)}")
        else:
            lines.append(f"Error: {info.get('error', 'Unknown error')}")
        
        lines.append("-" * 60)
        transactions = analysis.get("recent_transactions", [])
        if transactions:
            lines.append(f"Recent Transactions: {len(transactions)}")
            for tx in transactions[:5]:
                status = "V" if tx.get("confirmed") else "PENDING"
                lines.append(f"  [{status}] Fee: {tx.get('fee', 0):.8f} BTC - {tx.get('txid', '')[:16]}...")
        
        lines.append("-" * 60)
        risk = analysis.get("risk_indicators", [])
        if risk:
            lines.append("RISK INDICATORS:")
            for indicator in risk:
                lines.append(f"  - {indicator}")
        else:
            lines.append("No obvious risk indicators detected")
        
        lines.append("=" * 60)
        return "\n".join(lines)