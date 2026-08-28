"""
Ethereum Blockchain Analyzer
============================
Analyzes Ethereum addresses, transactions, and contracts using public APIs.
"""

import requests
from typing import Dict, List, Optional
from datetime import datetime


class EthereumAnalyzer:
    """Analyzes Ethereum blockchain data using public explorers."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://api.etherscan.io/api"
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "EthicalOSINT/1.0"})
    
    def _make_request(self, params: Dict) -> Dict:
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            response = self.session.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e), "status": "0"}
    
    def get_balance(self, address: str) -> Dict:
        params = {"module": "account", "action": "balance", "address": address, "tag": "latest"}
        result = self._make_request(params)
        if result.get("status") == "1":
            balance_wei = int(result["result"])
            return {"address": address, "balance_wei": balance_wei, "balance_eth": balance_wei / 10**18, "status": "success"}
        return {"error": result.get("message", "Unknown error"), "status": "error"}
    
    def get_transactions(self, address: str, page: int = 1, offset: int = 10) -> Dict:
        params = {"module": "account", "action": "txlist", "address": address, "startblock": 0, "endblock": 99999999, "page": page, "offset": offset, "sort": "desc"}
        result = self._make_request(params)
        if result.get("status") == "1":
            transactions = []
            for tx in result["result"]:
                transactions.append({
                    "hash": tx["hash"], "from": tx["from"], "to": tx["to"],
                    "value_eth": int(tx["value"]) / 10**18, "gas_used": tx["gasUsed"],
                    "timestamp": datetime.fromtimestamp(int(tx["timeStamp"])).isoformat(),
                    "is_error": tx["isError"] == "1"
                })
            return {"address": address, "transactions": transactions, "count": len(transactions), "status": "success"}
        return {"error": result.get("message", "Unknown error"), "status": "error"}
    
    def get_token_transfers(self, address: str, page: int = 1, offset: int = 10) -> Dict:
        params = {"module": "account", "action": "tokentx", "address": address, "page": page, "offset": offset, "sort": "desc"}
        result = self._make_request(params)
        if result.get("status") == "1":
            transfers = []
            for tx in result["result"]:
                decimals = int(tx.get("tokenDecimal", 18))
                transfers.append({
                    "hash": tx["hash"], "token_name": tx.get("tokenName", "Unknown"),
                    "token_symbol": tx.get("tokenSymbol", "???"), "from": tx["from"], "to": tx["to"],
                    "value": int(tx["value"]) / 10**decimals,
                    "timestamp": datetime.fromtimestamp(int(tx["timeStamp"])).isoformat()
                })
            return {"address": address, "transfers": transfers, "count": len(transfers), "status": "success"}
        return {"error": result.get("message", "Unknown error"), "status": "error"}
    
    def analyze_address(self, address: str) -> Dict:
        print(f"[*] Analyzing Ethereum address: {address}")
        balance = self.get_balance(address)
        transactions = self.get_transactions(address, offset=20)
        token_transfers = self.get_token_transfers(address, offset=20)
        
        risk_indicators = []
        if transactions.get("status") == "success":
            error_txs = sum(1 for tx in transactions["transactions"] if tx.get("is_error"))
            if error_txs > 0:
                risk_indicators.append(f"{error_txs} failed transactions detected")
        
        return {
            "address": address, "network": "Ethereum",
            "analysis_timestamp": datetime.now().isoformat(),
            "balance": balance, "recent_transactions": transactions,
            "recent_token_transfers": token_transfers, "risk_indicators": risk_indicators
        }
    
    def format_analysis(self, analysis: Dict) -> str:
        lines = ["=" * 60, "ETHEREUM ADDRESS ANALYSIS", "=" * 60,
                 f"Address: {analysis['address']}", f"Network: {analysis.get('network', 'Ethereum')}",
                 f"Analysis Time: {analysis.get('analysis_timestamp', 'N/A')}", "-" * 60]
        
        balance = analysis.get("balance", {})
        if balance.get("status") == "success":
            lines.append(f"Balance: {balance['balance_eth']:.6f} ETH")
        else:
            lines.append(f"Balance: Error - {balance.get('error', 'Unknown')}")
        
        lines.append("-" * 60)
        tx_data = analysis.get("recent_transactions", {})
        if tx_data.get("status") == "success":
            lines.append(f"Recent Transactions: {tx_data['count']}")
            for tx in tx_data["transactions"][:5]:
                direction = "OUT" if tx["from"].lower() == analysis["address"].lower() else "IN"
                lines.append(f"  [{direction}] {tx['value_eth']:.6f} ETH - {tx['hash'][:16]}...")
        
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