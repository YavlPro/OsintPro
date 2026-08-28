"""
Ethical OSINT Project - Tests
==============================
Basic tests for OSINT modules.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCryptoModule:
    def test_ethereum_analyzer_init(self):
        from src.crypto import EthereumAnalyzer
        analyzer = EthereumAnalyzer()
        assert analyzer.base_url == "https://api.etherscan.io/api"
    
    def test_bitcoin_analyzer_init(self):
        from src.crypto import BitcoinAnalyzer
        analyzer = BitcoinAnalyzer()
        assert analyzer.base_url == "https://blockstream.info/api"
    
    def test_wallet_checker_network_detection(self):
        from src.crypto import WalletChecker
        checker = WalletChecker()
        assert checker.detect_network("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e") == "ethereum"
        assert checker.detect_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "bitcoin"
        assert checker.detect_network("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "bitcoin"
        assert checker.detect_network("invalid") == "unknown"


class TestPhishingModule:
    def test_url_checker_init(self):
        from src.phishing import URLChecker
        checker = URLChecker()
        assert len(checker.suspicious_tlds) > 0
    
    def test_url_structure_analysis(self):
        from src.phishing import URLChecker
        checker = URLChecker()
        result = checker.analyze_url_structure("http://192.168.1.1/login@paypal.com")
        assert result.get("has_ip_address") == True
        assert result.get("has_at_symbol") == True
    
    def test_email_analyzer_init(self):
        from src.phishing import EmailAnalyzer
        analyzer = EmailAnalyzer()
        assert len(analyzer.disposable_domains) > 0
    
    def test_email_validation(self):
        from src.phishing import EmailAnalyzer
        analyzer = EmailAnalyzer()
        result = analyzer.validate_email("user@example.com")
        assert result.get("is_valid_format") == True
        result = analyzer.validate_email("user@tempmail.com")
        assert result.get("is_disposable") == True


class TestDomainModule:
    def test_whois_lookup_init(self):
        from src.domain_analysis import WHOISLookup
        lookup = WHOISLookup()
        assert lookup is not None
    
    def test_project_analyzer_init(self):
        from src.domain_analysis import ProjectAnalyzer
        analyzer = ProjectAnalyzer()
        assert analyzer is not None


class TestBreachModule:
    def test_breach_checker_init(self):
        from src.breach_monitor import BreachChecker
        checker = BreachChecker()
        assert checker.hibp_api_key is None
    
    def test_email_pattern_analysis(self):
        from src.breach_monitor import BreachChecker
        checker = BreachChecker()
        result = checker.check_email_pattern("user@yahoo.com")
        assert result.get("risk_level") == "HIGH"
        result = checker.check_email_pattern("user@mailinator.com")
        assert result.get("is_disposable") == True


class TestUtilsModule:
    def test_privacy_manager_init(self):
        from src.utils import PrivacyManager
        manager = PrivacyManager()
        assert manager.anonymize == True
        assert manager.mask_sensitive == True
    
    def test_email_masking(self):
        from src.utils import PrivacyManager
        manager = PrivacyManager()
        masked = manager.mask_email("john.doe@example.com")
        assert masked != "john.doe@example.com"
        assert "@example.com" in masked
    
    def test_ip_masking(self):
        from src.utils import PrivacyManager
        manager = PrivacyManager()
        masked = manager.mask_ip("192.168.1.100")
        assert masked == "192.168.*.*"
    
    def test_report_generator_init(self):
        from src.utils import ReportGenerator
        generator = ReportGenerator()
        assert generator.output_dir.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])