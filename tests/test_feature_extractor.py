"""
Unit Tests for Feature Extractor

Test the feature extraction functionality.
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.features.extractor import FeatureExtractor


@pytest.fixture
def extractor():
    """Create a feature extractor instance."""
    return FeatureExtractor()


class TestFeatureExtractor:
    """Test cases for FeatureExtractor."""
    
    def test_initialization(self, extractor):
        """Test extractor initialization."""
        assert extractor is not None
        assert len(extractor.ps_encoding_patterns) > 0
        assert len(extractor.suspicious_keywords) > 0
    
    def test_basic_feature_extraction(self, extractor):
        """Test basic feature extraction."""
        command = "ls -la /home/user"
        features = extractor.extract_features(command)
        
        assert isinstance(features, dict)
        assert len(features) > 0
        assert 'length' in features
        assert 'shannon_entropy' in features
        assert features['length'] == len(command)
    
    def test_powershell_obfuscation_detection(self, extractor):
        """Test PowerShell obfuscation pattern detection."""
        # Base64 encoded PowerShell
        command = "powershell -enc JABhAD0AJwBoAGUAbABsAG8AJwA7ACAAJABhAA=="
        features = extractor.extract_features(command)
        
        assert features['ps_encoding_count'] > 0
        assert features['has_base64'] > 0
        assert features['base64_char_ratio'] > 0.3
    
    def test_bash_obfuscation_detection(self, extractor):
        """Test Bash obfuscation pattern detection."""
        # Hex encoded bash
        command = "bash -c 'echo \\x48\\x65\\x6c\\x6c\\x6f'"
        features = extractor.extract_features(command)
        
        assert features['bash_encoding_count'] > 0
        assert features['has_hex_encoding'] > 0
    
    def test_entropy_calculation(self, extractor):
        """Test entropy calculation."""
        # Low entropy command
        low_entropy_cmd = "ls"
        low_features = extractor.extract_features(low_entropy_cmd)
        
        # High entropy command (random base64)
        high_entropy_cmd = "powershell -enc " + "A" * 100
        high_features = extractor.extract_features(high_entropy_cmd)
        
        # High entropy command should have higher entropy
        assert high_features['shannon_entropy'] > low_features['shannon_entropy']
    
    def test_character_features(self, extractor):
        """Test character distribution features."""
        command = "UPPERCASE lowercase 123 !@#$"
        features = extractor.extract_features(command)
        
        assert 'uppercase_ratio' in features
        assert 'lowercase_ratio' in features
        assert 'digit_ratio' in features
        assert 'special_char_ratio' in features
        
        # Verify ratios are between 0 and 1
        assert 0 <= features['uppercase_ratio'] <= 1
        assert 0 <= features['lowercase_ratio'] <= 1
        assert 0 <= features['digit_ratio'] <= 1
    
    def test_structural_features(self, extractor):
        """Test structural features."""
        command = "echo 'test' | grep pattern > output.txt"
        features = extractor.extract_features(command)
        
        assert features['pipe_count'] == 1
        assert features['redirect_count'] == 1
        assert features['quote_count'] == 2
    
    def test_platform_detection(self, extractor):
        """Test platform-specific feature detection."""
        # PowerShell command
        ps_cmd = "Get-Process | Where-Object {$_.CPU -gt 100}"
        ps_features = extractor.extract_features(ps_cmd)
        assert ps_features['powershell_score'] > 0
        
        # Bash command
        bash_cmd = "grep -r 'pattern' /var/log/ | awk '{print $1}'"
        bash_features = extractor.extract_features(bash_cmd)
        assert bash_features['bash_score'] > 0
    
    def test_batch_extraction(self, extractor):
        """Test batch feature extraction."""
        commands = [
            "ls -la",
            "Get-Process",
            "dir C:\\"
        ]
        
        features_array = extractor.extract_batch(commands)
        
        assert features_array.shape[0] == len(commands)
        assert features_array.shape[1] == len(extractor.get_feature_names())
    
    def test_suspicious_keywords(self, extractor):
        """Test suspicious keyword detection."""
        malicious_cmd = "powershell -windowstyle hidden -enc BASE64 bypass"
        features = extractor.extract_features(malicious_cmd)
        
        assert features['suspicious_keyword_count'] > 0
    
    def test_empty_command(self, extractor):
        """Test handling of empty command."""
        features = extractor.extract_features("")
        
        assert features['length'] == 0
        assert features['shannon_entropy'] == 0
    
    def test_feature_names_consistency(self, extractor):
        """Test that feature names are consistent."""
        command1 = "test command 1"
        command2 = "different test 2"
        
        features1 = extractor.extract_features(command1)
        features2 = extractor.extract_features(command2)
        
        assert list(features1.keys()) == list(features2.keys())
        assert len(features1) == len(extractor.get_feature_names())


class TestEdgeCases:
    """Test edge cases and special scenarios."""
    
    def test_very_long_command(self, extractor):
        """Test handling of very long commands."""
        long_command = "A" * 10000
        features = extractor.extract_features(long_command)
        
        assert features['length'] == 10000
        assert isinstance(features['shannon_entropy'], float)
    
    def test_unicode_characters(self, extractor):
        """Test handling of Unicode characters."""
        unicode_cmd = "echo 'Hello 世界 🌍'"
        features = extractor.extract_features(unicode_cmd)
        
        assert features['length'] > 0
        assert isinstance(features, dict)
    
    def test_special_characters(self, extractor):
        """Test handling of many special characters."""
        special_cmd = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        features = extractor.extract_features(special_cmd)
        
        assert features['special_char_ratio'] > 0.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])