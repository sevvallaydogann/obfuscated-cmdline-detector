import re
import math
import base64
from collections import Counter
from typing import Dict, List, Tuple
import numpy as np


class FeatureExtractor:
    """
    Extract features from command-line strings for ML model training/inference.
    """
    
    def __init__(self):
        """Initialize feature extractor with pattern definitions."""
        # PowerShell patterns
        self.ps_encoding_patterns = [
            r'-enc(?:odedcommand)?',
            r'-e\s+[A-Za-z0-9+/=]{20,}',
            r'frombase64string',
            r'convert::frombase64string',
        ]
        
        self.ps_obfuscation_patterns = [
            r'\${[^}]+}',  # Variable obfuscation
            r'`[a-z]',  # Backtick obfuscation
            r'\[char\]\d+',  # Character code
            r'invoke-expression|iex',
            r'invoke-command|icm',
            r'downloadstring|downloadfile',
            r'\$\([^)]+\)',  # Command substitution
        ]
        
        # Bash patterns
        self.bash_encoding_patterns = [
            r'\\x[0-9a-f]{2}',  # Hex encoding
            r'\\[0-7]{3}',  # Octal encoding
            r'\$\'\\x',  # ANSI-C quoting
            r'echo\s+-e',  # Echo with escape
        ]
        
        self.bash_obfuscation_patterns = [
            r'\$\{[^}]+\}',  # Parameter expansion
            r'\$\(\([^)]+\)\)',  # Arithmetic expansion
            r'eval\s+',
            r'\|\s*sh',
            r'\|\s*bash',
            r'\*|\?',  # Wildcards
        ]
        
        # CMD patterns
        self.cmd_obfuscation_patterns = [
            r'\^',  # Caret escape
            r'%[a-zA-Z0-9_]+%',  # Environment variables
            r'for\s+/[fl]',  # FOR loops
            r'set\s+[^=]+=',  # Variable setting
        ]
        
        # Suspicious keywords
        self.suspicious_keywords = [
            'hidden', 'bypass', 'noprofile', 'noninteractive',
            'windowstyle', 'exec', 'eval', 'invoke',
            'download', 'webclient', 'curl', 'wget',
            'base64', 'decode', 'encode', 'compress',
            'reverse', 'shell', 'payload', 'exploit'
        ]
        
    def extract_features(self, command: str) -> Dict[str, float]:
        """
        Extract all features from a command string.
        
        Args:
            command: Command-line string to analyze
            
        Returns:
            Dictionary of feature names to values
        """
        features = {}
        
        # Statistical features
        features.update(self._statistical_features(command))
        
        # Entropy features
        features.update(self._entropy_features(command))
        
        # Pattern-based features
        features.update(self._pattern_features(command))
        
        # Character distribution features
        features.update(self._character_features(command))
        
        # Structural features
        features.update(self._structural_features(command))
        
        # Platform-specific features
        features.update(self._platform_features(command))
        
        # Encoding detection features
        features.update(self._encoding_features(command))
        
        return features
    
    def _statistical_features(self, command: str) -> Dict[str, float]:
        """Extract basic statistical features."""
        return {
            'length': len(command),
            'word_count': len(command.split()),
            'unique_chars': len(set(command)),
            'avg_word_length': np.mean([len(w) for w in command.split()]) if command.split() else 0,
            'max_word_length': max([len(w) for w in command.split()]) if command.split() else 0,
        }
    
    def _entropy_features(self, command: str) -> Dict[str, float]:
        """Calculate entropy-based features."""
        return {
            'shannon_entropy': self._shannon_entropy(command),
            'normalized_entropy': self._shannon_entropy(command) / math.log2(len(set(command))) if len(set(command)) > 1 else 0,
            'word_entropy': self._word_entropy(command),
        }
    
    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _word_entropy(self, command: str) -> float:
        """Calculate entropy at word level."""
        words = command.split()
        if not words:
            return 0.0
        
        counter = Counter(words)
        total = len(words)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _pattern_features(self, command: str) -> Dict[str, float]:
        """Detect obfuscation patterns."""
        cmd_lower = command.lower()
        
        features = {
            # PowerShell encoding
            'ps_encoding_count': sum(len(re.findall(p, cmd_lower)) for p in self.ps_encoding_patterns),
            'ps_obfuscation_count': sum(len(re.findall(p, cmd_lower)) for p in self.ps_obfuscation_patterns),
            
            # Bash encoding
            'bash_encoding_count': sum(len(re.findall(p, command)) for p in self.bash_encoding_patterns),
            'bash_obfuscation_count': sum(len(re.findall(p, command)) for p in self.bash_obfuscation_patterns),
            
            # CMD obfuscation
            'cmd_obfuscation_count': sum(len(re.findall(p, command)) for p in self.cmd_obfuscation_patterns),
            
            # Suspicious keywords
            'suspicious_keyword_count': sum(1 for kw in self.suspicious_keywords if kw in cmd_lower),
        }
        
        return features
    
    def _character_features(self, command: str) -> Dict[str, float]:
        """Extract character distribution features."""
        total = len(command) if command else 1
        
        return {
            'uppercase_ratio': sum(1 for c in command if c.isupper()) / total,
            'lowercase_ratio': sum(1 for c in command if c.islower()) / total,
            'digit_ratio': sum(1 for c in command if c.isdigit()) / total,
            'special_char_ratio': sum(1 for c in command if not c.isalnum() and not c.isspace()) / total,
            'whitespace_ratio': sum(1 for c in command if c.isspace()) / total,
            'base64_char_ratio': sum(1 for c in command if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=') / total,
            'hex_char_ratio': sum(1 for c in command if c in '0123456789abcdefABCDEF') / total,
        }
    
    def _structural_features(self, command: str) -> Dict[str, float]:
        """Extract structural features of the command."""
        return {
            'pipe_count': command.count('|'),
            'semicolon_count': command.count(';'),
            'ampersand_count': command.count('&'),
            'redirect_count': command.count('>') + command.count('<'),
            'quote_count': command.count('"') + command.count("'"),
            'paren_count': command.count('(') + command.count(')'),
            'bracket_count': command.count('[') + command.count(']'),
            'brace_count': command.count('{') + command.count('}'),
            'backtick_count': command.count('`'),
            'dollar_count': command.count('$'),
            'backslash_count': command.count('\\'),
            'caret_count': command.count('^'),
        }
    
    def _platform_features(self, command: str) -> Dict[str, float]:
        """Detect platform-specific indicators."""
        cmd_lower = command.lower()
        
        # PowerShell indicators
        ps_cmdlets = ['get-', 'set-', 'new-', 'invoke-', 'start-', 'stop-']
        ps_score = sum(1 for cmdlet in ps_cmdlets if cmdlet in cmd_lower)
        
        # Bash indicators
        bash_builtins = ['cd', 'echo', 'export', 'source', 'alias', 'chmod', 'grep', 'awk', 'sed']
        bash_score = sum(1 for builtin in bash_builtins if f' {builtin} ' in f' {cmd_lower} ')
        
        # CMD indicators
        cmd_commands = ['dir', 'copy', 'move', 'del', 'type', 'findstr']
        cmd_score = sum(1 for cmd in cmd_commands if cmd in cmd_lower)
        
        return {
            'powershell_score': ps_score,
            'bash_score': bash_score,
            'cmd_score': cmd_score,
            'has_ps_extension': 1.0 if '.ps1' in cmd_lower or '-file' in cmd_lower else 0.0,
            'has_bash_shebang': 1.0 if command.startswith('#!') else 0.0,
        }
    
    def _encoding_features(self, command: str) -> Dict[str, float]:
        """Detect various encoding schemes."""
        features = {
            'has_base64': 0.0,
            'base64_length': 0.0,
            'has_hex_encoding': 0.0,
            'has_url_encoding': 0.0,
            'has_unicode_escape': 0.0,
        }
        
        # Base64 detection
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, command)
        if base64_matches:
            features['has_base64'] = 1.0
            features['base64_length'] = max(len(m) for m in base64_matches)
            
            # Try to decode to validate
            for match in base64_matches[:3]:  # Check first 3 matches
                try:
                    decoded = base64.b64decode(match)
                    if self._is_printable(decoded):
                        features['has_base64'] = 2.0  # Valid base64
                        break
                except:
                    pass
        
        # Hex encoding
        if re.search(r'(\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+)', command):
            features['has_hex_encoding'] = 1.0
        
        # URL encoding
        if re.search(r'%[0-9a-fA-F]{2}', command):
            features['has_url_encoding'] = 1.0
        
        # Unicode escapes
        if re.search(r'\\u[0-9a-fA-F]{4}', command):
            features['has_unicode_escape'] = 1.0
        
        return features
    
    def _is_printable(self, data: bytes) -> bool:
        """Check if decoded data contains printable characters."""
        try:
            text = data.decode('utf-8', errors='ignore')
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
            return printable_ratio > 0.7
        except:
            return False
    
    def get_feature_names(self) -> List[str]:
        """Return list of all feature names in order."""
        # Generate a dummy command to get all feature names
        dummy_features = self.extract_features("dummy command")
        return list(dummy_features.keys())
    
    def extract_batch(self, commands: List[str]) -> np.ndarray:
        """
        Extract features from multiple commands.
        
        Args:
            commands: List of command strings
            
        Returns:
            NumPy array of shape (n_samples, n_features)
        """
        features_list = []
        for command in commands:
            features = self.extract_features(command)
            features_list.append(list(features.values()))
        
        return np.array(features_list)


if __name__ == "__main__":
    # Test the feature extractor
    extractor = FeatureExtractor()
    
    # Test commands
    test_commands = [
        "powershell -enc JABhAD0AJwBoAGUAbABsAG8AJwA7ACAAJABhAA==",
        "bash -c 'echo \\x48\\x65\\x6c\\x6c\\x6f'",
        "cmd /c dir",
        "ls -la /tmp",
    ]
    
    print("Testing Feature Extractor\n" + "="*50)
    for cmd in test_commands:
        print(f"\nCommand: {cmd[:60]}...")
        features = extractor.extract_features(cmd)
        print(f"Number of features: {len(features)}")
        print("Top features:")
        for name, value in list(features.items())[:10]:
            print(f"  {name}: {value:.4f}")