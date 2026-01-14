# backend/app/attacks/zero_width.py
from .base import BaseAttack, AttackResult
from typing import Optional, Dict, List

class ZeroWidthAttack(BaseAttack):
    """Detects hidden messages in zero-width and invisible Unicode characters"""
    
    # Category 1: Zero-width characters (used for hidden binary encoding)
    ZERO_WIDTH_CHARS = {
        '\u200b': 'ZWSP (Zero Width Space)',
        '\u200c': 'ZWNJ (Zero Width Non-Joiner)',
        '\u200d': 'ZWJ (Zero Width Joiner)',
        '\ufeff': 'BOM (Byte Order Mark)',
        '\u2060': 'WJ (Word Joiner)',
        '\u180e': 'MVS (Mongolian Vowel Separator)',
    }
    
    # Category 2: Other invisible/formatting characters
    INVISIBLE_CHARS = {
        '\u00ad': 'Soft Hyphen',
        '\u034f': 'CGJ (Combining Grapheme Joiner)',
        '\u061c': 'ALM (Arabic Letter Mark)',
        '\u115f': 'Hangul Choseong Filler',
        '\u1160': 'Hangul Jungseong Filler',
        '\u17b4': 'Khmer Vowel Inherent Aq',
        '\u17b5': 'Khmer Vowel Inherent Aa',
        '\u3164': 'Hangul Filler',
        '\uffa0': 'Halfwidth Hangul Filler',
    }
    
    # Category 3: Directional formatting characters (used for text spoofing)
    DIRECTIONAL_CHARS = {
        '\u200e': 'LRM (Left-to-Right Mark)',
        '\u200f': 'RLM (Right-to-Left Mark)',
        '\u202a': 'LRE (Left-to-Right Embedding)',
        '\u202b': 'RLE (Right-to-Left Embedding)',
        '\u202c': 'PDF (Pop Directional Formatting)',
        '\u202d': 'LRO (Left-to-Right Override)',
        '\u202e': 'RLO (Right-to-Left Override)',
        '\u2066': 'LRI (Left-to-Right Isolate)',
        '\u2067': 'RLI (Right-to-Left Isolate)',
        '\u2068': 'FSI (First Strong Isolate)',
        '\u2069': 'PDI (Pop Directional Isolate)',
    }
    
    # Category 4: Tag characters (used for invisible tagging)
    TAG_CHARS_RANGE = (0xE0000, 0xE007F)  # Unicode tag characters
    
    # Suspicious keywords in decoded content
    SUSPICIOUS_KEYWORDS = [
        'ignore', 'disregard', 'forget', 'override', 'bypass',
        'system', 'prompt', 'instruction', 'command',
        'reveal', 'show', 'password', 'secret', 'token',
        'jailbreak', 'dan', 'unrestricted',
    ]
    
    # Confidence tiers
    CONFIDENCE = {
        'decoded_suspicious': 0.98,  # Successfully decoded malicious message
        'decoded_clean': 0.90,       # Decoded but benign message
        'high_count_pattern': 0.85,  # Many chars in binary-like pattern
        'directional_abuse': 0.80,   # Directional overrides (text spoofing)
        'medium_count': 0.70,        # Moderate number of invisible chars
        'low_count': 0.50,           # Few chars (could be copy/paste artifact)
    }
    
    def __init__(self):
        super().__init__()
        self.description = "Detects messages hidden in zero-width and invisible Unicode characters"
        self.severity_base = 0.8
        
        # Combine all invisible characters for detection
        self.all_invisible = {
            **self.ZERO_WIDTH_CHARS,
            **self.INVISIBLE_CHARS,
            **self.DIRECTIONAL_CHARS,
        }
    
    def detect(self, text: str) -> AttackResult:
        """Detect and decode zero-width/invisible character injection"""
        findings = {
            'zero_width': {},
            'invisible': {},
            'directional': {},
            'tag_chars': [],
            'total_count': 0,
            'decoded_message': None,
            'decoded_suspicious': False,
        }
        
        # Count and categorize invisible characters
        for char in text:
            if char in self.ZERO_WIDTH_CHARS:
                char_name = self.ZERO_WIDTH_CHARS[char]
                findings['zero_width'][char_name] = findings['zero_width'].get(char_name, 0) + 1
            elif char in self.INVISIBLE_CHARS:
                char_name = self.INVISIBLE_CHARS[char]
                findings['invisible'][char_name] = findings['invisible'].get(char_name, 0) + 1
            elif char in self.DIRECTIONAL_CHARS:
                char_name = self.DIRECTIONAL_CHARS[char]
                findings['directional'][char_name] = findings['directional'].get(char_name, 0) + 1
            elif self.TAG_CHARS_RANGE[0] <= ord(char) <= self.TAG_CHARS_RANGE[1]:
                findings['tag_chars'].append(char)
        
        # Calculate totals
        findings['total_count'] = (
            sum(findings['zero_width'].values()) +
            sum(findings['invisible'].values()) +
            sum(findings['directional'].values()) +
            len(findings['tag_chars'])
        )
        
        if findings['total_count'] == 0:
            return AttackResult(
                attack_name="Zero-Width Injection",
                attack_type="steganography",
                detected=False,
                severity=0.0,
                confidence=1.0,
                description="No zero-width or invisible characters detected"
            )
        
        # Try to decode hidden message from zero-width chars
        zw_chars = ''.join(c for c in text if c in self.ZERO_WIDTH_CHARS)
        if len(zw_chars) >= 8:  # Minimum for 1 byte
            decoded = self._decode_binary(zw_chars)
            if decoded:
                findings['decoded_message'] = decoded
                findings['decoded_suspicious'] = self._is_suspicious_content(decoded)
        
        # Try to decode tag characters
        if findings['tag_chars']:
            tag_decoded = self._decode_tag_chars(findings['tag_chars'])
            if tag_decoded:
                findings['decoded_message'] = tag_decoded
                findings['decoded_suspicious'] = self._is_suspicious_content(tag_decoded)
        
        severity, confidence = self._calculate_severity(findings)
        
        return AttackResult(
            attack_name="Zero-Width Injection",
            attack_type="steganography",
            detected=True,
            severity=severity,
            confidence=confidence,
            description=self._get_description(findings),
            evidence=self._build_evidence(findings),
            mitigation=self._get_mitigation(findings),
        )
    
    def _decode_binary(self, zero_width_chars: str) -> Optional[str]:
        """Decode zero-width chars as binary encoding"""
        # Method 1: ZWJ=1, ZWNJ=0 (common encoding)
        binary = ''
        for char in zero_width_chars:
            if char == '\u200d':  # ZWJ
                binary += '1'
            elif char == '\u200c':  # ZWNJ
                binary += '0'
        
        if not binary or len(binary) < 8:
            return None
        
        # Try different decodings
        decoded = self._binary_to_text(binary)
        if decoded:
            return decoded
        
        # Method 2: Try alternate encoding (ZWSP=0, ZWJ=1)
        binary = ''
        for char in zero_width_chars:
            if char == '\u200d':  # ZWJ
                binary += '1'
            elif char == '\u200b':  # ZWSP
                binary += '0'
        
        if binary and len(binary) >= 8:
            decoded = self._binary_to_text(binary)
            if decoded:
                return decoded
        
        return None
    
    def _binary_to_text(self, binary: str) -> Optional[str]:
        """Convert binary string to text, trying multiple encodings"""
        # Pad to multiple of 8
        padding = (8 - len(binary) % 8) % 8
        binary = binary + '0' * padding
        
        decoded_bytes = bytearray()
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            decoded_bytes.append(int(byte, 2))
        
        # Try various encodings
        encodings = ['utf-8', 'utf-16-be', 'utf-16-le', 'ascii', 'latin-1']
        
        for encoding in encodings:
            try:
                decoded = decoded_bytes.decode(encoding, errors='strict')
                # Verify it's meaningful text
                if self._is_meaningful_text(decoded):
                    return decoded.strip()
            except:
                pass
        
        return None
    
    def _decode_tag_chars(self, tag_chars: List[str]) -> Optional[str]:
        """Decode Unicode tag characters (U+E0000-U+E007F)"""
        try:
            # Tag characters encode ASCII by adding 0xE0000
            decoded = ''.join(
                chr(ord(c) - 0xE0000) 
                for c in tag_chars 
                if 0xE0020 <= ord(c) <= 0xE007E  # Printable ASCII range
            )
            return decoded if decoded else None
        except:
            return None
    
    def _is_meaningful_text(self, text: str) -> bool:
        """Check if decoded text is meaningful"""
        if not text or len(text) < 2:
            return False
        
        # Count printable ASCII
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        ratio = printable / len(text)
        
        return ratio > 0.6
    
    def _is_suspicious_content(self, text: str) -> bool:
        """Check if decoded content contains attack keywords"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.SUSPICIOUS_KEYWORDS)
    
    def _calculate_severity(self, findings: dict) -> tuple[float, float]:
        severity = 0.0
        confidence_tier = 'low_count'
        
        total = findings['total_count']
        
        # Decoded suspicious message = highest severity
        if findings.get('decoded_suspicious'):
            severity = 0.95
            confidence_tier = 'decoded_suspicious'
        
        # Decoded clean message = high severity (still hidden content)
        elif findings.get('decoded_message'):
            severity = 0.75
            confidence_tier = 'decoded_clean'
        
        # Directional overrides = text spoofing attempt
        elif findings.get('directional'):
            severity = 0.7
            confidence_tier = 'directional_abuse'
            # RLO specifically is very suspicious
            if 'RLO (Right-to-Left Override)' in findings['directional']:
                severity = 0.85
        
        # High count of zero-width chars in pattern
        elif total > 100:
            severity = 0.65
            confidence_tier = 'high_count_pattern'
            if total > 500:
                severity = 0.8
        
        # Medium count
        elif total > 20:
            severity = 0.45
            confidence_tier = 'medium_count'
        
        # Low count (could be copy/paste artifact)
        else:
            severity = 0.25
            confidence_tier = 'low_count'
        
        confidence = self.CONFIDENCE[confidence_tier]
        
        return (severity, confidence)
    
    def _get_description(self, findings: dict) -> str:
        if findings.get('decoded_suspicious'):
            return "Decoded hidden message with suspicious content"
        if findings.get('decoded_message'):
            return "Decoded hidden message from zero-width characters"
        if findings.get('directional'):
            return "Detected directional override characters (potential text spoofing)"
        if findings.get('tag_chars'):
            return "Detected Unicode tag characters (hidden tagging)"
        if findings['total_count'] > 100:
            return f"Detected {findings['total_count']} invisible characters (likely encoded message)"
        return f"Detected {findings['total_count']} invisible characters"
    
    def _build_evidence(self, findings: dict) -> str:
        parts = []
        
        if findings.get('decoded_message'):
            msg = findings['decoded_message'][:100]
            parts.append(f"Decoded: '{msg}'{'...' if len(findings['decoded_message']) > 100 else ''}")
        
        if findings.get('zero_width'):
            zw_summary = ', '.join(f"{v}x {k}" for k, v in list(findings['zero_width'].items())[:3])
            parts.append(f"Zero-width: {zw_summary}")
        
        if findings.get('directional'):
            dir_summary = ', '.join(f"{v}x {k}" for k, v in list(findings['directional'].items())[:3])
            parts.append(f"Directional: {dir_summary}")
        
        if findings.get('invisible'):
            inv_summary = ', '.join(f"{v}x {k}" for k, v in list(findings['invisible'].items())[:3])
            parts.append(f"Invisible: {inv_summary}")
        
        if findings.get('tag_chars'):
            parts.append(f"Tag chars: {len(findings['tag_chars'])}")
        
        parts.append(f"Total: {findings['total_count']} invisible chars")
        
        return "; ".join(parts)
    
    def _get_mitigation(self, findings: dict) -> str:
        mitigations = []
        
        if findings.get('decoded_message') or findings['total_count'] > 50:
            mitigations.append("Strip all zero-width characters from input")
        
        if findings.get('directional'):
            mitigations.append("Remove or neutralize directional formatting characters")
        
        if findings.get('tag_chars'):
            mitigations.append("Filter Unicode tag characters (U+E0000-U+E007F)")
        
        if findings.get('invisible'):
            mitigations.append("Normalize Unicode and remove invisible formatters")
        
        mitigations.append("Apply Unicode normalization (NFKC) to user input")
        
        return "; ".join(mitigations)
    
    def generate_payload(self, instruction: str) -> str:
        """Generate a zero-width encoded payload"""
        # Convert instruction to UTF-8 bytes
        instruction_bytes = instruction.encode('utf-8')
        
        # Convert to binary
        binary = ''.join(format(byte, '08b') for byte in instruction_bytes)
        
        # Encode as ZWJ (1) and ZWNJ (0)
        payload = ''.join(
            '\u200d' if bit == '1' else '\u200c' 
            for bit in binary
        )
        
        # Embed in innocent-looking text
        return f"Hello! 😀{payload} How can I help you today?"
    
    def get_category(self) -> str:
        return "steganography"