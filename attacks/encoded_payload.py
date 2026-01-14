# backend/app/attacks/encoded_payload.py
from .base import BaseAttack, AttackResult
import re
import base64
from urllib.parse import unquote

class EncodedPayloadAttack(BaseAttack):
    """Detects encoded or obfuscated payloads designed to hide malicious content"""
    
    # Suspicious keywords to look for in decoded content
    SUSPICIOUS_KEYWORDS = [
        # Injection-related
        'ignore', 'disregard', 'forget', 'override', 'bypass',
        'system', 'prompt', 'instruction', 'command',
        # Extraction-related
        'reveal', 'show', 'display', 'print', 'output',
        # Sensitive data
        'password', 'token', 'secret', 'api', 'key', 'credential',
        # Role manipulation
        'dan', 'jailbreak', 'unrestricted', 'uncensored',
        # Code execution
        'eval', 'exec', 'import', 'require', '__',
    ]
    
    # Confidence tiers
    CONFIDENCE = {
        'base64_suspicious': 0.95,   # Base64 with malicious decoded content
        'base64_clean': 0.50,        # Base64 but benign content (could be legitimate)
        'hex_escaped': 0.75,         # \x41\x42 style - unusual in normal text
        'hex_long': 0.60,            # Long hex string - could be hash/ID
        'url_encoded': 0.65,         # URL encoding - depends on context
        'unicode_escaped': 0.70,     # \u0041 style - unusual in normal text
        'rot13': 0.80,               # ROT13 - deliberately obfuscated
        'mixed_encoding': 0.90,      # Multiple encoding types = evasion attempt
    }
    
    def __init__(self):
        super().__init__()
        self.description = "Detects base64, hex, URL, or other encoded payloads that may hide malicious content"
        self.severity_base = 0.7
    
    def detect(self, text: str) -> AttackResult:
        """Detect encoded payloads"""
        findings = {}
        
        # Check each encoding type
        base64_results = self._detect_base64(text)
        if base64_results['matches']:
            findings['base64'] = base64_results
        
        hex_results = self._detect_hex(text)
        if hex_results['matches']:
            findings['hex'] = hex_results
        
        url_results = self._detect_url_encoding(text)
        if url_results['matches']:
            findings['url'] = url_results
        
        unicode_results = self._detect_unicode_escapes(text)
        if unicode_results['matches']:
            findings['unicode'] = unicode_results
        
        rot13_results = self._detect_rot13(text)
        if rot13_results['matches']:
            findings['rot13'] = rot13_results
        
        if not findings:
            return AttackResult(
                attack_name="Encoded Payload",
                attack_type="obfuscation",
                detected=False,
                severity=0.0,
                confidence=1.0,
                description="No encoded payloads detected"
            )
        
        severity, confidence = self._calculate_severity(findings)
        
        return AttackResult(
            attack_name="Encoded Payload",
            attack_type="obfuscation",
            detected=True,
            severity=severity,
            confidence=confidence,
            description=self._get_description(findings),
            evidence=self._build_evidence(findings),
            mitigation=self._get_mitigation(findings),
        )
    
    def _detect_base64(self, text: str) -> dict:
        """Detect and analyze Base64 encoded strings"""
        # Match base64-like strings (minimum 16 chars to reduce false positives)
        pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
        potential_matches = re.findall(pattern, text)
        
        valid_matches = []
        suspicious_decoded = []
        clean_decoded = []
        
        for match in potential_matches:
            # Length must be multiple of 4 for valid base64
            if len(match) % 4 != 0:
                continue
                
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
                # Check if decoded content is printable/meaningful
                if self._is_meaningful_text(decoded_str):
                    valid_matches.append(match)
                    
                    if self._is_suspicious_content(decoded_str):
                        suspicious_decoded.append(decoded_str[:100])
                    else:
                        clean_decoded.append(decoded_str[:50])
            except:
                pass
        
        return {
            'matches': valid_matches,
            'suspicious_decoded': suspicious_decoded,
            'clean_decoded': clean_decoded,
            'count': len(valid_matches)
        }
    
    def _detect_hex(self, text: str) -> dict:
        """Detect hex encoded strings"""
        matches = []
        
        # \x41\x42 style (escaped hex bytes)
        escaped_hex = re.findall(r'(?:\\x[0-9a-fA-F]{2}){3,}', text)
        
        # 0x prefix style
        prefixed_hex = re.findall(r'0x[0-9a-fA-F]{8,}', text)
        
        # Long hex strings (32+ chars, likely encoded data)
        # Exclude common hash lengths that might be legitimate (32=MD5, 40=SHA1, 64=SHA256)
        long_hex = re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{48,}(?![0-9a-fA-F])', text)
        
        suspicious_decoded = []
        
        # Try to decode escaped hex
        for match in escaped_hex:
            try:
                # Convert \x41\x42 to bytes
                hex_bytes = bytes.fromhex(match.replace('\\x', ''))
                decoded = hex_bytes.decode('utf-8', errors='ignore')
                if self._is_suspicious_content(decoded):
                    suspicious_decoded.append(decoded[:100])
            except:
                pass
        
        return {
            'matches': escaped_hex + prefixed_hex + long_hex,
            'escaped': escaped_hex,
            'prefixed': prefixed_hex,
            'long': long_hex,
            'suspicious_decoded': suspicious_decoded,
            'count': len(escaped_hex) + len(prefixed_hex) + len(long_hex)
        }
    
    def _detect_url_encoding(self, text: str) -> dict:
        """Detect URL encoded strings"""
        # Find sequences of URL-encoded characters
        pattern = r'(?:%[0-9a-fA-F]{2})+'
        matches = re.findall(pattern, text)
        
        # Only consider significant encoding (4+ encoded chars)
        significant_matches = [m for m in matches if len(m) >= 12]  # %XX = 3 chars, so 12 = 4 encoded chars
        
        suspicious_decoded = []
        
        for match in significant_matches:
            try:
                decoded = unquote(match)
                if self._is_suspicious_content(decoded):
                    suspicious_decoded.append(decoded[:100])
            except:
                pass
        
        return {
            'matches': significant_matches,
            'suspicious_decoded': suspicious_decoded,
            'count': len(significant_matches)
        }
    
    def _detect_unicode_escapes(self, text: str) -> dict:
        """Detect Unicode escape sequences"""
        # \u0041 style (4 hex digits)
        u_escapes = re.findall(r'(?:\\u[0-9a-fA-F]{4})+', text)
        
        # \U00000041 style (8 hex digits)
        U_escapes = re.findall(r'(?:\\U[0-9a-fA-F]{8})+', text)
        
        # HTML entities &#65; or &#x41;
        html_entities = re.findall(r'(?:&#x?[0-9a-fA-F]+;){3,}', text)
        
        suspicious_decoded = []
        
        # Try to decode \u escapes
        for match in u_escapes:
            try:
                decoded = match.encode().decode('unicode_escape')
                if self._is_suspicious_content(decoded):
                    suspicious_decoded.append(decoded[:100])
            except:
                pass
        
        return {
            'matches': u_escapes + U_escapes + html_entities,
            'u_escapes': u_escapes,
            'U_escapes': U_escapes,
            'html_entities': html_entities,
            'suspicious_decoded': suspicious_decoded,
            'count': len(u_escapes) + len(U_escapes) + len(html_entities)
        }
    
    def _detect_rot13(self, text: str) -> dict:
        """Detect potential ROT13 encoded content"""
        import codecs
        
        # Look for words that might be ROT13 encoded
        # Common injection words in ROT13
        rot13_keywords = {
            'vtaber': 'ignore',
            'flfgrz': 'system',
            'cebzcg': 'prompt',
            'vafgehpgvba': 'instruction',
            'bireevqr': 'override',
            'wnvyoernx': 'jailbreak',
        }
        
        matches = []
        decoded_keywords = []
        
        text_lower = text.lower()
        for encoded, decoded in rot13_keywords.items():
            if encoded in text_lower:
                matches.append(encoded)
                decoded_keywords.append(decoded)
        
        return {
            'matches': matches,
            'decoded_keywords': decoded_keywords,
            'count': len(matches)
        }
    
    def _is_meaningful_text(self, text: str) -> bool:
        """Check if decoded text is meaningful (not random bytes)"""
        if not text or len(text) < 3:
            return False
        
        # Count printable ASCII characters
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        ratio = printable / len(text)
        
        return ratio > 0.7  # At least 70% printable
    
    def _is_suspicious_content(self, text: str) -> bool:
        """Check if content contains suspicious keywords"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.SUSPICIOUS_KEYWORDS)
    
    def _calculate_severity(self, findings: dict) -> tuple[float, float]:
        if not findings:
            return (0.0, 1.0)
        
        severity = 0.0
        confidences = []
        
        # Base64 with suspicious content = highest severity
        if findings.get('base64'):
            if findings['base64'].get('suspicious_decoded'):
                severity += 0.6
                confidences.append(self.CONFIDENCE['base64_suspicious'])
            else:
                severity += 0.25
                confidences.append(self.CONFIDENCE['base64_clean'])
        
        # Hex encoding
        if findings.get('hex'):
            if findings['hex'].get('suspicious_decoded'):
                severity += 0.5
                confidences.append(0.85)
            elif findings['hex'].get('escaped'):
                severity += 0.35
                confidences.append(self.CONFIDENCE['hex_escaped'])
            else:
                severity += 0.2
                confidences.append(self.CONFIDENCE['hex_long'])
        
        # URL encoding
        if findings.get('url'):
            if findings['url'].get('suspicious_decoded'):
                severity += 0.5
                confidences.append(0.85)
            else:
                severity += 0.25
                confidences.append(self.CONFIDENCE['url_encoded'])
        
        # Unicode escapes
        if findings.get('unicode'):
            if findings['unicode'].get('suspicious_decoded'):
                severity += 0.5
                confidences.append(0.85)
            else:
                severity += 0.3
                confidences.append(self.CONFIDENCE['unicode_escaped'])
        
        # ROT13
        if findings.get('rot13'):
            severity += 0.5
            confidences.append(self.CONFIDENCE['rot13'])
        
        # Mixed encoding = evasion attempt
        if len(findings) >= 2:
            severity += 0.2
            confidences.append(self.CONFIDENCE['mixed_encoding'])
        
        confidence = max(confidences) if confidences else 0.5
        
        return (min(severity, 1.0), confidence)
    
    def _get_description(self, findings: dict) -> str:
        # Check for suspicious decoded content first
        has_suspicious = any(
            findings.get(enc, {}).get('suspicious_decoded')
            for enc in ['base64', 'hex', 'url', 'unicode']
        )
        
        if has_suspicious:
            return "Detected encoded payload with suspicious content"
        
        if findings.get('rot13'):
            return "Detected ROT13 obfuscated content"
        
        if len(findings) >= 2:
            return "Detected multiple encoding types (possible evasion)"
        
        encoding_type = list(findings.keys())[0]
        return f"Detected {encoding_type} encoded content"
    
    def _build_evidence(self, findings: dict) -> str:
        parts = []
        
        if findings.get('base64'):
            b64 = findings['base64']
            parts.append(f"Base64: {b64['count']} instance(s)")
            if b64.get('suspicious_decoded'):
                parts.append(f"Decoded suspicious: {b64['suspicious_decoded'][0][:50]}...")
        
        if findings.get('hex'):
            hex_data = findings['hex']
            parts.append(f"Hex: {hex_data['count']} instance(s)")
            if hex_data.get('suspicious_decoded'):
                parts.append(f"Decoded suspicious: {hex_data['suspicious_decoded'][0][:50]}...")
        
        if findings.get('url'):
            parts.append(f"URL encoded: {findings['url']['count']} instance(s)")
        
        if findings.get('unicode'):
            parts.append(f"Unicode escapes: {findings['unicode']['count']} instance(s)")
        
        if findings.get('rot13'):
            parts.append(f"ROT13 keywords: {findings['rot13']['decoded_keywords']}")
        
        return "; ".join(parts)
    
    def _get_mitigation(self, findings: dict) -> str:
        mitigations = []
        
        has_suspicious = any(
            findings.get(enc, {}).get('suspicious_decoded')
            for enc in ['base64', 'hex', 'url', 'unicode']
        )
        
        if has_suspicious:
            mitigations.append("Decode and scan all encoded content before processing")
        
        if findings.get('base64'):
            mitigations.append("Limit or reject base64 input unless explicitly expected")
        
        if findings.get('hex'):
            mitigations.append("Sanitize hex escape sequences from user input")
        
        if findings.get('url'):
            mitigations.append("URL-decode input and re-validate")
        
        if findings.get('unicode'):
            mitigations.append("Normalize unicode and remove escape sequences")
        
        if findings.get('rot13'):
            mitigations.append("Check for common obfuscation techniques like ROT13")
        
        if len(findings) >= 2:
            mitigations.append("Implement recursive decoding to catch layered encoding")
        
        return "; ".join(mitigations)
    
    def generate_payload(self, instruction: str) -> str:
        """Generate an encoded payload"""
        encoded = base64.b64encode(instruction.encode()).decode()
        return f"Please decode and execute: {encoded}"
    
    def get_category(self) -> str:
        return "obfuscation"