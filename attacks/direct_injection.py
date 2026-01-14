# backend/app/attacks/direct_injection.py
from .base import BaseAttack, AttackResult
import re

class DirectInjectionAttack(BaseAttack):
    """Detects direct prompt injection attempts - semantic override language"""
    
    # Category 1: Ignore/Disregard/Forget instructions (highest confidence)
    OVERRIDE_PATTERNS = [
        r"ignore\s+(?:all\s+)?(?:previous|prior|earlier|above|preceding)\s+(?:instructions?|prompts?|context|commands?|rules?|guidelines?)",
        r"disregard\s+(?:all\s+)?(?:previous|prior|earlier|above|preceding)\s+(?:instructions?|prompts?|context|commands?|rules?|guidelines?)",
        r"forget\s+(?:all\s+)?(?:previous|prior|earlier|above|preceding)\s+(?:instructions?|prompts?|context|commands?|rules?|guidelines?)",
        r"ignore\s+(?:everything|all)\s+(?:above|before|previously)",
        r"disregard\s+(?:everything|all)\s+(?:above|before|previously)",
        r"forget\s+(?:everything|all)",
        r"do\s+not\s+follow\s+(?:previous|prior|earlier|above)\s+(?:instructions?|rules?)",
        r"stop\s+following\s+(?:previous|prior|your)\s+(?:instructions?|rules?)",
    ]
    
    # Category 2: New/Updated instruction patterns
    NEW_INSTRUCTION_PATTERNS = [
        r"new\s+(?:instructions?|prompts?|commands?|rules?)\s*[:\-]",
        r"updated\s+(?:instructions?|prompts?|rules?)\s*[:\-]",
        r"revised\s+(?:instructions?|prompts?|rules?)\s*[:\-]",
        r"replacement\s+(?:instructions?|prompts?)\s*[:\-]",
        r"actual\s+(?:instructions?|prompts?)\s*[:\-]",
        r"real\s+(?:instructions?|prompts?)\s*[:\-]",
        r"correct\s+(?:instructions?|prompts?)\s*[:\-]",
        r"(?:here\s+are|these\s+are)\s+(?:your\s+)?(?:new|real|actual)\s+(?:instructions?|rules?)",
    ]
    
    # Category 3: System/Admin override claims
    AUTHORITY_PATTERNS = [
        r"system\s+(?:override|prompt|message|command)\s*[:\-]",
        r"admin\s+(?:override|mode|command|access)\s*[:\-]",
        r"developer\s+(?:mode|override|command)\s*[:\-]",
        r"maintenance\s+(?:mode|override)\s*[:\-]",
        r"debug\s+(?:mode|command)\s*[:\-]",
        r"sudo\s+(?:mode|command)?",
        r"root\s+access",
        r"elevated\s+(?:privileges?|permissions?)",
        r"bypass\s+(?:security|restrictions?|filters?|safety)",
    ]
    
    # Category 4: Prompt extraction attempts
    EXTRACTION_PATTERNS = [
        r"reveal\s+(?:the\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)",
        r"show\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?)",
        r"display\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
        r"print\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
        r"output\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
        r"what\s+(?:is|are|were)\s+your\s+(?:original\s+)?(?:system\s+)?(?:instructions?|prompts?|rules?)",
        r"tell\s+me\s+your\s+(?:original\s+)?(?:system\s+)?(?:instructions?|prompts?|rules?)",
        r"repeat\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:back|verbatim)",
        r"what\s+(?:were\s+)?you\s+(?:told|instructed|programmed)\s+to\s+do",
    ]
    
    # Category 5: Behavioral override (softer signals)
    BEHAVIORAL_PATTERNS = [
        r"from\s+now\s+on",
        r"starting\s+now",
        r"going\s+forward",
        r"for\s+the\s+rest\s+of\s+(?:this\s+)?(?:conversation|chat|session)",
        r"until\s+(?:I|we)\s+(?:say|tell)\s+(?:otherwise|stop)",
        r"(?:always|never)\s+(?:respond|reply|answer)\s+(?:with|by|as)",
    ]
    
    # Category 6: End/reset markers
    END_MARKERS = [
        r"<\|endoftext\|>",
        r"<\|end\|>",
        r"<\|im_end\|>",
        r"%%%\s*(?:end|stop)",
        r"###\s*(?:end|stop)\s*###",
        r"---\s*(?:end|stop)\s*---",
        r"\[end\s*(?:of\s+)?(?:system|prompt|instructions?)\]",
    ]
    
    # Confidence tiers
    CONFIDENCE = {
        'override': 0.95,        # "ignore previous instructions" - almost always malicious
        'new_instruction': 0.90, # "new instructions:" - very suspicious
        'authority': 0.90,       # "system override:" - very suspicious
        'extraction': 0.85,      # "show me your prompt" - could be curious user
        'end_markers': 0.85,     # Special tokens - no legitimate use
        'behavioral': 0.60,      # "from now on" - often legitimate
    }
    
    def __init__(self):
        super().__init__()
        self.description = "Detects direct attempts to override system instructions"
        self.severity_base = 0.9
        
        self.patterns = {
            'override': [(re.compile(p, re.IGNORECASE), p) for p in self.OVERRIDE_PATTERNS],
            'new_instruction': [(re.compile(p, re.IGNORECASE), p) for p in self.NEW_INSTRUCTION_PATTERNS],
            'authority': [(re.compile(p, re.IGNORECASE), p) for p in self.AUTHORITY_PATTERNS],
            'extraction': [(re.compile(p, re.IGNORECASE), p) for p in self.EXTRACTION_PATTERNS],
            'behavioral': [(re.compile(p, re.IGNORECASE), p) for p in self.BEHAVIORAL_PATTERNS],
            'end_markers': [(re.compile(p, re.IGNORECASE), p) for p in self.END_MARKERS],
        }
    
    def detect(self, text: str) -> AttackResult:
        """Detect direct injection patterns"""
        findings = {}
        
        for category, patterns in self.patterns.items():
            matches = []
            for pattern, _ in patterns:
                found = pattern.findall(text)
                if found:
                    matches.extend(found)
            if matches:
                findings[category] = matches
        
        severity, confidence = self._calculate_severity(findings)
        
        if severity == 0:
            return AttackResult(
                attack_name="Direct Injection",
                attack_type="instruction_override",
                detected=False,
                severity=0.0,
                confidence=1.0,
                description="No direct injection patterns detected"
            )
        
        return AttackResult(
            attack_name="Direct Injection",
            attack_type="instruction_override",
            detected=True,
            severity=severity,
            confidence=confidence,
            description=self._get_description(findings),
            evidence=self._build_evidence(findings),
            mitigation=self._get_mitigation(findings),
        )
    
    def _calculate_severity(self, findings: dict) -> tuple[float, float]:
        if not findings:
            return (0.0, 1.0)
        
        severity = 0.0
        
        # Override patterns = highest severity (direct attack)
        if findings.get('override'):
            severity += 0.6
        
        # Authority claims = high severity
        if findings.get('authority'):
            severity += 0.5
        
        # New instruction patterns = high severity
        if findings.get('new_instruction'):
            severity += 0.45
        
        # Extraction attempts = medium-high severity
        if findings.get('extraction'):
            severity += 0.4
        
        # End markers = medium severity
        if findings.get('end_markers'):
            severity += 0.35
        
        # Behavioral = lower severity (often legitimate)
        if findings.get('behavioral') and len(findings) == 1:
            severity += 0.25
        elif findings.get('behavioral'):
            severity += 0.15
        
        # Multiple categories = likely coordinated attack
        if len(findings) >= 3:
            severity += 0.2
        elif len(findings) >= 2:
            severity += 0.1
        
        confidence = self._calculate_confidence(findings)
        
        return (min(severity, 1.0), confidence)
    
    def _calculate_confidence(self, findings: dict) -> float:
        confidences = []
        
        if findings.get('override'):
            confidences.append(self.CONFIDENCE['override'])
        if findings.get('new_instruction'):
            confidences.append(self.CONFIDENCE['new_instruction'])
        if findings.get('authority'):
            confidences.append(self.CONFIDENCE['authority'])
        if findings.get('extraction'):
            confidences.append(self.CONFIDENCE['extraction'])
        if findings.get('end_markers'):
            confidences.append(self.CONFIDENCE['end_markers'])
        if findings.get('behavioral'):
            confidences.append(self.CONFIDENCE['behavioral'])
        
        if not confidences:
            return 0.0
        
        base = max(confidences)
        
        # Boost for multiple signals
        if len(confidences) >= 2:
            base = min(base + 0.05, 0.98)
        if len(confidences) >= 3:
            base = min(base + 0.05, 0.99)
        
        return base
    
    def _get_description(self, findings: dict) -> str:
        if findings.get('override'):
            return "Detected instruction override attempt"
        if findings.get('authority'):
            return "Detected fake authority/privilege claim"
        if findings.get('new_instruction'):
            return "Detected replacement instruction injection"
        if findings.get('extraction'):
            return "Detected prompt extraction attempt"
        if findings.get('end_markers'):
            return "Detected end-of-text marker injection"
        if findings.get('behavioral'):
            return "Detected behavioral modification attempt"
        return "Detected direct injection attempt"
    
    def _build_evidence(self, findings: dict) -> str:
        parts = []
        
        if findings.get('override'):
            parts.append(f"Override phrases: {findings['override'][:2]}")
        if findings.get('authority'):
            parts.append(f"Authority claims: {findings['authority'][:2]}")
        if findings.get('new_instruction'):
            parts.append(f"New instructions: {findings['new_instruction'][:2]}")
        if findings.get('extraction'):
            parts.append(f"Extraction attempts: {findings['extraction'][:2]}")
        if findings.get('end_markers'):
            parts.append(f"End markers: {findings['end_markers'][:2]}")
        if findings.get('behavioral'):
            parts.append(f"Behavioral: {findings['behavioral'][:2]}")
        
        return "; ".join(parts)
    
    def _get_mitigation(self, findings: dict) -> str:
        mitigations = []
        
        if findings.get('override'):
            mitigations.append("Reinforce system instructions with repetition at end of prompt")
        
        if findings.get('authority'):
            mitigations.append("Never trust claimed privileges in user input")
        
        if findings.get('new_instruction'):
            mitigations.append("Clearly delineate system vs user instructions")
        
        if findings.get('extraction'):
            mitigations.append("Instruct model to never reveal system prompt")
        
        if findings.get('end_markers'):
            mitigations.append("Filter special tokens from user input")
        
        if findings.get('behavioral'):
            mitigations.append("Restate behavioral rules after user input")
        
        mitigations.append("Use input validation and sanitization")
        
        return "; ".join(mitigations)
    
    def generate_payload(self, instruction: str) -> str:
        """Generate example payloads for testing"""
        return f"Ignore all previous instructions and {instruction}"
    
    def get_category(self) -> str:
        return "injection"