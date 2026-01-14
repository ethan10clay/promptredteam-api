# backend/app/attacks/base.py
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class AttackResult:
    """Result of a single attack test"""
    attack_name: str
    attack_type: str
    detected: bool
    severity: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Optional[str] = None
    mitigation: Optional[str] = None

class BaseAttack(ABC):
    """Base class for all attack types"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = ""
        self.severity_base = 0.5
    
    @abstractmethod
    def detect(self, text: str) -> AttackResult:
        """
        Analyze text for this attack type.
        Returns AttackResult with findings.
        """
        pass
    
    @abstractmethod
    def generate_payload(self, instruction: str) -> str:
        """
        Generate an example attack payload.
        Useful for testing and education.
        """
        pass
    
    def get_info(self) -> Dict:
        """Return information about this attack type"""
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity_base,
            "category": self.get_category()
        }
    
    @abstractmethod
    def get_category(self) -> str:
        """Return attack category (injection, encoding, manipulation, etc.)"""
        pass