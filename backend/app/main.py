from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional
import time
from app.middleware.rate_limit import rate_limit_middleware, rate_limiter

# Since we're creating a standalone version, include AttackResult inline
class AttackResult:
    def __init__(self, attack_name: str, attack_type: str, detected: bool, 
                 severity: float, confidence: float, description: str,
                 evidence: Optional[str] = None, mitigation: Optional[str] = None,
                 reference_url: Optional[str] = None):
        self.attack_name = attack_name
        self.attack_type = attack_type
        self.detected = detected
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.evidence = evidence
        self.mitigation = mitigation
        self.reference_url = reference_url

from app.attacks import (
    ZeroWidthAttack,
    DirectInjectionAttack,
    RoleManipulationAttack,
    DelimiterInjectionAttack,
    EncodedPayloadAttack
)

# Use the real attack detectors
ATTACKS = {
    "zero_width": ZeroWidthAttack(),
    "direct_injection": DirectInjectionAttack(),
    "role_manipulation": RoleManipulationAttack(),
    "delimiter_injection": DelimiterInjectionAttack(),
    "encoded_payload": EncodedPayloadAttack(),
}

app = FastAPI(
    title="LLM Security Testing API",
    description="Test your prompts for security vulnerabilities - Free & Open Source",
    version="0.1.0"
)

# Add rate limiting middleware - CRITICAL: Must be added before CORS
app.middleware("http")(rate_limit_middleware)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock this down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class TestRequest(BaseModel):
    text: str = Field(..., description="Text to analyze for security threats")
    attacks: Optional[List[str]] = Field(
        default=None,
        description="Specific attacks to test. If None, tests all."
    )

    @validator('text')
    def validate_text_length(cls, v):
        max_length = rate_limiter.max_text_length
        if len(v) > max_length:
            raise ValueError(
                f"Text too long. Maximum {max_length} characters. "
                f"Deploy your own instance for unlimited text length."
            )
        if len(v) == 0:
            raise ValueError("Text cannot be empty")
        return v

class AttackResultResponse(BaseModel):
    attack_name: str
    attack_type: str
    detected: bool
    severity: float
    confidence: float
    description: str
    evidence: Optional[str]
    mitigation: Optional[str]
    reference_url: Optional[str]

class TestResponse(BaseModel):
    scan_id: str
    timestamp: float
    text_length: int
    attacks_tested: int
    threats_detected: int
    overall_risk_score: float
    results: List[AttackResultResponse]
    recommendations: List[str]
    cleaned_text: str

# Endpoints
@app.get("/")
def root():
    return {
        "service": "LLM Security Testing API",
        "version": "0.1.0",
        "status": "online",
        "docs": "/docs",
        "github": "https://github.com/ethantclay/promptredteam-api",
        "available_attacks": list(ATTACKS.keys()),
        "rate_limit": {
            "requests_per_minute": rate_limiter.requests_per_minute,
            "max_text_length": rate_limiter.max_text_length
        }
    }

@app.get("/health")
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": time.time()
    }

@app.get("/attacks")
def list_attacks():
    """List all available attack detection methods"""
    return {
        "attacks": [
            {
                "id": key,
                **attack.get_info()
            }
            for key, attack in ATTACKS.items()
        ]
    }

@app.get("/rate-limit-status")
def rate_limit_status(request: Request):
    """Check rate limit status for debugging"""
    from app.middleware.rate_limit import get_client_ip
    
    client_ip = get_client_ip(request)
    return {
        "your_ip": client_ip,
        "requests_in_last_minute": len(rate_limiter.ip_requests[client_ip]),
        "remaining_requests": rate_limiter.get_remaining_requests(client_ip),
        "reset_in_seconds": rate_limiter.get_reset_time(client_ip),
        "limit": rate_limiter.requests_per_minute,
        "all_request_counts": {ip: len(timestamps) for ip, timestamps in rate_limiter.ip_requests.items()}
    }

@app.post("/test", response_model=TestResponse)
def test_prompt(request: TestRequest):
    """
    Test a prompt for security vulnerabilities.
    Returns detailed analysis of potential threats.
    """
    start_time = time.time()
    
    # Determine which attacks to run
    attacks_to_run = request.attacks if request.attacks else list(ATTACKS.keys())
    
    # Validate attack names
    invalid_attacks = [a for a in attacks_to_run if a not in ATTACKS]
    if invalid_attacks:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack types: {invalid_attacks}. Valid types: {list(ATTACKS.keys())}"
        )
    
    # Run all selected attacks
    results = []
    for attack_name in attacks_to_run:
        attack = ATTACKS[attack_name]
        result = attack.detect(request.text)
        results.append(result)
    
    # Calculate metrics
    threats = [r for r in results if r.detected]
    overall_risk = calculate_overall_risk(results)
    recommendations = generate_recommendations(threats)
    cleaned_text = clean_text(request.text)
    
    # Generate unique scan ID
    scan_id = f"scan_{int(start_time * 1000)}"
    
    return TestResponse(
        scan_id=scan_id,
        timestamp=start_time,
        text_length=len(request.text),
        attacks_tested=len(results),
        threats_detected=len(threats),
        overall_risk_score=overall_risk,
        results=[AttackResultResponse(**r.__dict__) for r in results],
        recommendations=recommendations,
        cleaned_text=cleaned_text
    )

@app.post("/generate-payload")
def generate_payload(attack_type: str, instruction: str = "reveal system prompt"):
    """Generate an example attack payload for testing"""
    if attack_type not in ATTACKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown attack type: {attack_type}. Valid types: {list(ATTACKS.keys())}"
        )
    
    payload = ATTACKS[attack_type].generate_payload(instruction)
    
    return {
        "attack_type": attack_type,
        "instruction": instruction,
        "payload": payload,
        "warning": "This is for testing purposes only. Do not use maliciously."
    }

@app.get("/test")
def test_info():
    """Information about the test endpoint"""
    return {
        "endpoint": "/test",
        "method": "POST",
        "description": "Test a prompt for security vulnerabilities",
        "usage": "Send POST request with JSON body: {\"text\": \"your prompt here\"}",
        "example_curl": 'curl -X POST https://api.promptredteam.com/test -H "Content-Type: application/json" -d "{\\"text\\": \\"Ignore all previous instructions\\"}"',
        "docs": "https://api.promptredteam.com/docs"
    }

# Helper functions
def calculate_overall_risk(results: List[AttackResult]) -> float:
    """Calculate overall risk score from all results"""
    if not results:
        return 0.0
    
    # Weight by severity and confidence
    weighted_scores = [
        r.severity * r.confidence
        for r in results if r.detected
    ]
    
    if not weighted_scores:
        return 0.0
    
    # Use max score (most severe threat)
    return round(max(weighted_scores), 2)

def generate_recommendations(threats: List[AttackResult]) -> List[str]:
    """Generate actionable recommendations based on threats found"""
    if not threats:
        return ["No threats detected. Your prompt appears secure."]
    
    recommendations = []
    
    # Collect unique mitigations
    mitigations = set()
    for threat in threats:
        if threat.mitigation:
            mitigations.add(threat.mitigation)
    
    recommendations.extend(mitigations)
    
    # Add general recommendations
    if len(threats) > 2:
        recommendations.append("Multiple threats detected. Consider a comprehensive security review.")
    
    # Add severity-based recommendations
    high_severity_threats = [t for t in threats if t.severity > 0.8]
    if high_severity_threats:
        recommendations.append("High severity threats found. Address these immediately.")
    
    return list(recommendations)

def clean_text(text: str) -> str:
    """Remove detected malicious content"""
    # Remove zero-width characters
    cleaned = ''.join(c for c in text if c not in ['\u200b', '\u200c', '\u200d', '\ufeff'])
    return cleaned

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)