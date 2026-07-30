"""
Broken Access Control Detection Module
Intelligent OWASP Security Gateway
"""

from models.attack_result import AttackResult
from config import LOW, MEDIUM, HIGH, CRITICAL

BAC_SIGNATURES = {

    "Admin Resource Access": {
        "severity": CRITICAL,
        "risk_score": 95,
        "recommendation": "Block Immediately",
        "patterns": [
            "/admin",
            "/administrator",
            "/admin/login",
            "/admin/dashboard",
            "/admin/users"
        ]
    },

    "Sensitive API Access": {
        "severity": HIGH,
        "risk_score": 80,
        "recommendation": "Verify Authorization",
        "patterns": [
            "/api/admin",
            "/api/users",
            "/api/accounts",
            "/api/settings",
            "/api/config"
        ]
    },

    "Restricted System Files": {
        "severity": CRITICAL,
        "risk_score": 95,
        "recommendation": "Block Immediately",
        "patterns": [
            "/etc/passwd",
            "/etc/shadow",
            "/boot.ini",
            "/windows/system32"
        ]
    },

    "Authentication Bypass Attempts": {
        "severity": HIGH,
        "risk_score": 85,
        "recommendation": "Require Authentication",
        "patterns": [
            "/login?admin=true",
            "/auth/bypass",
            "/bypass",
            "role=admin"
        ]
    },

    "Forced Browsing": {
        "severity": MEDIUM,
        "risk_score": 65,
        "recommendation": "Monitor Request",
        "patterns": [
            "/backup",
            "/private",
            "/hidden",
            "/internal",
            "/secret"
        ]
    }

}


def detect_broken_access_control(payload: str) -> AttackResult:

    payload_lower = payload.lower()

    for category, details in BAC_SIGNATURES.items():

        for pattern in details["patterns"]:

            if pattern in payload_lower:

                return AttackResult(
                    detected=True,
                    attack_type="Broken Access Control",
                    category=category,
                    matched_pattern=pattern,
                    severity=details["severity"],
                    risk_score=details["risk_score"],
                    recommendation=details["recommendation"]
                )

    return AttackResult(
        detected=False
    )