"""
Security Misconfiguration Detection Module
Intelligent OWASP Security Gateway
"""

from models.attack_result import AttackResult
from config import MEDIUM, HIGH, CRITICAL

SECURITY_MISCONFIG_SIGNATURES = {

    "Exposed Configuration Files": {
        "severity": CRITICAL,
        "risk_score": 95,
        "recommendation": "Block Immediately",
        "patterns": [
            ".env",
            "config.php",
            "config.yml",
            "config.yaml",
            "web.config"
        ]
    },

    "Exposed Version Control": {
        "severity": CRITICAL,
        "risk_score": 95,
        "recommendation": "Block Immediately",
        "patterns": [
            ".git",
            ".svn",
            ".hg"
        ]
    },

    "Backup Files": {
        "severity": HIGH,
        "risk_score": 80,
        "recommendation": "Block Immediately",
        "patterns": [
            ".bak",
            ".old",
            ".backup",
            ".zip",
            ".tar",
            ".sql"
        ]
    },

    "Debug Files": {
        "severity": HIGH,
        "risk_score": 75,
        "recommendation": "Disable Debug Mode",
        "patterns": [
            "phpinfo.php",
            "debug",
            "trace",
            "stacktrace"
        ]
    },

    "Server Information Disclosure": {
        "severity": MEDIUM,
        "risk_score": 60,
        "recommendation": "Restrict Server Information",
        "patterns": [
            "server-status",
            "server-info",
            "robots.txt"
        ]
    }

}


def detect_security_misconfiguration(payload: str) -> AttackResult:

    payload_lower = payload.lower()

    for category, details in SECURITY_MISCONFIG_SIGNATURES.items():

        for pattern in details["patterns"]:

            if pattern in payload_lower:

                return AttackResult(
                    detected=True,
                    attack_type="Security Misconfiguration",
                    category=category,
                    matched_pattern=pattern,
                    severity=details["severity"],
                    risk_score=details["risk_score"],
                    recommendation=details["recommendation"]
                )

    return AttackResult(
        detected=False
    )
