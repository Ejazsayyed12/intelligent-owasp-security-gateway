"""
Cross Site Scripting (XSS) Detection Module
Intelligent OWASP Security Gateway
"""

from models.attack_result import AttackResult
from config import MEDIUM, HIGH, CRITICAL


XSS_SIGNATURES = {

    "Script Injection": {
        "severity": HIGH,
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "<script",
            "</script>",
            "<script src"
        ]
    },

    "Event Handler Injection": {
        "severity": HIGH,
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "onload=",
            "onclick=",
            "onerror=",
            "onmouseover=",
            "onfocus=",
            "onmouseenter="
        ]
    },

    "JavaScript URI": {
        "severity": HIGH,
        "risk_score": 70,
        "recommendation": "Block Immediately",
        "patterns": [
            "javascript:",
            "javascript:alert",
            "javascript:void"
        ]
    },

    "HTML Injection": {
        "severity": MEDIUM,
        "risk_score": 40,
        "recommendation": "Monitor Request",
        "patterns": [
            "<iframe",
            "<object",
            "<embed",
            "<form"
        ]
    },

    "SVG Injection": {
        "severity": HIGH,
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "<svg",
            "<animate",
            "<foreignobject"
        ]
    },

    "DOM-Based XSS": {
        "severity": CRITICAL,
        "risk_score": 80,
        "recommendation": "Block Immediately",
        "patterns": [
            "document.cookie",
            "document.location",
            "window.location",
            "innerhtml"
        ]
    }

}


def detect_xss(payload: str) -> AttackResult:

    payload_lower = payload.lower()

    for category, details in XSS_SIGNATURES.items():

        for pattern in details["patterns"]:

            if pattern in payload_lower:

                return AttackResult(
                    detected=True,
                    attack_type="Cross Site Scripting",
                    category=category,
                    matched_pattern=pattern,
                    severity=details["severity"],
                    risk_score=details["risk_score"],
                    recommendation=details["recommendation"]
                )

    return AttackResult(
        detected=False
    )