"""
SQL Injection Detection Module
Intelligent OWASP Security Gateway
"""

from models.attack_result import AttackResult
from config import MEDIUM, HIGH, CRITICAL


SQLI_SIGNATURES = {

    "Authentication Bypass": {
        "severity": MEDIUM,
        "risk_score": 40,
        "recommendation": "Block Request",
        "patterns": [
            "or 1=1",
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "'--",
            "--"
        ]
    },

    "UNION Injection": {
        "severity": HIGH,
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "union select",
            "union all select"
        ]
    },

    "Database Enumeration": {
        "severity": HIGH,
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "information_schema",
            "sqlite_master",
            "sysobjects"
        ]
    },

    "Blind SQL Injection": {
        "severity": HIGH,
        "risk_score": 70,
        "recommendation": "Block Immediately",
        "patterns": [
            "sleep(",
            "benchmark(",
            "waitfor delay"
        ]
    },

    "Destructive Query": {
        "severity": CRITICAL,
        "risk_score": 90,
        "recommendation": "Block Immediately",
        "patterns": [
            "drop table",
            "delete from",
            "truncate table",
            "alter table",
            "update "
        ]
    }

}


def detect_sqli(payload: str) -> AttackResult:

    payload_lower = payload.lower()

    for category, details in SQLI_SIGNATURES.items():

        for pattern in details["patterns"]:

            if pattern in payload_lower:

                return AttackResult(
                    detected=True,
                    attack_type="SQL Injection",
                    category=category,
                    matched_pattern=pattern,
                    severity=details["severity"],
                    risk_score=details["risk_score"],
                    recommendation=details["recommendation"]
                )

    return AttackResult(
        detected=False
    )