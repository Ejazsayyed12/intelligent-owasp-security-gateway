"""
Command Injection Detection Module
Intelligent OWASP Security Gateway
"""

from models.attack_result import AttackResult
from config import MEDIUM, HIGH, CRITICAL


COMMAND_SIGNATURES = {

    "Command Chaining": {
        "severity": HIGH,
        "risk_score": 70,
        "recommendation": "Block Immediately",
        "patterns": [
            "&&",
            ";",
            "||",
            "|"
        ]
    },

    "Linux Commands": {
        "severity": HIGH,
        "risk_score": 70,
        "recommendation": "Block Immediately",
        "patterns": [
            " ls ",
            " cat ",
            " pwd",
            " chmod ",
            " chown ",
            " wget ",
            " curl ",
            " find "
        ]
    },

    "Windows Commands": {
        "severity": HIGH,
        "risk_score": 70,
        "recommendation": "Block Immediately",
        "patterns": [
            "cmd.exe",
            "powershell",
            " dir ",
            " type ",
            " copy ",
            " move "
        ]
    },

    "Network Commands": {
        "severity": MEDIUM,
        "risk_score": 50,
        "recommendation": "Monitor Request",
        "patterns": [
            " ping ",
            " netstat ",
            " nslookup ",
            " tracert ",
            " curl ",
            " wget ",
            " nc "
        ]
    },

    "File Manipulation": {
        "severity": CRITICAL,
        "risk_score": 90,
        "recommendation": "Block Immediately",
        "patterns": [
            " rm ",
            " del ",
            " mv ",
            " rmdir ",
            " unlink "
        ]
    },

    "Privilege/System Commands": {
        "severity": CRITICAL,
        "risk_score": 90,
        "recommendation": "Block Immediately",
        "patterns": [
            " sudo ",
            " su ",
            " whoami",
            "net user",
            "net localgroup"
        ]
    }

}


def detect_command_injection(payload: str) -> AttackResult:

    payload_lower = f" {payload.lower()} "

    for category, details in COMMAND_SIGNATURES.items():

        for pattern in details["patterns"]:

            if pattern in payload_lower:

                return AttackResult(
                    detected=True,
                    attack_type="Command Injection",
                    category=category,
                    matched_pattern=pattern,
                    severity=details["severity"],
                    risk_score=details["risk_score"],
                    recommendation=details["recommendation"]
                )

    return AttackResult(
        detected=False
    )