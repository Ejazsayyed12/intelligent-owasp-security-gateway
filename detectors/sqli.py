"""
SQL Injection Detection Module
Intelligent OWASP Security Gateway
"""

SQLI_SIGNATURES = {

    "Authentication Bypass": {
        "severity": "Medium",
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
        "severity": "High",
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "union select",
            "union all select"
        ]
    },

    "Database Enumeration": {
        "severity": "High",
        "risk_score": 60,
        "recommendation": "Block Request",
        "patterns": [
            "information_schema",
            "sqlite_master",
            "sysobjects"
        ]
    },

    "Blind SQL Injection": {
        "severity": "High",
        "risk_score": 70,
        "recommendation": "Block Immediately",
        "patterns": [
            "sleep(",
            "benchmark(",
            "waitfor delay"
        ]
    },

    "Destructive Query": {
        "severity": "Critical",
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


def detect_sqli(payload: str):

    payload_lower = payload.lower()

    print(f"\nPayload Received: {payload_lower}")

    for category, details in SQLI_SIGNATURES.items():

        print(f"\nChecking Category: {category}")

        for pattern in details["patterns"]:

            print(f"Checking Pattern: {pattern}")

            if pattern in payload_lower:

                print("MATCH FOUND!")

                return {
                    "detected": True,
                    "attack_type": "SQL Injection",
                    "category": category,
                    "matched_pattern": pattern,
                    "severity": details["severity"],
                    "risk_score": details["risk_score"],
                    "recommendation": details["recommendation"]
                }

    print("NO MATCH FOUND")

    return {
        "detected": False
    }