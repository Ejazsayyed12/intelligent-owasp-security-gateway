"""
Risk Evaluation Engine
Intelligent OWASP Security Gateway
"""


def calculate_risk(attacks):

    total_risk = sum(attack["risk_score"] for attack in attacks)

    highest_severity = "Low"

    if any(a["severity"] == "Critical" for a in attacks):
        highest_severity = "Critical"

    elif any(a["severity"] == "High" for a in attacks):
        highest_severity = "High"

    elif any(a["severity"] == "Medium" for a in attacks):
        highest_severity = "Medium"

    return {
        "total_risk": total_risk,
        "highest_severity": highest_severity
    }