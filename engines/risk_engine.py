"""
Risk Evaluation Engine
Intelligent OWASP Security Gateway
"""

from config import LOW, MEDIUM, HIGH, CRITICAL


def calculate_risk(attacks):

    total_risk = sum(attack.risk_score for attack in attacks)

    highest_severity = LOW

    if any(a.severity == CRITICAL for a in attacks):
        highest_severity = CRITICAL

    elif any(a.severity == HIGH for a in attacks):
        highest_severity = HIGH

    elif any(a.severity == MEDIUM for a in attacks):
        highest_severity = MEDIUM

    return {
        "total_risk": total_risk,
        "highest_severity": highest_severity
    }