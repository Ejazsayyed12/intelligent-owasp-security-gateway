"""
Decision Engine
Intelligent OWASP Security Gateway
"""


def make_decision(total_risk):

    if total_risk >= 80:
        return "BLOCK"

    elif total_risk >= 40:
        return "MONITOR"

    return "ALLOW"