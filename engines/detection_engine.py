from detectors.sqli import detect_sqli
from detectors.xss import detect_xss
from detectors.command_injection import detect_command_injection

from engines.risk_engine import calculate_risk
from engines.decision_engine import make_decision


def analyze_request(payload: str):

    print("\n" + "=" * 60)
    print("      INTELLIGENT OWASP SECURITY GATEWAY")
    print("=" * 60)

    print(f"\nIncoming Payload:\n{payload}")

    detected_attacks = []

    detectors = [
        detect_sqli,
        detect_xss,
        detect_command_injection
    ]

    for detector in detectors:

        result = detector(payload)

        if result.detected:
            detected_attacks.append(result)

    if not detected_attacks:

        print("\nNo threats detected.")
        print("Gateway Decision : ALLOW")

        return {
            "detected": False,
            "decision": "ALLOW",
            "risk_score": 0,
            "highest_severity": "",
            "attacks": []
        }

    risk = calculate_risk(detected_attacks)

    decision = make_decision(risk["total_risk"])

    print("\nDetected Attacks")
    print("-" * 60)

    for attack in detected_attacks:

        print(f"""
Attack Type      : {attack.attack_type}
Category         : {attack.category}
Pattern          : {attack.matched_pattern}
Severity         : {attack.severity}
Risk Score       : {attack.risk_score}
Recommendation   : {attack.recommendation}
""")

    print("-" * 60)

    print(f"Highest Severity : {risk['highest_severity']}")
    print(f"Total Risk Score : {risk['total_risk']}")
    print(f"Gateway Decision : {decision}")
    print("=" * 60)

    return {
        "detected": True,
        "decision": decision,
        "risk_score": risk["total_risk"],
        "highest_severity": risk["highest_severity"],
        "attacks": [attack.model_dump() for attack in detected_attacks]
    }