from pydantic import BaseModel


class AttackResult(BaseModel):

    detected: bool

    attack_type: str = ""

    category: str = ""

    matched_pattern: str = ""

    severity: str = ""

    risk_score: int = 0

    recommendation: str = ""