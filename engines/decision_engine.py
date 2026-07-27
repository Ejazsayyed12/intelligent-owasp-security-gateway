from config import BLOCK_THRESHOLD, MONITOR_THRESHOLD
from config import BLOCK, MONITOR, ALLOW


def make_decision(total_risk):

    if total_risk >= BLOCK_THRESHOLD:
        return BLOCK

    elif total_risk >= MONITOR_THRESHOLD:
        return MONITOR

    return ALLOW