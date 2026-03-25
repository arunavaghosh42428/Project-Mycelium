"""
Threat Classifier – Phase 3 rule-based model.
Designed to be swapped for an RL model in a later phase.
"""
import time
from collections import defaultdict
from typing import Tuple


# Severity multipliers per threat type
THREAT_WEIGHTS = {
    "port_scan":         1.0,
    "brute_force":       1.3,
    "exploit_attempt":   1.8,
    "credential_harvest":1.5,
    "recon":             0.8,
    "unknown":           0.5,
}

# If the same IP generates X events in Y seconds, multiply severity
BURST_WINDOW = 60   # seconds
BURST_THRESH = 10   # events


class ThreatClassifier:
    def __init__(self):
        # ip -> list of (timestamp, raw_severity)
        self._history: dict = defaultdict(list)

    def classify(self, source_ip: str, threat_type: str,
                  raw_severity: float, extra: dict = None
                  ) -> Tuple[float, float]:
        """
        Returns (confidence, adjusted_severity) both in [0.0, 1.0].

        Confidence rises with:
          - Repeated events from the same IP
          - Higher-weight threat types
          - Burst patterns
        """
        now    = time.time()
        hist   = self._history[source_ip]
        hist.append((now, raw_severity))
        # Trim old entries
        self._history[source_ip] = [(t, s) for t, s in hist if now - t < 600]

        type_weight = THREAT_WEIGHTS.get(threat_type, 0.5)
        event_count = len(self._history[source_ip])

        # Burst multiplier
        burst_events = sum(1 for t, _ in self._history[source_ip]
                           if now - t < BURST_WINDOW)
        burst_mult = min(2.0, 1 + (burst_events / BURST_THRESH) * 0.5)

        # Repetition confidence
        rep_conf = min(1.0, event_count / 20)

        adjusted_severity = min(1.0, raw_severity * type_weight * burst_mult)
        confidence        = min(1.0, rep_conf * 0.5 + adjusted_severity * 0.5)

        return round(confidence, 4), round(adjusted_severity, 4)
