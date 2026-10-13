"""
Shared building blocks for all analyzers.

An analyzer looks at one aspect of an email and returns a list of Findings.
Each Finding carries its own risk points and a human-readable reason,
so every point in the final score can be explained to the user.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    signal: str   # stable machine-readable id, e.g. "dmarc_fail"
    points: int   # how much risk this adds to the score
    reason: str   # explanation shown to the user
