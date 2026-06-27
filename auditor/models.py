from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    # Python 3.11+ changed how str enums format inside f-strings.
    # Without this, you get "Severity.CRITICAL" instead of just "CRITICAL".
    def __str__(self):
        return self.value


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"

    def __str__(self):
        return self.value


# score = (points earned) / (total possible) * 100
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Status
    detail: str
    remediation: str = ""  # empty string if the check passed
    # CIS Cisco IOS Benchmark control number, e.g. "1.1.2".
    # Left empty for checks that are good practice but aren't numbered
    # controls in the published benchmark (see checks.py for which ones).
    cis_ref: str = ""


@dataclass
class DeviceResult:
    hostname: str
    ip: str
    findings: List[Finding] = field(default_factory=list)
    error: str = ""  # set if we couldn't connect to the device
    os_version: str = ""  # e.g. "17.09.04a", parsed from 'show version'
    model: str = ""  # e.g. "C8000V", parsed from 'show version'

    def score(self) -> int:
        if self.error or not self.findings:
            return 0

        total_possible = 0
        earned = 0

        for finding in self.findings:
            weight = SEVERITY_WEIGHTS[finding.severity]
            total_possible += weight
            if finding.status == Status.PASS:
                earned += weight

        return round((earned / total_possible) * 100)

    def grade(self) -> str:
        s = self.score()
        if s >= 90:
            return "A"
        elif s >= 75:
            return "B"
        elif s >= 60:
            return "C"
        elif s >= 45:
            return "D"
        else:
            return "F"

    def get_failures(self) -> List[Finding]:
        failures = []
        for finding in self.findings:
            if finding.status == Status.FAIL:
                failures.append(finding)
        return failures

    def get_passes(self) -> List[Finding]:
        passes = []
        for finding in self.findings:
            if finding.status == Status.PASS:
                passes.append(finding)
        return passes
