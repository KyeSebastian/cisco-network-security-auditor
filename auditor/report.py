"""
Generates the HTML audit report from templates/report.html.j2 via Jinja2.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader

from .checks import ALL_CHECKS
from .models import DeviceResult, Finding, Severity, Status, SEVERITY_WEIGHTS

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

# Defines what each severity means and how much it costs in the weighted
# score - shown directly in the report so the rating scale isn't implicit.
SEVERITY_DEFINITIONS = [
    {
        "severity": Severity.CRITICAL,
        "weight": SEVERITY_WEIGHTS[Severity.CRITICAL],
        "description": "Immediately exploitable with direct, unauthenticated impact - plaintext credentials, default access strings, or no authentication required at all.",
    },
    {
        "severity": Severity.HIGH,
        "weight": SEVERITY_WEIGHTS[Severity.HIGH],
        "description": "Materially weakens authentication, encryption, or centralized access control, significantly increasing the odds of compromise.",
    },
    {
        "severity": Severity.MEDIUM,
        "weight": SEVERITY_WEIGHTS[Severity.MEDIUM],
        "description": "Reduces resilience against brute-force attempts, session hijacking, or incident investigation; exploitation requires additional conditions.",
    },
    {
        "severity": Severity.LOW,
        "weight": SEVERITY_WEIGHTS[Severity.LOW],
        "description": "Best-practice or compliance-notice gap with limited direct security impact on its own.",
    },
]


def _organize_findings(device: DeviceResult) -> Dict[str, List[Finding]]:
    """
    Split one device's findings into the three sections the report renders:

    - exceptions: failing CIS-numbered controls, worst severity first
    - verified: passing CIS-numbered controls, in benchmark control order
    - recommendations: checks that aren't numbered controls in the published
      CIS benchmark (banner, NTP) but are still good practice

    Numbered vs. unnumbered is determined by Finding.cis_ref - see checks.py
    for which checks carry a real CIS Cisco IOS Benchmark control number.
    """
    numbered = [f for f in device.findings if f.cis_ref]
    unnumbered = [f for f in device.findings if not f.cis_ref]

    exceptions = sorted(
        (f for f in numbered if f.status == Status.FAIL),
        key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.cis_ref)
    )
    verified = sorted(
        (f for f in numbered if f.status == Status.PASS),
        key=lambda f: f.cis_ref
    )
    recommendations = sorted(
        unnumbered,
        key=lambda f: _SEVERITY_ORDER.index(f.severity)
    )

    return {"exceptions": exceptions, "verified": verified, "recommendations": recommendations}


def _count_failures_by_severity(devices: List[DeviceResult], severity: Severity) -> int:
    """
    Count how many checks of a given severity failed across all devices.
    Used to build the fleet-wide summary bar at the top of the report.
    """
    total = 0
    for device in devices:
        for finding in device.findings:
            if finding.severity == severity and finding.status == Status.FAIL:
                total += 1
    return total


def _count_all_passes(devices: List[DeviceResult]) -> int:
    """Count total passing checks across all devices."""
    total = 0
    for device in devices:
        for finding in device.findings:
            if finding.status == Status.PASS:
                total += 1
    return total


def _build_fleet_summary(devices: List[DeviceResult]) -> List[Dict]:
    """
    One row per device for the fleet-wide summary table at the top of the
    report, so a reader auditing many devices can triage without reading
    every per-device section.
    """
    summary = []
    for device in devices:
        if device.error:
            summary.append({
                "hostname": device.hostname,
                "ip": device.ip,
                "incomplete": True,
                "grade": "-",
                "score": "-",
                "exceptions": "-",
            })
        else:
            summary.append({
                "hostname": device.hostname,
                "ip": device.ip,
                "incomplete": False,
                "grade": device.grade(),
                "score": device.score(),
                "exceptions": len(device.get_failures()),
            })
    return summary


def _build_action_items(devices: List[DeviceResult]) -> List[Dict]:
    """
    Deduplicate failing findings across the whole fleet into a single
    prioritized punch list (worst severity first), with the list of
    affected hosts attached to each item - instead of making the reader
    collect the same remediation command from every device section.
    """
    items_by_check: Dict[str, Dict] = {}

    for device in devices:
        if device.error:
            continue
        for finding in device.findings:
            if finding.status != Status.FAIL:
                continue
            if finding.check_id not in items_by_check:
                items_by_check[finding.check_id] = {
                    "check_id": finding.check_id,
                    "cis_ref": finding.cis_ref,
                    "title": finding.title,
                    "severity": finding.severity,
                    "remediation": finding.remediation,
                    "hosts": [],
                }
            items_by_check[finding.check_id]["hosts"].append(device.hostname)

    return sorted(
        items_by_check.values(),
        key=lambda item: (_SEVERITY_ORDER.index(item["severity"]), item["check_id"]),
    )


def generate_report(
    devices: List[DeviceResult],
    output_path: str = "audit_report.html",
    template_dir: str = "templates",
) -> str:
    """
    Render the HTML report and write it to output_path.
    Returns the output path so the caller can print it.
    """
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html.j2")

    total_checks = 0
    for device in devices:
        if not device.error:
            total_checks += len(device.findings)

    # pre-split so the template doesn't re-derive grouping with Jinja filters
    sections_by_host = {device.hostname: _organize_findings(device) for device in devices if not device.error}

    template_data = {
        "devices": devices,
        "sections_by_host": sections_by_host,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_devices": len(devices),
        "total_checks": total_checks,
        "fleet_critical": _count_failures_by_severity(devices, Severity.CRITICAL),
        "fleet_high": _count_failures_by_severity(devices, Severity.HIGH),
        "fleet_medium": _count_failures_by_severity(devices, Severity.MEDIUM),
        "fleet_low": _count_failures_by_severity(devices, Severity.LOW),
        "fleet_pass": _count_all_passes(devices),
        "fleet_summary": _build_fleet_summary(devices),
        "action_items": _build_action_items(devices),
        "severity_definitions": SEVERITY_DEFINITIONS,
        "controls_in_scope": len(ALL_CHECKS),
    }

    html_output = template.render(**template_data)
    Path(output_path).write_text(html_output, encoding="utf-8")

    return output_path
