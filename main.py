"""
Cisco Device Security Auditor.

Connects to Cisco IOS devices via SSH, runs CIS Benchmark hardening checks
against the running config, and generates an HTML report with a security
score for each device.

Usage:
    python main.py
    python main.py --config nornir.yaml --output my_report.html
    python main.py --no-report
"""

import argparse
import sys

from auditor.scanner import run_audit
from auditor.report import generate_report
from auditor.models import Status, Severity


def print_results_to_terminal(devices):
    """Print a summary of each device's findings to the terminal."""

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

    for device in devices:
        if device.error:
            print(f"\n  [{device.hostname}]  ERROR - could not connect")
            print(f"  {device.error}")
            continue

        print(f"\n  [{device.hostname}]  {device.ip}")
        print(f"  Score: {device.score()}/100  Grade: {device.grade()}")
        print()

        for severity_level in severity_order:
            failures_at_this_level = []
            for finding in device.findings:
                if finding.severity == severity_level and finding.status == Status.FAIL:
                    failures_at_this_level.append(finding)

            for finding in failures_at_this_level:
                print(f"    [FAIL] [{finding.check_id}] {finding.severity:<8}  {finding.title}")

        pass_count = len(device.get_passes())
        fail_count = len(device.get_failures())
        print(f"\n  {pass_count} passed, {fail_count} failed")


def main():
    parser = argparse.ArgumentParser(
        description="Audit Cisco devices for CIS Benchmark hardening compliance"
    )
    parser.add_argument(
        "--config",
        default="nornir.yaml",
        help="Path to the Nornir config file (default: nornir.yaml)"
    )
    parser.add_argument(
        "--output",
        default="audit_report.html",
        help="Where to save the HTML report (default: audit_report.html)"
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip HTML report, just print results to the terminal"
    )
    args = parser.parse_args()

    print("\ncisco-auditor - connecting to devices...\n")

    devices = run_audit(config_file=args.config)

    print_results_to_terminal(devices)

    if not args.no_report:
        output_path = generate_report(devices, output_path=args.output)
        print(f"\n  Report saved to: {output_path}\n")
    else:
        print()

    # non-zero exit on CRITICAL/HIGH so this can gate a CI pipeline
    has_critical_or_high_failures = False
    for device in devices:
        for finding in device.findings:
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                if finding.status == Status.FAIL:
                    has_critical_or_high_failures = True
                    break

    if has_critical_or_high_failures:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
