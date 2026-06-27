"""
Handles connecting to devices and running the audit.

Inventory is defined in inventory/hosts.yaml and inventory/groups.yaml.
"""

import re

from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_command
from nornir.core.task import Task, Result
from typing import List, Tuple

from .models import DeviceResult
from .checks import run_all_checks


def _parse_version_info(version_text: str) -> Tuple[str, str]:
    """Pull the IOS/IOS XE software version and hardware model out of 'show version' output."""
    version_match = re.search(r'Version\s+([\w.()]+)', version_text)
    model_match = re.search(r'[Cc]isco\s+(\S+)\s+\(.*processor', version_text)

    os_version = version_match.group(1) if version_match else ""
    model = model_match.group(1) if model_match else ""
    return os_version, model


def _audit_single_device(task: Task) -> Result:
    """The function Nornir runs on each device in the inventory."""
    # use_textfsm=False: we want the raw config text, not parsed structured data
    show_result = task.run(
        task=netmiko_send_command,
        command_string="show running-config",
        use_textfsm=False,
    )

    config_text = show_result[0].result
    findings = run_all_checks(config_text)

    version_result = task.run(
        task=netmiko_send_command,
        command_string="show version",
        use_textfsm=False,
    )
    os_version, model = _parse_version_info(version_result[0].result)

    return Result(host=task.host, result={"findings": findings, "os_version": os_version, "model": model})


def run_audit(config_file: str = "nornir.yaml") -> List[DeviceResult]:
    """Run the audit on every host in the inventory, return one DeviceResult per device."""
    nr = InitNornir(config_file=config_file)

    print(f"  Found {len(nr.inventory.hosts)} device(s) in inventory")

    # num_workers (parallelism) is set in nornir.yaml
    all_results = nr.run(task=_audit_single_device)

    device_results = []

    for hostname, multi_result in all_results.items():
        host = nr.inventory.hosts[hostname]
        ip_address = str(host.hostname)

        if multi_result.failed:
            error_message = str(multi_result[0].exception)
            device_result = DeviceResult(
                hostname=hostname,
                ip=ip_address,
                error=error_message,
            )
            print(f"  [ERROR] {hostname} ({ip_address}) - {error_message}")
        else:
            audit_data = multi_result[0].result
            device_result = DeviceResult(
                hostname=hostname,
                ip=ip_address,
                findings=audit_data["findings"],
                os_version=audit_data["os_version"],
                model=audit_data["model"],
            )

        device_results.append(device_result)

    return device_results
