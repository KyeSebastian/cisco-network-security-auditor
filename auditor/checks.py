"""
Security checks based on the CIS Cisco IOS Benchmark.

Each check function takes the raw running-config text as a string,
looks for a specific misconfiguration, and returns a Finding with
the result. All checks are independent - they don't call each other.

To add a new check: write the function, append it to ALL_CHECKS at the bottom.
"""

import re
from typing import List
from .models import Finding, Severity, Status


def _get_vty_blocks(config: str) -> List[str]:
    """
    Pull every 'line vty' block out of the config, header plus everything
    indented under it, up to the next top-level statement.
    """
    pattern = re.compile(
        r'(line vty[^\n]*\n(?:(?! *line )[ \t][^\n]*\n)*)',
        re.MULTILINE
    )
    return pattern.findall(config)


def _get_console_blocks(config: str) -> List[str]:
    """Same as _get_vty_blocks but for the console port (line con 0)."""
    pattern = re.compile(
        r'(line con[^\n]*\n(?:(?! *line )[ \t][^\n]*\n)*)',
        re.MULTILINE
    )
    return pattern.findall(config)


# CRITICAL checks

def check_telnet_disabled(config: str) -> Finding:
    """Check that Telnet is disabled on VTY lines (CIS Benchmark 1.1.2)."""
    vty_blocks = _get_vty_blocks(config)

    for block in vty_blocks:
        # 'transport input all' also includes telnet, not just explicit 'telnet'
        if re.search(r'transport input\s+(telnet|all)', block):
            return Finding(
                check_id="C01",
                title="Ensure Telnet is disabled on VTY lines",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                detail="One or more VTY lines allow Telnet. Credentials are transmitted in plaintext.",
                remediation="Under each 'line vty' block, run: transport input ssh",
                cis_ref="1.1.2",
            )

    return Finding(
        check_id="C01",
        title="Ensure Telnet is disabled on VTY lines",
        severity=Severity.CRITICAL,
        status=Status.PASS,
        detail="No VTY lines permit Telnet.",
        cis_ref="1.1.2",
    )


def check_snmp_default_communities(config: str) -> Finding:
    """Check for default SNMP community strings 'public'/'private' (CIS Benchmark 3.2.1)."""
    found_default = re.search(
        r'snmp-server community\s+(public|private)\b',
        config,
        re.IGNORECASE
    )

    if found_default:
        return Finding(
            check_id="C02",
            title="Ensure default SNMP community strings are not used",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            detail="Device uses 'public' or 'private' SNMP community strings - the factory defaults.",
            remediation="Run: no snmp-server community public\nno snmp-server community private",
            cis_ref="3.2.1",
        )

    return Finding(
        check_id="C02",
        title="Ensure default SNMP community strings are not used",
        severity=Severity.CRITICAL,
        status=Status.PASS,
        detail="No default SNMP community strings detected.",
        cis_ref="3.2.1",
    )


def check_console_auth(config: str) -> Finding:
    """Check that the console port requires a password (CIS Benchmark 1.2.1)."""
    console_blocks = _get_console_blocks(config)

    for block in console_blocks:
        has_no_login = bool(re.search(r'\bno login\b', block))
        # Behavior with no 'login' statement at all varies by IOS version; flag as failure to be safe
        has_login = bool(re.search(r'\blogin\b', block))

        if has_no_login or not has_login:
            return Finding(
                check_id="C03",
                title="Ensure console port requires authentication",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                detail="Console line (line con 0) has no login requirement - physical access grants full CLI.",
                remediation="Under 'line con 0', run: login local",
                cis_ref="1.2.1",
            )

    return Finding(
        check_id="C03",
        title="Ensure console port requires authentication",
        severity=Severity.CRITICAL,
        status=Status.PASS,
        detail="Console port requires authentication.",
        cis_ref="1.2.1",
    )


# HIGH checks

def check_ssh_version_2(config: str) -> Finding:
    """Check that SSH version 2 is explicitly configured (CIS Benchmark 1.1.1)."""
    if re.search(r'ip ssh version 1\b', config):
        return Finding(
            check_id="H01",
            title="Ensure SSH version 2 is enforced",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="SSH version 1 is configured. It has known cryptographic weaknesses.",
            remediation="Run: ip ssh version 2",
            cis_ref="1.1.1",
        )

    # If v2 isn't explicitly set either, some IOS versions will still negotiate v1
    if not re.search(r'ip ssh version 2\b', config):
        return Finding(
            check_id="H01",
            title="Ensure SSH version 2 is enforced",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="SSH version 2 is not explicitly set - device may negotiate version 1.",
            remediation="Run: ip ssh version 2",
            cis_ref="1.1.1",
        )

    return Finding(
        check_id="H01",
        title="Ensure SSH version 2 is enforced",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="SSH version 2 is explicitly enforced.",
        cis_ref="1.1.1",
    )


def check_password_encryption(config: str) -> Finding:
    """Check that 'service password-encryption' is enabled (CIS Benchmark 2.1.1)."""
    if not re.search(r'service password-encryption', config):
        return Finding(
            check_id="H02",
            title="Ensure password encryption service is enabled",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="'service password-encryption' is off - passwords in the running config may be stored in plaintext.",
            remediation="Run: service password-encryption",
            cis_ref="2.1.1",
        )

    return Finding(
        check_id="H02",
        title="Ensure password encryption service is enabled",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="Password encryption service is enabled.",
        cis_ref="2.1.1",
    )


def check_aaa_new_model(config: str) -> Finding:
    """Check that AAA (Authentication, Authorization, Accounting) is enabled (CIS Benchmark 2.2.1)."""
    if not re.search(r'aaa new-model', config):
        return Finding(
            check_id="H03",
            title="Ensure AAA new-model is configured",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="AAA is not enabled. Without it, centralized authentication and command logging can't be enforced.",
            remediation="Run: aaa new-model",
            cis_ref="2.2.1",
        )

    return Finding(
        check_id="H03",
        title="Ensure AAA new-model is configured",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="AAA new-model is enabled.",
        cis_ref="2.2.1",
    )


def check_http_server_disabled(config: str) -> Finding:
    """Check that the HTTP management server is disabled (CIS Benchmark 1.3.1)."""
    # Need both checks since the config may explicitly include 'no ip http server'
    explicitly_disabled = bool(re.search(r'no ip http server', config))
    explicitly_enabled = bool(re.search(r'^ip http server', config, re.MULTILINE))

    if explicitly_enabled and not explicitly_disabled:
        return Finding(
            check_id="H04",
            title="Ensure HTTP management server is disabled",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="Unencrypted HTTP management interface is active. Login credentials are sent in cleartext.",
            remediation="Run: no ip http server",
            cis_ref="1.3.1",
        )

    return Finding(
        check_id="H04",
        title="Ensure HTTP management server is disabled",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="HTTP management server is disabled.",
        cis_ref="1.3.1",
    )


# MEDIUM checks

def check_login_rate_limiting(config: str) -> Finding:
    """Check that login rate limiting ('login block-for') is configured (CIS Benchmark 1.4.1)."""
    if not re.search(r'login block-for', config):
        return Finding(
            check_id="M01",
            title="Ensure login rate limiting is configured",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail="No 'login block-for' is set - brute force login attempts are not throttled.",
            remediation="Run: login block-for 60 attempts 3 within 30",
            cis_ref="1.4.1",
        )

    return Finding(
        check_id="M01",
        title="Ensure login rate limiting is configured",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="Login rate limiting is configured.",
        cis_ref="1.4.1",
    )


def check_vty_timeout(config: str) -> Finding:
    """Check that VTY lines have an idle timeout configured (CIS Benchmark 1.2.3)."""
    vty_blocks = _get_vty_blocks(config)

    for block in vty_blocks:
        set_to_never = bool(re.search(r'exec-timeout 0 0', block))
        not_set = not bool(re.search(r'exec-timeout', block))

        if set_to_never or not_set:
            return Finding(
                check_id="M02",
                title="Ensure VTY idle timeout is configured",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                detail="VTY lines have no idle timeout - abandoned sessions stay open forever.",
                remediation="Under each 'line vty' block, run: exec-timeout 10 0",
                cis_ref="1.2.3",
            )

    return Finding(
        check_id="M02",
        title="Ensure VTY idle timeout is configured",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="VTY idle timeout is configured.",
        cis_ref="1.2.3",
    )


def check_ip_source_routing(config: str) -> Finding:
    """Check that IP source routing is disabled (CIS Benchmark 3.1.2)."""
    explicitly_disabled = bool(re.search(r'no ip source-route', config))
    explicitly_enabled = bool(re.search(r'^ip source-route', config, re.MULTILINE))

    if explicitly_enabled and not explicitly_disabled:
        return Finding(
            check_id="M03",
            title="Ensure IP source routing is disabled",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail="IP source routing is on. Attackers can use it to influence how packets are routed.",
            remediation="Run: no ip source-route",
            cis_ref="3.1.2",
        )

    return Finding(
        check_id="M03",
        title="Ensure IP source routing is disabled",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="IP source routing is disabled.",
        cis_ref="3.1.2",
    )


def check_logging_host(config: str) -> Finding:
    """Check that a remote syslog server is configured (CIS Benchmark 4.1.1)."""
    if not re.search(r'logging host', config):
        return Finding(
            check_id="M04",
            title="Ensure remote syslog host is configured",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail="No remote syslog server is configured - logs are lost on reboot or if an attacker clears them.",
            remediation="Run: logging host <your-syslog-server-ip>",
            cis_ref="4.1.1",
        )

    return Finding(
        check_id="M04",
        title="Ensure remote syslog host is configured",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="Remote syslog host is configured.",
        cis_ref="4.1.1",
    )


def check_timestamps(config: str) -> Finding:
    """Check that syslog timestamps are enabled (CIS Benchmark 4.1.2)."""
    if not re.search(r'service timestamps log', config):
        return Finding(
            check_id="M05",
            title="Ensure log timestamps are configured",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail="Syslog messages don't include real timestamps - incident timeline correlation is unreliable.",
            remediation="Run: service timestamps log datetime msec",
            cis_ref="4.1.2",
        )

    return Finding(
        check_id="M05",
        title="Ensure log timestamps are configured",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="Log timestamps are configured.",
        cis_ref="4.1.2",
    )


# LOW checks

def check_banner_configured(config: str) -> Finding:
    """Check that a login banner is configured."""
    # motd is the most common, but login and exec banners also satisfy this
    if not re.search(r'banner (motd|login|exec)', config):
        return Finding(
            check_id="L01",
            title="Ensure a login banner is configured",
            severity=Severity.LOW,
            status=Status.FAIL,
            detail="No login banner is set. Compliance frameworks require an authorized-use-only warning before login.",
            remediation="Add a 'banner motd' with an authorized-use-only legal notice."
        )

    return Finding(
        check_id="L01",
        title="Ensure a login banner is configured",
        severity=Severity.LOW,
        status=Status.PASS,
        detail="Login banner is configured.",
    )


def check_ntp_configured(config: str) -> Finding:
    """Check that an NTP server is configured."""
    if not re.search(r'ntp server', config):
        return Finding(
            check_id="L02",
            title="Ensure an NTP server is configured",
            severity=Severity.LOW,
            status=Status.FAIL,
            detail="No NTP server configured - device clock drifts and log timestamps become unreliable.",
            remediation="Run: ntp server <ntp-server-ip>"
        )

    return Finding(
        check_id="L02",
        title="Ensure an NTP server is configured",
        severity=Severity.LOW,
        status=Status.PASS,
        detail="NTP server is configured.",
    )


def check_small_servers_disabled(config: str) -> Finding:
    """Check that TCP and UDP small servers are disabled (CIS Benchmark 3.1.1)."""
    tcp_on = bool(re.search(r'service tcp-small-servers', config))
    udp_on = bool(re.search(r'service udp-small-servers', config))

    if tcp_on or udp_on:
        return Finding(
            check_id="L03",
            title="Ensure TCP/UDP small servers are disabled",
            severity=Severity.LOW,
            status=Status.FAIL,
            detail="Legacy diagnostic services (echo, chargen, discard) are active and can be abused in DoS attacks.",
            remediation="Run: no service tcp-small-servers\nno service udp-small-servers",
            cis_ref="3.1.1",
        )

    return Finding(
        check_id="L03",
        title="Ensure TCP/UDP small servers are disabled",
        severity=Severity.LOW,
        status=Status.PASS,
        detail="TCP/UDP small servers are disabled.",
        cis_ref="3.1.1",
    )


# Control plane and CVE-driven checks, added on top of the management-plane
# checks above. None carry a cis_ref - see report under Additional Recommendations.

def _get_control_plane_block(config: str) -> str:
    """Pull the 'control-plane' block out of the config, same approach as the line-block helpers above."""
    pattern = re.compile(
        r'(control-plane[^\n]*\n(?:(?! *control-plane)[ \t][^\n]*\n)*)',
        re.MULTILINE
    )
    match = pattern.search(config)
    return match.group(1) if match else ""


def check_smart_install_disabled(config: str) -> Finding:
    """Check that the Cisco Smart Install client is disabled (no vstack)."""
    if not re.search(r'no vstack', config):
        return Finding(
            check_id="C04",
            title="Ensure the Smart Install client is disabled",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            detail="Smart Install client is not explicitly disabled. This service has a documented history of unauthenticated remote exploitation.",
            remediation="Run: no vstack",
        )

    return Finding(
        check_id="C04",
        title="Ensure the Smart Install client is disabled",
        severity=Severity.CRITICAL,
        status=Status.PASS,
        detail="Smart Install client is disabled.",
    )


def check_vty_access_class(config: str) -> Finding:
    """Check that VTY lines restrict management access with an access-class."""
    vty_blocks = _get_vty_blocks(config)

    for block in vty_blocks:
        if not re.search(r'access-class\s+\S+\s+in', block):
            return Finding(
                check_id="H05",
                title="Ensure VTY lines restrict access with an access-class",
                severity=Severity.HIGH,
                status=Status.FAIL,
                detail="One or more VTY lines have no inbound access-class. Any source address that can reach the device can attempt to log in.",
                remediation="Under each 'line vty' block, run: access-class <management-acl> in",
            )

    return Finding(
        check_id="H05",
        title="Ensure VTY lines restrict access with an access-class",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="VTY lines restrict inbound management access with an access-class.",
    )


def check_snmp_v3_only(config: str) -> Finding:
    """Check that SNMP access does not rely on SNMPv1/v2c community strings."""
    if re.search(r'snmp-server community\s+\S+', config):
        return Finding(
            check_id="H06",
            title="Ensure SNMP access does not rely on SNMPv1/v2c",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="A SNMPv1/v2c community string is configured. The protocol sends it in plaintext regardless of how strong the string is.",
            remediation="Replace community-string SNMP access with SNMPv3, for example: snmp-server group ADMINGROUP v3 priv\nsnmp-server user admin ADMINGROUP v3 auth sha <key> priv aes 128 <key>",
        )

    return Finding(
        check_id="H06",
        title="Ensure SNMP access does not rely on SNMPv1/v2c",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="No SNMPv1/v2c community strings are configured.",
    )


def check_control_plane_policing(config: str) -> Finding:
    """Check that a Control Plane Policing (CoPP) service-policy is applied."""
    control_plane_block = _get_control_plane_block(config)

    if not control_plane_block or not re.search(r'service-policy', control_plane_block):
        return Finding(
            check_id="H07",
            title="Ensure Control Plane Policing is configured",
            severity=Severity.HIGH,
            status=Status.FAIL,
            detail="No control-plane service-policy is applied. The device's CPU has no rate-limiting against traffic directed at it.",
            remediation="Define and apply a CoPP policy, for example: control-plane\n service-policy input COPP-POLICY",
        )

    return Finding(
        check_id="H07",
        title="Ensure Control Plane Policing is configured",
        severity=Severity.HIGH,
        status=Status.PASS,
        detail="A Control Plane Policing service-policy is applied.",
    )


def check_ntp_authentication(config: str) -> Finding:
    """Check that NTP authentication is configured, separate from check_ntp_configured() above."""
    if not re.search(r'ntp authenticate', config):
        return Finding(
            check_id="M06",
            title="Ensure NTP authentication is configured",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail="NTP authentication is not enabled. Any time source this device uses can be spoofed.",
            remediation="Run: ntp authenticate\nntp authentication-key 1 md5 <key>\nntp trusted-key 1",
        )

    return Finding(
        check_id="M06",
        title="Ensure NTP authentication is configured",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="NTP authentication is configured.",
    )


def check_password_min_length(config: str) -> Finding:
    """Check that a minimum local password length (8+ characters) is enforced."""
    match = re.search(r'security passwords min-length\s+(\d+)', config)

    if not match or int(match.group(1)) < 8:
        return Finding(
            check_id="M07",
            title="Ensure a minimum password length is enforced",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail="No minimum password length of at least 8 characters is enforced for local accounts.",
            remediation="Run: security passwords min-length 8",
        )

    return Finding(
        check_id="M07",
        title="Ensure a minimum password length is enforced",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        detail="A minimum password length of at least 8 characters is enforced.",
    )


# All check functions in the order they run.
# To add a new check, write the function above and append it here.
ALL_CHECKS = [
    check_telnet_disabled,
    check_snmp_default_communities,
    check_console_auth,
    check_ssh_version_2,
    check_password_encryption,
    check_aaa_new_model,
    check_http_server_disabled,
    check_login_rate_limiting,
    check_vty_timeout,
    check_ip_source_routing,
    check_logging_host,
    check_timestamps,
    check_banner_configured,
    check_ntp_configured,
    check_small_servers_disabled,
    check_smart_install_disabled,
    check_vty_access_class,
    check_snmp_v3_only,
    check_control_plane_policing,
    check_ntp_authentication,
    check_password_min_length,
]


def run_all_checks(config: str) -> List[Finding]:
    """Run every check against the config text and return the full list of results."""
    results = []
    for check_func in ALL_CHECKS:
        results.append(check_func(config))
    return results
