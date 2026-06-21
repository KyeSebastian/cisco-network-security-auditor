"""
Unit tests for the CIS Cisco IOS Benchmark checks in auditor/checks.py.

Each check gets a minimal config snippet that should fail it and a minimal
config snippet that should pass it, instead of relying on the two large
clean/dirty fixtures in smoke_test.py. Catches the case where a check is
right for the wrong reason, e.g. passing only because an unrelated line
elsewhere in a big fixture happened to satisfy the regex.
"""

from auditor.checks import (
    ALL_CHECKS,
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
    run_all_checks,
)
from auditor.models import Status


def test_telnet_disabled_fail():
    config = "line vty 0 4\n transport input telnet\n"
    assert check_telnet_disabled(config).status == Status.FAIL


def test_telnet_disabled_pass():
    config = "line vty 0 4\n transport input ssh\n"
    assert check_telnet_disabled(config).status == Status.PASS


def test_snmp_default_communities_fail():
    config = "snmp-server community public RO\n"
    assert check_snmp_default_communities(config).status == Status.FAIL


def test_snmp_default_communities_pass():
    config = "snmp-server community S3cr3tStr1ng RO\n"
    assert check_snmp_default_communities(config).status == Status.PASS


def test_console_auth_fail():
    config = "line con 0\n no login\n"
    assert check_console_auth(config).status == Status.FAIL


def test_console_auth_pass():
    config = "line con 0\n login local\n"
    assert check_console_auth(config).status == Status.PASS


def test_ssh_version_2_fail_when_v1_set():
    config = "ip ssh version 1\n"
    assert check_ssh_version_2(config).status == Status.FAIL


def test_ssh_version_2_fail_when_unset():
    config = ""
    assert check_ssh_version_2(config).status == Status.FAIL


def test_ssh_version_2_pass():
    config = "ip ssh version 2\n"
    assert check_ssh_version_2(config).status == Status.PASS


def test_password_encryption_fail():
    config = ""
    assert check_password_encryption(config).status == Status.FAIL


def test_password_encryption_pass():
    config = "service password-encryption\n"
    assert check_password_encryption(config).status == Status.PASS


def test_aaa_new_model_fail():
    config = ""
    assert check_aaa_new_model(config).status == Status.FAIL


def test_aaa_new_model_pass():
    config = "aaa new-model\n"
    assert check_aaa_new_model(config).status == Status.PASS


def test_http_server_disabled_fail():
    config = "ip http server\n"
    assert check_http_server_disabled(config).status == Status.FAIL


def test_http_server_disabled_pass():
    config = "no ip http server\n"
    assert check_http_server_disabled(config).status == Status.PASS


def test_login_rate_limiting_fail():
    config = ""
    assert check_login_rate_limiting(config).status == Status.FAIL


def test_login_rate_limiting_pass():
    config = "login block-for 60 attempts 3 within 30\n"
    assert check_login_rate_limiting(config).status == Status.PASS


def test_vty_timeout_fail():
    config = "line vty 0 4\n exec-timeout 0 0\n"
    assert check_vty_timeout(config).status == Status.FAIL


def test_vty_timeout_pass():
    config = "line vty 0 4\n exec-timeout 10 0\n"
    assert check_vty_timeout(config).status == Status.PASS


def test_ip_source_routing_fail():
    config = "ip source-route\n"
    assert check_ip_source_routing(config).status == Status.FAIL


def test_ip_source_routing_pass():
    config = "no ip source-route\n"
    assert check_ip_source_routing(config).status == Status.PASS


def test_logging_host_fail():
    config = ""
    assert check_logging_host(config).status == Status.FAIL


def test_logging_host_pass():
    config = "logging host 10.0.0.1\n"
    assert check_logging_host(config).status == Status.PASS


def test_timestamps_fail():
    config = ""
    assert check_timestamps(config).status == Status.FAIL


def test_timestamps_pass():
    config = "service timestamps log datetime msec\n"
    assert check_timestamps(config).status == Status.PASS


def test_banner_configured_fail():
    config = ""
    assert check_banner_configured(config).status == Status.FAIL


def test_banner_configured_pass():
    config = "banner motd ^authorized use only^\n"
    assert check_banner_configured(config).status == Status.PASS


def test_ntp_configured_fail():
    config = ""
    assert check_ntp_configured(config).status == Status.FAIL


def test_ntp_configured_pass():
    config = "ntp server 10.0.0.2\n"
    assert check_ntp_configured(config).status == Status.PASS


def test_small_servers_disabled_fail():
    config = "service tcp-small-servers\n"
    assert check_small_servers_disabled(config).status == Status.FAIL


def test_small_servers_disabled_pass():
    config = ""
    assert check_small_servers_disabled(config).status == Status.PASS


def test_smart_install_disabled_fail():
    config = ""
    assert check_smart_install_disabled(config).status == Status.FAIL


def test_smart_install_disabled_pass():
    config = "no vstack\n"
    assert check_smart_install_disabled(config).status == Status.PASS


def test_vty_access_class_fail():
    config = "line vty 0 4\n transport input ssh\n"
    assert check_vty_access_class(config).status == Status.FAIL


def test_vty_access_class_pass():
    config = "line vty 0 4\n access-class MGMT-ACL in\n"
    assert check_vty_access_class(config).status == Status.PASS


def test_snmp_v3_only_fail():
    config = "snmp-server community S3cr3tStr1ng RO\n"
    assert check_snmp_v3_only(config).status == Status.FAIL


def test_snmp_v3_only_pass():
    config = "snmp-server group ADMINGROUP v3 priv\n"
    assert check_snmp_v3_only(config).status == Status.PASS


def test_control_plane_policing_fail():
    config = ""
    assert check_control_plane_policing(config).status == Status.FAIL


def test_control_plane_policing_pass():
    config = "control-plane\n service-policy input COPP-POLICY\n"
    assert check_control_plane_policing(config).status == Status.PASS


def test_ntp_authentication_fail():
    config = "ntp server 10.0.0.2\n"
    assert check_ntp_authentication(config).status == Status.FAIL


def test_ntp_authentication_pass():
    config = "ntp server 10.0.0.2\nntp authenticate\n"
    assert check_ntp_authentication(config).status == Status.PASS


def test_password_min_length_fail():
    config = ""
    assert check_password_min_length(config).status == Status.FAIL


def test_password_min_length_fail_when_too_short():
    config = "security passwords min-length 4\n"
    assert check_password_min_length(config).status == Status.FAIL


def test_password_min_length_pass():
    config = "security passwords min-length 8\n"
    assert check_password_min_length(config).status == Status.PASS


def test_run_all_checks_returns_one_finding_per_check():
    findings = run_all_checks("")
    assert len(findings) == len(ALL_CHECKS)


def test_run_all_checks_has_unique_check_ids():
    findings = run_all_checks("")
    check_ids = [f.check_id for f in findings]
    assert len(check_ids) == len(set(check_ids))
