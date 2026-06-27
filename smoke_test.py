from auditor.checks import run_all_checks
from auditor.report import generate_report
from auditor.models import DeviceResult, Status

CLEAN_CONFIG = """
service password-encryption
ip ssh version 2
aaa new-model
no ip http server
no ip source-route
no vstack
logging host 10.0.0.1
service timestamps log datetime msec
banner motd ^authorized use only^
ntp server 10.0.0.2
ntp authenticate
login block-for 60 attempts 3 within 30
security passwords min-length 8
snmp-server group ADMINGROUP v3 priv
control-plane
 service-policy input COPP-POLICY
line vty 0 4
 transport input ssh
 exec-timeout 10 0
 login local
 access-class MGMT-ACL in
line con 0
 login local
"""

DIRTY_CONFIG = """
ip http server
ip source-route
service tcp-small-servers
snmp-server community public RO
line vty 0 4
 transport input telnet
 exec-timeout 0 0
line con 0
 no login
"""

print("=== Clean config (expect mostly PASS) ===")
findings = run_all_checks(CLEAN_CONFIG)
for f in findings:
    icon = "PASS" if f.status == Status.PASS else "FAIL"
    print(f"  [{icon}] [{f.check_id}] {f.severity:<8} {f.title}")

passed = len([f for f in findings if f.status == Status.PASS])
failed = len([f for f in findings if f.status == Status.FAIL])
print(f"\n  {passed} passed, {failed} failed")

print("\n=== Dirty config (expect mostly FAIL) ===")
findings2 = run_all_checks(DIRTY_CONFIG)
for f in findings2:
    icon = "PASS" if f.status == Status.PASS else "FAIL"
    print(f"  [{icon}] [{f.check_id}] {f.severity:<8} {f.title}")

passed2 = len([f for f in findings2 if f.status == Status.PASS])
failed2 = len([f for f in findings2 if f.status == Status.FAIL])
print(f"\n  {passed2} passed, {failed2} failed")

devices = [
    DeviceResult(hostname="router-clean", ip="10.0.0.1", findings=findings, os_version="17.09.04a", model="C8000V"),
    DeviceResult(hostname="router-dirty", ip="10.0.0.2", findings=findings2, os_version="17.03.05", model="C8000V"),
]
path = generate_report(devices, output_path="sample_report.html")
print(f"\nreport: {path}")
