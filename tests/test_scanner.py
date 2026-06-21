from auditor.scanner import _parse_version_info

# Captured-format sample, not a live device - shape matches real 'show version'
# output for IOS XE on Cat8kv (the DevNet sandbox target) and a classic IOS switch.
IOSXE_CAT8KV_VERSION = """
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Thu 17-Aug-23 14:01 by mcpre

ROM: IOS-XE ROMMON

Router uptime is 2 hours, 14 minutes
Uptime for this control processor is 2 hours, 16 minutes

cisco C8000V (VXE) processor (revision VXE) with 1987684K/3075K bytes of memory.
Processor board ID 9XKR3K2KVQ7
"""

CLASSIC_IOS_SWITCH_VERSION = """
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2017 by Cisco Systems, Inc.

cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
"""


def test_parse_version_info_iosxe_cat8kv():
    os_version, model = _parse_version_info(IOSXE_CAT8KV_VERSION)
    assert os_version == "17.09.04a"
    assert model == "C8000V"


def test_parse_version_info_classic_ios_switch():
    os_version, model = _parse_version_info(CLASSIC_IOS_SWITCH_VERSION)
    assert os_version == "15.0(2)SE11"
    assert model == "WS-C2960-24TT-L"


def test_parse_version_info_empty_input():
    os_version, model = _parse_version_info("")
    assert os_version == ""
    assert model == ""
