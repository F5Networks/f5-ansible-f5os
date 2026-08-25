# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys
from unittest.mock import MagicMock

# Mock ansible.netcommon which is not available in the test environment
# but is required by some modules via plugins/module_utils/ipaddress.py
import ipaddress as _ipaddress


def _validate_ip_address(addr):
    try:
        _ipaddress.IPv4Address(addr)
        return True
    except (ValueError, _ipaddress.AddressValueError):
        return False


def _validate_ip_v6_address(addr):
    try:
        _ipaddress.IPv6Address(addr)
        return True
    except (ValueError, _ipaddress.AddressValueError):
        return False


netcommon_utils = MagicMock()
netcommon_utils.validate_ip_address = _validate_ip_address
netcommon_utils.validate_ip_v6_address = _validate_ip_v6_address

sys.modules.setdefault(
    'ansible_collections.ansible', MagicMock()
)
sys.modules.setdefault(
    'ansible_collections.ansible.netcommon', MagicMock()
)
sys.modules.setdefault(
    'ansible_collections.ansible.netcommon.plugins', MagicMock()
)
sys.modules.setdefault(
    'ansible_collections.ansible.netcommon.plugins.module_utils', MagicMock()
)
sys.modules.setdefault(
    'ansible_collections.ansible.netcommon.plugins.module_utils.network', MagicMock()
)
sys.modules.setdefault(
    'ansible_collections.ansible.netcommon.plugins.module_utils.network.common', MagicMock()
)
sys.modules.setdefault(
    'ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils', netcommon_utils
)
