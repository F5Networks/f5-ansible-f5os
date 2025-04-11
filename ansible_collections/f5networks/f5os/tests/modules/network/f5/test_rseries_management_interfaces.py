# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import rseries_management_interfaces
from ansible_collections.f5networks.f5os.plugins.modules.rseries_management_interfaces import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch
)
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json, AnsibleFailJson, AnsibleExitJson
)


from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError


fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)

    if path in fixture_data:
        return fixture_data[path]

    with open(path) as f:
        data = f.read()

    try:
        data = json.loads(data)
    except Exception:
        pass

    fixture_data[path] = data
    return data


class TestParameters(unittest.TestCase):

    def test_module_parameters(self):
        args = dict(
            dhcp=False,
            ipv4=dict(
                ip_address='10.144.140.80',
                prefix_length=20,
                gateway='10.144.140.254'
            ),
            ipv6=dict(
                ip_address='2001:db8:1::2',
                prefix_length=64,
                gateway='2001:db8:1::1'
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.dhcp, False)

        self.assertEqual(p.ipv4["ip_address"], '10.144.140.80'),
        self.assertEqual(p.ipv4["prefix_length"], 20),
        self.assertEqual(p.ipv4["gateway"], '10.144.140.254'),

        self.assertEqual(p.ipv6["ip_address"], '2001:db8:1::2'),
        self.assertEqual(p.ipv6["prefix_length"], 64),
        self.assertEqual(p.ipv6["gateway"], '2001:db8:1::1'),

        self.assertEqual(p.state, 'present')

    def test_default_module_parameters(self):
        args = dict(
            dhcp=False,
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.dhcp, False)

        self.assertEqual(p.ipv4["ip_address"], '0.0.0.0'),
        self.assertEqual(p.ipv4["prefix_length"], 0),
        self.assertEqual(p.ipv4["gateway"], '0.0.0.0'),

        self.assertEqual(p.ipv6["ip_address"], '::'),
        self.assertEqual(p.ipv6["prefix_length"], 0),
        self.assertEqual(p.ipv6["gateway"], '::'),

        self.assertEqual(p.state, 'present')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.rseries_management_interfaces.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.rseries_management_interfaces.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_update_management_interfaces(self, *args):
        set_module_args(dict(
            dhcp=False,
            ipv4=dict(
                ip_address='10.144.140.121',
                prefix_length=20,
                gateway='10.144.140.254'
            ),
            ipv6=dict(
                ip_address='2001:db8:1::1',
                prefix_length=64,
                gateway='2001:db8:1::1'
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture("f5os_rseries_management_interfaces.json")))
        # mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(rseries_management_interfaces, 'Connection')
    @patch.object(rseries_management_interfaces.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            dhcp=False,
            ipv4=dict(
                ip_address='10.144.140.121',
                prefix_length=20,
                gateway='10.144.140.254'
            ),
            ipv6=dict(
                ip_address='2001:db8:1::1',
                prefix_length=64,
                gateway='2001:db8:1::1'
            ),
            state='present'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            rseries_management_interfaces.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(rseries_management_interfaces, 'Connection')
    @patch.object(rseries_management_interfaces.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            dhcp=False,
            ipv4=dict(
                ip_address='10.144.140.121',
                prefix_length=20,
                gateway='10.144.140.254'
            ),
            ipv6=dict(
                ip_address='2001:db8:1::1',
                prefix_length=64,
                gateway='2001:db8:1::1'
            ),
            state='present'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            rseries_management_interfaces.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            dhcp=False,
            ipv4=dict(
                ip_address='10.144.140.121',
                prefix_length=20,
                gateway='10.144.140.254'
            ),
            ipv6=dict(
                ip_address='2001:db8:1::1',
                prefix_length=64,
                gateway='2001:db8:1::1'
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200)])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())
