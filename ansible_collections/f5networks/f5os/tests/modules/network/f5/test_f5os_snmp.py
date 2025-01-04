# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_snmp
from ansible_collections.f5networks.f5os.plugins.modules.f5os_snmp import (
    ArgumentSpec, ModuleManager
)

from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json, AnsibleFailJson, AnsibleExitJson
)


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


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_snmp.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_snmp.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_snmp_community(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_snmp_user(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='user1',
                auth_proto="MD5",
                auth_passwd="pass1",
                privacy_proto="DES",
                privacy_passwd="pass2",
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_snmp_target(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model="v1",
                community="community1",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:0000:130F:0000:0000:09C0:876A:130B",
                port="8080",
                user="user1",
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_snmp_mib(self, *args):
        set_module_args(dict(
            snmp_mib=dict(
                syscontact='user user@email.com',
                sysname='appliance-x',
                syslocation="appliance-x.chassis.local",
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)

    def test_update_snmp_community(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_update_snmp_target(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model="v1",
                community="community1",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:0000:130F:0000:0000:09C0:876A:130B",
                port="8080",
                user="user1",
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    @patch.object(f5os_snmp, 'Connection')
    @patch.object(f5os_snmp.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_snmp.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_snmp, 'Connection')
    @patch.object(f5os_snmp.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_snmp.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
