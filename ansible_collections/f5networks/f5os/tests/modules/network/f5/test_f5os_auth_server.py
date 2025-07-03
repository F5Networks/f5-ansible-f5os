# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_auth_server
from ansible_collections.f5networks.f5os.plugins.modules.f5os_auth_server import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch
)
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


class TestParameters(unittest.TestCase):

    def test_module_parameters(self):
        args = dict(
            name='test_server',
            provider_type='radius',
            server=dict(
                server_ip='1.1.1.1',
                port=1000,
                secret='test',
                timeout='5'
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'test_server')
        self.assertEqual(p.provider_type, 'radius')
        self.assertEqual(p.server["server_ip"], '1.1.1.1')
        self.assertEqual(p.server['port'], 1000)
        self.assertEqual(p.server['secret'], 'test')
        self.assertEqual(p.server['timeout'], '5')
        self.assertEqual(p.state, 'present')

    def test_module_parameters(self):
        args = dict(
            name='test_server',
            provider_type='radius',
            server=dict(
                server_ip='1.1.1.1',
                port=1000,
                secret='test',
                timeout='5'
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'test_server')
        self.assertEqual(p.provider_type, 'radius')
        self.assertEqual(p.server[0]["server_ip"], '1.1.1.1')
        self.assertEqual(p.server[0]['port'], 1000)
        self.assertEqual(p.server[0]['secret'], 'test')
        self.assertEqual(p.server[0]['timeout'], '5')
        self.assertEqual(p.state, 'present')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth_server.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth_server.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_auth_server_group(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='radius',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_create_auth_radius_server(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='radius',
            server=[{'server_ip': '1.1.1.1', 'port': 1000, 'secret': 'test', 'timeout': 5}],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        mm.client.put = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_create_auth_tacacs_server(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='tacacs',
            server=[{'server_ip': '1.1.1.1', 'port': 1000, 'secret': 'test'}],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        mm.client.put = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_create_auth_ldap_server(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='ldap',
            server=[{'server_ip': '1.1.1.1', 'port': 1000, 'type': 'ldap over tcp'}],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        mm.client.put = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_update_auth_server(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='tacacs',
            server=[
                        {'server_ip': '1.1.1.1', 'port': 1000, 'secret': 'test', 'timeout': 5},
                        {'server_ip': '2.2.2.2', 'port': 1005, 'secret': 'test_update', 'timeout': 6}],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_auth_server.json'))),

        ])
        mm.client.put = Mock(side_effect=[
            dict(code=204, contents=dict())
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_remove_auth_server(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='tacacs',
            server=[
                        {'server_ip': '2.2.2.2', 'port': 1005, 'secret': 'test_update', 'timeout': 6},
                        {'server_ip': '3.3.3.3', 'port': 1000, 'secret': 'test', 'timeout': 5}],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_auth_server_group.json'))),
            dict(code=404, contents=dict())
        ])
        mm.client.delete = Mock(side_effect=[
            dict(code=204, contents=dict())
        ])
        results = mm.exec_module()

        # self.assertTrue(results['changed'])

    @patch.object(f5os_auth_server, 'Connection')
    @patch.object(f5os_auth_server.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='radius',
            state='present'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_auth_server.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_auth_server, 'Connection')
    @patch.object(f5os_auth_server.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='test_server',
            provider_type='radius',
            state='present'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_auth_server.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
