# t -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_license
from ansible_collections.f5networks.f5os.plugins.modules.f5os_license import (
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
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            addon_keys=['YYYYY-YYYYYYY'],
            proxy_server='http://proxy.example.com:443',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.registration_key, 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX')
        self.assertListEqual(p.addon_keys, ['YYYYY-YYYYYYY'])
        self.assertEqual(p.proxy_server, 'http://proxy.example.com:443')

    def test_module_parameters_no_proxy(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            addon_keys=['YYYYY-YYYYYYY'],
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.registration_key, 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX')
        self.assertListEqual(p.addon_keys, ['YYYYY-YYYYYYY'])
        self.assertIsNone(p.proxy_server)

    def test_module_parameters_invalid_proxy_server(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            proxy_server='proxy.example.com:443',
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.proxy_server

        self.assertIn('must be a full URL', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_license.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_license.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_license_activate_without_proxy(self, *args):
        """Test license activation without proxy_server - existing behavior unchanged."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[False, True])
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('f5os_license_eula_accepted.json')),
            dict(code=200, contents=load_fixture('f5os_license_install_success.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # Verify get_eula call payload does NOT contain proxy-server
        eula_payload = mm.client.post.call_args_list[0][0][1]
        self.assertNotIn('f5-system-licensing-install:proxy-server', eula_payload)
        # Verify install call payload does NOT contain proxy-server
        install_payload = mm.client.post.call_args_list[1][0][1]
        self.assertNotIn('f5-system-licensing-install:proxy-server', install_payload)

    def test_license_activate_with_proxy_server(self, *args):
        """Test license activation with proxy_server only."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            proxy_server='http://proxy.example.com:8080',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[False, True])
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('f5os_license_eula_accepted.json')),
            dict(code=200, contents=load_fixture('f5os_license_install_success.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_server'], 'http://proxy.example.com:8080')

        # Verify get_eula call payload contains proxy-server
        eula_payload = mm.client.post.call_args_list[0][0][1]
        self.assertEqual(
            eula_payload['f5-system-licensing-install:proxy-server'],
            'http://proxy.example.com:8080'
        )
        # Verify install call payload contains proxy-server
        install_payload = mm.client.post.call_args_list[1][0][1]
        self.assertEqual(
            install_payload['f5-system-licensing-install:proxy-server'],
            'http://proxy.example.com:8080'
        )

    def test_license_activate_with_addon_and_proxy(self, *args):
        """Test license activation with addon_keys and proxy_server."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            addon_keys=['YYYYY-YYYYYYY'],
            proxy_server='http://proxy.example.com:8080',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[False, True])
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('f5os_license_eula_accepted.json')),
            dict(code=200, contents=load_fixture('f5os_license_install_success.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_server'], 'http://proxy.example.com:8080')
        self.assertListEqual(results['addon_keys'], ['YYYYY-YYYYYYY'])

        # Verify get_eula call payload contains all expected keys
        eula_payload = mm.client.post.call_args_list[0][0][1]
        self.assertEqual(
            eula_payload['f5-system-licensing-install:registration-key'],
            'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
        )
        self.assertListEqual(
            eula_payload['f5-system-licensing-install:add-on-keys'],
            ['YYYYY-YYYYYYY']
        )
        self.assertEqual(
            eula_payload['f5-system-licensing-install:proxy-server'],
            'http://proxy.example.com:8080'
        )
        # Verify install call payload contains all expected keys
        install_payload = mm.client.post.call_args_list[1][0][1]
        self.assertEqual(
            install_payload['f5-system-licensing-install:registration-key'],
            'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
        )
        self.assertListEqual(
            install_payload['f5-system-licensing-install:add-on-keys'],
            ['YYYYY-YYYYYYY']
        )
        self.assertEqual(
            install_payload['f5-system-licensing-install:proxy-server'],
            'http://proxy.example.com:8080'
        )

    def test_license_activate_with_addon_no_proxy(self, *args):
        """Test license activation with addon_keys but without proxy_server."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            addon_keys=['YYYYY-YYYYYYY'],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[False, True])
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('f5os_license_eula_accepted.json')),
            dict(code=200, contents=load_fixture('f5os_license_install_success.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertListEqual(results['addon_keys'], ['YYYYY-YYYYYYY'])

        # Verify payloads contain add-on-keys but NOT proxy-server
        eula_payload = mm.client.post.call_args_list[0][0][1]
        self.assertIn('f5-system-licensing-install:add-on-keys', eula_payload)
        self.assertNotIn('f5-system-licensing-install:proxy-server', eula_payload)

        install_payload = mm.client.post.call_args_list[1][0][1]
        self.assertIn('f5-system-licensing-install:add-on-keys', install_payload)
        self.assertNotIn('f5-system-licensing-install:proxy-server', install_payload)

    def test_license_install_fails(self, *args):
        """Test license activation fails with server error."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            proxy_server='http://proxy.example.com:8080',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('f5os_license_eula_accepted.json')),
            dict(code=400, contents='server error'),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    @patch.object(f5os_license, 'Connection')
    @patch.object(f5os_license.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_license.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_license, 'Connection')
    @patch.object(f5os_license.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_license.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
