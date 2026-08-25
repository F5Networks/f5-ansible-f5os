# -*- coding: utf-8 -*-
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
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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

    def test_module_parameters_proxy_server_missing_hostname(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            proxy_server='http://',
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.proxy_server

        self.assertIn('must contain a valid hostname', err.exception.args[0])


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

    def test_license_activate_uses_install_action_post_uris(self, *args):
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
        self.assertEqual(mm.client.post.call_count, 2)
        self.assertEqual(
            mm.client.post.call_args_list[0][0][0],
            '/openconfig-system:system/f5-system-licensing:licensing/f5-system-licensing-install:get-eula'
        )
        self.assertEqual(
            mm.client.post.call_args_list[1][0][0],
            '/openconfig-system:system/f5-system-licensing:licensing/f5-system-licensing-install:install'
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

    def test_license_activate_eula_not_accepted(self, *args):
        """Test license activation fails when EULA is not accepted."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents={'f5-system-licensing-install:output': {'status': 'eula-not-accepted'}}),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('EULA was not accepted', err.exception.args[0])

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

    def test_state_absent_returns_no_change(self, *args):
        """state=absent path through exec_module (deactivation not supported)."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_exists_returns_true_active_license(self, *args):
        """Real exists() method with matching non-expired license."""
        set_module_args(dict(
            registration_key='AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        active = load_fixture('f5os_license_active.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=active))

        self.assertTrue(mm.exists())

    def test_exists_returns_false_expired_license(self, *args):
        """Real exists() returns False for expired license."""
        set_module_args(dict(
            registration_key='AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        expired = load_fixture('f5os_license_expired.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=expired))

        self.assertFalse(mm.exists())

    def test_exists_returns_false_404(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404))

        self.assertFalse(mm.exists())

    def test_exists_raises_on_api_error(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='internal error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exists()

        self.assertIn('internal error', err.exception.args[0])

    def test_exists_returns_false_no_registration_key_in_state(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'f5-system-licensing:licensing': {'state': {}}}
        ))

        self.assertFalse(mm.exists())

    def test_exists_returns_false_different_key(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        active = load_fixture('f5os_license_active.json')
        # Fixture has key 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE', want is different
        mm.client.get = Mock(return_value=dict(code=200, contents=active))

        self.assertFalse(mm.exists())

    def test_exists_returns_false_registration_key_none(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.want._values['registration_key'] = None

        self.assertFalse(mm.exists())

    def test_exists_returns_true_no_end_date(self, *args):
        """License matches but no end date in license text — assumed valid."""
        set_module_args(dict(
            registration_key='AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'f5-system-licensing:licensing': {'state': {
                'registration-key': {'base': 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE'},
                'license': 'Licensed version 1.7.0\nNo end date present'
            }}}
        ))

        self.assertTrue(mm.exists())

    def test_get_dossier_device_success(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(
            code=200,
            contents={'f5-system-licensing-install:output': {'system-dossier': 'dossier-content-abc'}}
        ))

        result = mm.get_dossier_device()

        self.assertEqual(result, 'dossier-content-abc')

    def test_get_dossier_device_error(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=500, contents='dossier error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.get_dossier_device()

        self.assertIn('dossier error', err.exception.args[0])

    def test_get_eula_with_addon_keys(self, *args):
        """get_eula includes addon_keys in payload when present."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            addon_keys=['ADDON-KEY1'],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(
            code=200,
            contents={'f5-system-licensing-install:output': {'status': 'eula-accepted'}}
        ))

        result = mm.get_eula()

        self.assertTrue(result)
        payload = mm.client.post.call_args[0][1]
        self.assertIn('f5-system-licensing-install:add-on-keys', payload)

    def test_get_eula_error(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=500, contents='eula server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.get_eula()

        self.assertIn('eula server error', err.exception.args[0])

    def test_get_eula_not_accepted(self, *args):
        """Direct test of get_eula() returning False when status != eula-accepted."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(
            code=200,
            contents={'f5-system-licensing-install:output': {'status': 'eula-pending'}}
        ))

        result = mm.get_eula()

        self.assertFalse(result)

    def test_create_on_device_license_server_exception(self, *args):
        """License server returns an exception message in the result."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
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
            dict(code=200, contents={
                'f5-system-licensing-install:output': {
                    'result': 'License server has returned an exception: key invalid'
                }
            }),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('License server has returned an exception', err.exception.args[0])

    def test_create_on_device_unexpected_result(self, *args):
        """Install returns non-success result string."""
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
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
            dict(code=200, contents={
                'f5-system-licensing-install:output': {
                    'result': 'Unknown failure occurred'
                }
            }),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Unknown failure occurred', err.exception.args[0])

    def test_create_on_device_full_flow_with_exists(self, *args):
        """create_on_device exercises real exists() on final check."""
        set_module_args(dict(
            registration_key='AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE',
            addon_keys=['ADDON-1'],
            proxy_server='http://proxy.example.com:8080',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        active = load_fixture('f5os_license_active.json')
        # First exists() call → 404 (not licensed); final exists() after install → active
        mm.client.get = Mock(side_effect=[
            dict(code=404),
            dict(code=200, contents=active),
        ])
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=load_fixture('f5os_license_eula_accepted.json')),
            dict(code=200, contents=load_fixture('f5os_license_install_success.json')),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # Confirm both exists() calls happened (pre-check + post-install verification)
        self.assertEqual(mm.client.get.call_count, 2)
        # Verify proxy and addon in install payload
        install_payload = mm.client.post.call_args_list[1][0][1]
        self.assertEqual(install_payload['f5-system-licensing-install:proxy-server'], 'http://proxy.example.com:8080')
        self.assertIn('f5-system-licensing-install:add-on-keys', install_payload)

    def test_update_on_device_success(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.want._values['dossier'] = 'test-dossier'
        mm.want._values['license'] = 'test-license-text'
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))

        result = mm.update_on_device()

        self.assertTrue(result)
        mm.client.patch.assert_called_once()

    def test_update_on_device_error(self, *args):
        set_module_args(dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.want._values['dossier'] = 'test-dossier'
        mm.want._values['license'] = 'test-license-text'
        mm.client.patch = Mock(return_value=dict(code=500, contents='patch failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.update_on_device()

        self.assertIn('patch failed', err.exception.args[0])

    def test_license_already_active_full_flow(self, *args):
        """present() returns None (no change) when license exists and is valid."""
        set_module_args(dict(
            registration_key='AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        active = load_fixture('f5os_license_active.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=active))

        results = mm.exec_module()

        self.assertFalse(results['changed'])


class TestModuleParametersExtended(unittest.TestCase):
    """Additional parameter coverage for license_options, license_url, license_envelope."""

    def test_addon_keys_none_when_registration_key_none(self):
        args = dict(
            registration_key=None,
            addon_keys=['SOME-KEY'],
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertIsNone(p.addon_keys)

    def test_addon_keys_none_when_empty_list(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            addon_keys=[],
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertIsNone(p.addon_keys)

    def test_license_options_returns_defaults(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            license_server='activate.f5.com',
            state='present',
        )

        p = ModuleParameters(params=args)

        opts = p.license_options
        self.assertEqual(opts['eula'], '')
        self.assertEqual(opts['email'], '')
        self.assertEqual(opts['first_name'], '')
        self.assertEqual(opts['last_name'], '')
        self.assertEqual(opts['company'], '')
        self.assertEqual(opts['phone'], '')
        self.assertEqual(opts['job_title'], '')
        self.assertEqual(opts['address'], '')
        self.assertEqual(opts['city'], '')
        # BUG: license_options uses self.state which resolves to the Ansible module
        # 'state' param ('present'/'absent'), not a geographic state/province.
        # This leaks into the SOAP envelope's stateProvince field.
        self.assertNotEqual(opts['state'], '')  # documents the collision exists
        self.assertEqual(opts['postal_code'], '')
        self.assertEqual(opts['country'], '')

    def test_license_url(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            license_server='activate.f5.com',
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(
            p.license_url,
            'https://activate.f5.com/license/services/urn:com.f5.license.v5b.ActivationService'
        )

    def test_license_envelope(self):
        args = dict(
            registration_key='XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
            license_server='activate.f5.com',
            state='present',
        )

        p = ModuleParameters(params=args)
        p._values['dossier'] = 'test-dossier-string'

        envelope = p.license_envelope
        self.assertIn('activate.f5.com', envelope)
        self.assertIn('test-dossier-string', envelope)
        self.assertIn('getLicense', envelope)
        self.assertIn('SOAP-ENV:Envelope', envelope)

    def test_api_parameters_empty(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.registration_key)
        self.assertIsNone(p.addon_keys)
