# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_client_cert_auth
from ansible_collections.f5networks.f5os.plugins.modules.f5os_client_cert_auth import (
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


def clear_fixture_cache():
    fixture_data.clear()


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
    def test_module_parameters_enabled(self):
        args = dict(
            enabled=True,
            trusted_ca='my-ca-bundle',
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertTrue(p.enabled)
        self.assertEqual(p.trusted_ca, 'my-ca-bundle')

    def test_module_parameters_disabled(self):
        args = dict(
            enabled=False,
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertFalse(p.enabled)
        self.assertIsNone(p.trusted_ca)

    def test_api_parameters_enabled_with_ca(self):
        data = load_fixture('f5os_client_cert_auth_enabled.json')

        p = ApiParameters(params=data)

        self.assertTrue(p.enabled)
        self.assertEqual(p.trusted_ca, 'my-ca-bundle')

    def test_api_parameters_disabled(self):
        data = load_fixture('f5os_client_cert_auth_disabled.json')

        p = ApiParameters(params=data)

        self.assertFalse(p.enabled)
        self.assertIsNone(p.trusted_ca)

    def test_api_parameters_empty(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.enabled)
        self.assertIsNone(p.trusted_ca)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_client_cert_auth.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_client_cert_auth.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_enable_client_cert_auth(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertTrue(mm.client.put.called)

    def test_enable_client_cert_auth_with_ca(self, *args):
        set_module_args(dict(
            enabled=True,
            trusted_ca='my-ca-bundle',
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertEqual(results['trusted_ca'], 'my-ca-bundle')
        self.assertTrue(mm.client.put.called)

    def test_disable_client_cert_auth(self, *args):
        set_module_args(dict(
            enabled=False,
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(results['enabled'])
        self.assertTrue(mm.client.put.called)

    def test_enable_no_change(self, *args):
        set_module_args(dict(
            enabled=True,
            trusted_ca='my-ca-bundle',
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_disable_no_change(self, *args):
        set_module_args(dict(
            enabled=False,
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_client_cert_auth(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_remove_client_cert_auth_not_configured(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_fails(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=400, contents='bad request'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('bad request', err.exception.args[0])

    def test_delete_fails(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_read_current_fails(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('VELOS controller', err.exception.args[0])

    def test_velos_partition_allowed(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])

    def test_rseries_platform_allowed(self, *args):
        set_module_args(dict(
            enabled=False,
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(results['enabled'])

    def test_check_mode_present(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
            _ansible_check_mode=True,
        ))

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_check_mode_absent(self, *args):
        set_module_args(dict(
            state='absent',
            _ansible_check_mode=True,
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.delete.called)

    def test_update_verifies_payload_with_ca(self, *args):
        set_module_args(dict(
            enabled=True,
            trusted_ca='my-ca-bundle',
            state='present',
        ))

        expected_payload = {
            'f5-openconfig-aaa-tls:client-cert-auth': {
                'config': {
                    'enabled': True,
                    'trusted-ca': 'my-ca-bundle',
                }
            }
        }
        expected_uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:client-cert-auth'

        current_data = load_fixture('f5os_client_cert_auth_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()
        self.assertEqual(mm.client.put.call_args[0][0], expected_uri)
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_payload)

    def test_update_verifies_payload_without_ca(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        expected_payload = {
            'f5-openconfig-aaa-tls:client-cert-auth': {
                'config': {
                    'enabled': True,
                }
            }
        }
        expected_uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:client-cert-auth'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()
        self.assertEqual(mm.client.put.call_args[0][0], expected_uri)
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_payload)

    def test_delete_verifies_uri(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')
        expected_uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:client-cert-auth'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once_with(expected_uri)

    def test_read_current_404_enables(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertTrue(mm.client.put.called)

    @patch.object(f5os_client_cert_auth, 'Connection')
    @patch.object(f5os_client_cert_auth.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_client_cert_auth.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_client_cert_auth, 'Connection')
    @patch.object(f5os_client_cert_auth.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_client_cert_auth.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_update_trusted_ca_only(self, *args):
        set_module_args(dict(
            enabled=True,
            trusted_ca='new-ca-bundle',
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled_old_ca.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['trusted_ca'], 'new-ca-bundle')
        self.assertTrue(mm.client.put.called)

    def test_clear_trusted_ca_with_empty_string(self, *args):
        set_module_args(dict(
            enabled=True,
            trusted_ca='',
            state='present',
        ))

        current_data = load_fixture('f5os_client_cert_auth_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['enabled']],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)
        # Verify trusted-ca is NOT in the payload (clearing it)
        put_payload = mm.client.put.call_args[1]['data']
        self.assertNotIn('trusted-ca', put_payload['f5-openconfig-aaa-tls:client-cert-auth']['config'])
