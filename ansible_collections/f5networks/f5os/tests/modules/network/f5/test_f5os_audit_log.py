# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_audit_log
from ansible_collections.f5networks.f5os.plugins.modules.f5os_audit_log import (
    ArgumentSpec, ModuleManager, ApiParameters, ModuleParameters, Difference
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


class TestApiParameters(unittest.TestCase):
    def test_api_parameters_with_config(self):
        data = load_fixture('f5os_audit_log_config.json')
        params = data['f5-openconfig-system-logging:audit-log']
        p = ApiParameters(params=params)

        self.assertTrue(p.enabled)
        self.assertIsNotNone(p.remote_forwarding)
        self.assertTrue(p.remote_forwarding['enabled'])
        self.assertEqual(p.remote_forwarding['server'], '10.10.10.100')
        self.assertEqual(p.remote_forwarding['port'], 514)
        self.assertEqual(p.remote_forwarding['protocol'], 'udp')

    def test_api_parameters_disabled(self):
        data = load_fixture('f5os_audit_log_disabled.json')
        params = data['f5-openconfig-system-logging:audit-log']
        p = ApiParameters(params=params)

        self.assertFalse(p.enabled)
        self.assertIsNone(p.remote_forwarding)

    def test_api_parameters_empty(self):
        p = ApiParameters(params={})

        self.assertIsNone(p.enabled)
        self.assertIsNone(p.remote_forwarding)

    def test_api_parameters_state_key(self):
        """Test that ApiParameters can parse 'state' key as well as 'config' key."""
        params = {
            'state': {
                'enabled': True,
                'remote-forwarding': {
                    'state': {
                        'enabled': True,
                        'host': '10.10.10.200',
                        'port': 6514,
                        'protocol': 'tcp'
                    }
                }
            }
        }
        p = ApiParameters(params=params)

        self.assertTrue(p.enabled)
        self.assertIsNotNone(p.remote_forwarding)
        self.assertTrue(p.remote_forwarding['enabled'])
        self.assertEqual(p.remote_forwarding['server'], '10.10.10.200')
        self.assertEqual(p.remote_forwarding['port'], 6514)
        self.assertEqual(p.remote_forwarding['protocol'], 'tcp')


class TestModuleParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            enabled=True,
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.100',
                port=514,
                protocol='udp',
            ),
            state='present',
        )
        p = ModuleParameters(params=args)

        self.assertTrue(p.enabled)
        self.assertIsNotNone(p.remote_forwarding)
        self.assertTrue(p.remote_forwarding['enabled'])
        self.assertEqual(p.remote_forwarding['server'], '10.10.10.100')
        self.assertEqual(p.remote_forwarding['port'], 514)
        self.assertEqual(p.remote_forwarding['protocol'], 'udp')

    def test_module_parameters_none(self):
        args = dict(
            enabled=None,
            remote_forwarding=None,
            state='present',
        )
        p = ModuleParameters(params=args)

        self.assertIsNone(p.enabled)
        self.assertIsNone(p.remote_forwarding)


class TestDifference(unittest.TestCase):
    def test_difference_enabled_changed(self):
        want = ModuleParameters(params=dict(enabled=False))
        have = ApiParameters(params=dict(config=dict(enabled=True)))
        diff = Difference(want, have)

        self.assertFalse(diff.enabled)

    def test_difference_enabled_no_change(self):
        want = ModuleParameters(params=dict(enabled=True))
        have = ApiParameters(params=dict(config=dict(enabled=True)))
        diff = Difference(want, have)

        self.assertIsNone(diff.enabled)

    def test_difference_enabled_want_none(self):
        want = ModuleParameters(params=dict(enabled=None))
        have = ApiParameters(params=dict(config=dict(enabled=True)))
        diff = Difference(want, have)

        self.assertIsNone(diff.enabled)

    def test_difference_remote_forwarding_changed(self):
        want = ModuleParameters(params=dict(
            remote_forwarding=dict(enabled=True, server='10.10.10.200', port=6514, protocol='tcp')
        ))
        have = ApiParameters(params=dict(
            config=dict(
                enabled=True,
                **{'remote-forwarding': {'config': {'enabled': True, 'host': '10.10.10.100', 'port': 514, 'protocol': 'udp'}}}
            )
        ))
        diff = Difference(want, have)

        result = diff.remote_forwarding
        self.assertIsNotNone(result)
        self.assertEqual(result['server'], '10.10.10.200')
        self.assertEqual(result['port'], 6514)
        self.assertEqual(result['protocol'], 'tcp')

    def test_difference_remote_forwarding_no_change(self):
        want = ModuleParameters(params=dict(
            remote_forwarding=dict(enabled=True, server='10.10.10.100', port=514, protocol='udp')
        ))
        have = ApiParameters(params=dict(
            config=dict(
                enabled=True,
                **{'remote-forwarding': {'config': {'enabled': True, 'host': '10.10.10.100', 'port': 514, 'protocol': 'udp'}}}
            )
        ))
        diff = Difference(want, have)

        self.assertIsNone(diff.remote_forwarding)

    def test_difference_remote_forwarding_want_none(self):
        want = ModuleParameters(params=dict(remote_forwarding=None))
        have = ApiParameters(params=dict(
            config=dict(
                enabled=True,
                **{'remote-forwarding': {'config': {'enabled': True, 'host': '10.10.10.100', 'port': 514, 'protocol': 'udp'}}}
            )
        ))
        diff = Difference(want, have)

        self.assertIsNone(diff.remote_forwarding)

    def test_difference_remote_forwarding_have_none(self):
        want = ModuleParameters(params=dict(
            remote_forwarding=dict(enabled=True, server='10.10.10.100', port=514, protocol='udp')
        ))
        have = ApiParameters(params=dict(config=dict(enabled=True)))
        diff = Difference(want, have)

        result = diff.remote_forwarding
        self.assertIsNotNone(result)
        self.assertEqual(result['server'], '10.10.10.100')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_audit_log.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_audit_log.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_audit_log_enabled(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertEqual(mm.client.put.call_count, 1)

    def test_create_audit_log_with_remote_forwarding(self, *args):
        set_module_args(dict(
            enabled=True,
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.100',
                port=514,
                protocol='udp',
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertIn('remote_forwarding', results)
        self.assertEqual(mm.client.put.call_count, 1)

    def test_update_audit_log_enable_to_disable(self, *args):
        set_module_args(dict(
            enabled=False,
            state='present',
        ))

        current = load_fixture('f5os_audit_log_config.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.put.call_count, 1)

        # Verify payload preserves remote_forwarding from current state
        put_call_args = mm.client.put.call_args
        payload = put_call_args[1].get('data') if put_call_args[1] else put_call_args[0][1]
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        self.assertFalse(config['enabled'])
        self.assertIn('remote-forwarding', config)

    def test_update_audit_log_no_change(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current = load_fixture('f5os_audit_log_config.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.put.call_count, 0)

    def test_update_remote_forwarding_change_server(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.200',
                port=6514,
                protocol='tcp',
            ),
            state='present',
        ))

        current = load_fixture('f5os_audit_log_config.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('remote_forwarding', results)
        self.assertEqual(mm.client.put.call_count, 1)

        # Verify payload preserves enabled from current state
        put_call_args = mm.client.put.call_args
        payload = put_call_args[1].get('data') if put_call_args[1] else put_call_args[0][1]
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        self.assertTrue(config['enabled'])
        rf = config['remote-forwarding']['config']
        self.assertEqual(rf['host'], '10.10.10.200')
        self.assertEqual(rf['port'], 6514)
        self.assertEqual(rf['protocol'], 'tcp')

    def test_read_audit_log_state(self, *args):
        set_module_args(dict(
            state='read',
        ))

        current = load_fixture('f5os_audit_log_config.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertIn('remote_forwarding', results)
        self.assertEqual(results['remote_forwarding']['server'], '10.10.10.100')
        self.assertEqual(results['remote_forwarding']['port'], 514)
        self.assertEqual(results['remote_forwarding']['protocol'], 'udp')

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)

        # Test exists returns True on 200
        mm.client.get = Mock(return_value={'code': 200})
        res1 = mm.exists()
        self.assertTrue(res1)

        # Test exists returns False on 404
        mm.client.get = Mock(return_value={'code': 404})
        res2 = mm.exists()
        self.assertFalse(res2)

        # Test exists raises on error
        mm.client.get = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res3:
            mm.exists()
        self.assertIn('service not available', res3.exception.args[0])

        # Test read_current_from_device raises on error
        mm.client.get = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res4:
            mm.read_current_from_device()
        self.assertIn('service not available', res4.exception.args[0])

        # Test create_on_device raises on error
        mm._set_changed_options()
        mm.client.put = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res5:
            mm.create_on_device()
        self.assertIn('service not available', res5.exception.args[0])

        # Test update_on_device raises on error
        mm.client.put = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res6:
            mm.update_on_device()
        self.assertIn('service not available', res6.exception.args[0])

    @patch.object(f5os_audit_log, 'Connection')
    @patch.object(f5os_audit_log.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_audit_log.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_audit_log, 'Connection')
    @patch.object(f5os_audit_log.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_audit_log.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_build_payload_enabled_only(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm._set_changed_options()
        payload = mm._build_payload()

        self.assertIn('f5-openconfig-system-logging:audit-log', payload)
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        self.assertTrue(config['enabled'])
        self.assertNotIn('remote-forwarding', config)

    def test_build_payload_with_remote_forwarding(self, *args):
        set_module_args(dict(
            enabled=True,
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.100',
                port=514,
                protocol='udp',
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm._set_changed_options()
        payload = mm._build_payload()

        self.assertIn('f5-openconfig-system-logging:audit-log', payload)
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        self.assertTrue(config['enabled'])
        self.assertIn('remote-forwarding', config)
        rf = config['remote-forwarding']['config']
        self.assertTrue(rf['enabled'])
        self.assertEqual(rf['host'], '10.10.10.100')
        self.assertEqual(rf['port'], 514)
        self.assertEqual(rf['protocol'], 'udp')

    def test_create_from_disabled_state(self, *args):
        """Test creating audit log config when device returns 404 (no config exists)."""
        set_module_args(dict(
            enabled=True,
            remote_forwarding=dict(
                enabled=True,
                server='192.168.1.100',
                port=1514,
                protocol='tcp',
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # Verify the PUT was called with proper payload
        put_call_args = mm.client.put.call_args
        payload = put_call_args[1].get('data') if put_call_args[1] else put_call_args[0][1]
        audit_log = payload['f5-openconfig-system-logging:audit-log']
        self.assertTrue(audit_log['config']['enabled'])
        rf_config = audit_log['config']['remote-forwarding']['config']
        self.assertEqual(rf_config['host'], '192.168.1.100')
        self.assertEqual(rf_config['port'], 1514)
        self.assertEqual(rf_config['protocol'], 'tcp')

    def test_disable_remote_forwarding(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=False,
            ),
            state='present',
        ))

        current = load_fixture('f5os_audit_log_config.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.put.call_count, 1)

        # Verify payload preserves enabled: true from current state
        put_call_args = mm.client.put.call_args
        payload = put_call_args[1].get('data') if put_call_args[1] else put_call_args[0][1]
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        self.assertTrue(config['enabled'])

    def test_disable_remote_forwarding_payload_excludes_none_values(self, *args):
        """Ansible fills unset suboptions with None. Verify those don't leak into the payload."""
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=False,
            ),
            state='present',
        ))

        current = load_fixture('f5os_audit_log_config.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

        put_call_args = mm.client.put.call_args
        payload = put_call_args[1].get('data') if put_call_args[1] else put_call_args[0][1]
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        rf_config = config['remote-forwarding']['config']

        # Verify no None values leaked into the payload
        for key, value in rf_config.items():
            self.assertIsNotNone(value, f"Key '{key}' in remote-forwarding config should not be None")

        # Verify enabled=False is present
        self.assertFalse(rf_config['enabled'])

        # Verify preserved values from current state are present
        self.assertEqual(rf_config['host'], '10.10.10.100')
        self.assertEqual(rf_config['port'], 514)
        self.assertEqual(rf_config['protocol'], 'udp')

    def test_create_partial_remote_forwarding_excludes_none(self, *args):
        """On create with partial remote_forwarding, None-filled keys must not appear in payload."""
        set_module_args(dict(
            enabled=True,
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.100',
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

        put_call_args = mm.client.put.call_args
        payload = put_call_args[1].get('data') if put_call_args[1] else put_call_args[0][1]
        config = payload['f5-openconfig-system-logging:audit-log']['config']
        rf_config = config['remote-forwarding']['config']

        # Verify no None values in payload
        for key, value in rf_config.items():
            self.assertIsNotNone(value, f"Key '{key}' in remote-forwarding config should not be None")

        # Only enabled and host should be present, not port or protocol
        self.assertTrue(rf_config['enabled'])
        self.assertEqual(rf_config['host'], '10.10.10.100')
        self.assertNotIn('port', rf_config)
        self.assertNotIn('protocol', rf_config)

    def test_port_validation_invalid_port(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.100',
                port=99999,
                protocol='udp',
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('port', err.exception.args[0])

    def test_port_validation_zero_port(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                server='10.10.10.100',
                port=0,
                protocol='udp',
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('port', err.exception.args[0])

    def test_api_parameters_port_string_converted_to_int(self):
        params = {
            'f5-openconfig-system-logging:audit-log': {
                'config': {
                    'remote-forwarding': {
                        'config': {'port': '514'}
                    }
                }
            }
        }
        p = ApiParameters(params=params['f5-openconfig-system-logging:audit-log'])
        self.assertIsNotNone(p.remote_forwarding)
        self.assertIsInstance(p.remote_forwarding['port'], int)
        self.assertEqual(p.remote_forwarding['port'], 514)
