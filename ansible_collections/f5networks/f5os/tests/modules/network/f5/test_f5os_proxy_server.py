# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_proxy_server
from ansible_collections.f5networks.f5os.plugins.modules.f5os_proxy_server import (
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
    def test_module_parameters(self):
        args = dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            proxy_username='proxyuser',
            proxy_password='proxypass',
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.proxy_server, '10.1.1.100')
        self.assertEqual(p.proxy_port, 3128)
        self.assertEqual(p.proxy_username, 'proxyuser')
        self.assertEqual(p.proxy_password, 'proxypass')

    def test_module_parameters_no_auth(self):
        args = dict(
            proxy_server='proxy.example.com',
            proxy_port=8080,
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.proxy_server, 'proxy.example.com')
        self.assertEqual(p.proxy_port, 8080)
        self.assertIsNone(p.proxy_username)
        self.assertIsNone(p.proxy_password)

    def test_api_parameters_configured(self):
        data = load_fixture('f5os_proxy_server_configured.json')

        p = ApiParameters(params=data)

        self.assertEqual(p.proxy_server, '10.1.1.100')
        self.assertEqual(p.proxy_port, 3128)
        self.assertEqual(p.proxy_username, 'proxyuser')

    def test_api_parameters_no_auth(self):
        data = load_fixture('f5os_proxy_server_no_auth.json')

        p = ApiParameters(params=data)

        self.assertEqual(p.proxy_server, 'proxy.example.com')
        self.assertEqual(p.proxy_port, 8080)
        self.assertIsNone(p.proxy_username)

    def test_api_parameters_empty(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.proxy_server)
        self.assertIsNone(p.proxy_port)
        self.assertIsNone(p.proxy_username)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_proxy_server.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_proxy_server.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_proxy_with_auth(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            proxy_username='proxyuser',
            proxy_password='proxypass',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_server'], '10.1.1.100')
        self.assertEqual(results['proxy_port'], 3128)
        self.assertEqual(results['proxy_username'], 'proxyuser')
        self.assertTrue(mm.client.put.called)

    def test_create_proxy_without_auth(self, *args):
        set_module_args(dict(
            proxy_server='proxy.example.com',
            proxy_port=8080,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_server'], 'proxy.example.com')
        self.assertEqual(results['proxy_port'], 8080)
        self.assertTrue(mm.client.put.called)

    def test_update_proxy_server_requires_credentials_when_existing_auth(self, *args):
        set_module_args(dict(
            proxy_server='192.168.1.1',
            proxy_port=3128,
            state='present',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Existing proxy credentials detected', str(err.exception))
        self.assertFalse(mm.client.put.called)

    def test_update_proxy_port_requires_credentials_when_existing_auth(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=8080,
            state='present',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Existing proxy credentials detected', str(err.exception))
        self.assertFalse(mm.client.put.called)

    def test_update_proxy_server_succeeds_with_credentials_when_existing_auth(self, *args):
        set_module_args(dict(
            proxy_server='192.168.1.1',
            proxy_port=8080,
            proxy_username='updateduser',
            proxy_password='updatedpass',
            state='present',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        expected_payload = {
            'f5-system-diagnostics-proxy:proxy': {
                'config': {
                    'proxy-server': 'http://192.168.1.1:8080',
                    'proxy-username': 'updateduser',
                    'proxy-password': 'updatedpass',
                }
            }
        }
        expected_uri = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['proxy_server'], '192.168.1.1')
        self.assertEqual(results['proxy_port'], 8080)
        self.assertEqual(results['proxy_username'], 'updateduser')
        mm.client.put.assert_called_once()
        self.assertEqual(mm.client.put.call_args[0][0], expected_uri)
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_payload)

    def test_no_change_same_config(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            proxy_username='proxyuser',
            proxy_password='somepass',
            state='present',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_password_idempotent_when_config_matches(self, *args):
        """When all updatable fields match and password is provided,
        the module should be idempotent (no change) since we cannot
        compare passwords returned by the API."""
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            proxy_username='proxyuser',
            proxy_password='newpassword',
            state='present',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_proxy(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_remove_proxy_not_configured(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_proxy_with_scheme_and_port(self, *args):
        set_module_args(dict(
            proxy_server='https://proxy.example.com:443',
            proxy_port=3128,
            proxy_username='proxyuser',
            proxy_password='proxypass',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        expected_payload = {
            'f5-system-diagnostics-proxy:proxy': {
                'config': {
                    'proxy-server': 'https://proxy.example.com:3128',
                    'proxy-username': 'proxyuser',
                    'proxy-password': 'proxypass',
                }
            }
        }
        mm.client.put.assert_called_once()
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_payload)

    def test_create_proxy_with_scheme_and_provided_port(self, *args):
        set_module_args(dict(
            proxy_server='https://proxy.example.com',
            proxy_port=8443,
            proxy_username='proxyuser',
            proxy_password='proxypass',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        expected_payload = {
            'f5-system-diagnostics-proxy:proxy': {
                'config': {
                    'proxy-server': 'https://proxy.example.com:8443',
                    'proxy-username': 'proxyuser',
                    'proxy-password': 'proxypass',
                }
            }
        }
        mm.client.put.assert_called_once()
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_payload)

    def test_update_fails(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=400, contents='bad request'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('bad request', err.exception.args[0])

    def test_delete_fails(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
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
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
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
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('VELOS controller', err.exception.args[0])

    def test_velos_partition_allowed(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_check_mode_present(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
            _ansible_check_mode=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_check_mode_absent(self, *args):
        set_module_args(dict(
            state='absent',
            _ansible_check_mode=True,
        ))

        current_data = load_fixture('f5os_proxy_server_configured.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.delete.called)

    def test_update_verifies_payload_with_auth(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            proxy_username='proxyuser',
            proxy_password='proxypass',
            state='present',
        ))

        expected_payload = {
            'f5-system-diagnostics-proxy:proxy': {
                'config': {
                    'proxy-server': 'http://10.1.1.100:3128',
                    'proxy-username': 'proxyuser',
                    'proxy-password': 'proxypass',
                }
            }
        }
        expected_uri = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
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

    def test_update_verifies_payload_without_auth(self, *args):
        set_module_args(dict(
            proxy_server='proxy.example.com',
            proxy_port=8080,
            state='present',
        ))

        expected_payload = {
            'f5-system-diagnostics-proxy:proxy': {
                'config': {
                    'proxy-server': 'http://proxy.example.com:8080',
                }
            }
        }
        expected_uri = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
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

    def test_update_verifies_payload_diagnostics_endpoint(self, *args):
        set_module_args(dict(
            proxy_server='proxy.example.com',
            proxy_port=8080,
            proxy_username='proxyuser',
            proxy_password='proxypass',
            state='present',
        ))

        expected_payload = {
            'f5-system-diagnostics-proxy:proxy': {
                'config': {
                    'proxy-server': 'http://proxy.example.com:8080',
                    'proxy-username': 'proxyuser',
                    'proxy-password': 'proxypass',
                }
            }
        }
        expected_uri = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents={
            'f5-system-diagnostics-proxy:proxy': {
                'state': {
                    'proxy-server': '',
                    'proxy-username': ''
                }
            }
        }))
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

        current_data = load_fixture('f5os_proxy_server_configured.json')
        expected_uri = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once_with(expected_uri)

    def test_delete_verifies_uri_diagnostics_endpoint(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        current_data = {
            'f5-system-diagnostics-proxy:proxy': {
                'state': {
                    'proxy-server': 'http://proxy.example.com:8080',
                    'proxy-username': 'proxyuser'
                }
            }
        }
        expected_uri = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once_with(expected_uri)

    @patch.object(f5os_proxy_server, 'Connection')
    @patch.object(f5os_proxy_server.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_proxy_server.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_proxy_server, 'Connection')
    @patch.object(f5os_proxy_server.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_proxy_server.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_rseries_platform_allowed(self, *args):
        set_module_args(dict(
            proxy_server='10.1.1.100',
            proxy_port=3128,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=[
                ['state', 'present', ['proxy_server', 'proxy_port']],
            ],
            required_together=[
                ['proxy_username', 'proxy_password'],
            ],
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
