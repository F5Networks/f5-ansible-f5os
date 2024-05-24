# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_lldp_config
from ansible_collections.f5networks.f5os.plugins.modules.f5os_lldp_config import (
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
            enabled=True,
            system_name='test',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            max_neighbors_per_port=15,
            tx_delay=22,
            interfaces=dict(
                name='1.0',
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.enabled, True)
        self.assertEqual(p.system_name, 'test')
        self.assertEqual(p.system_description, 'Test Description')
        self.assertEqual(p.tx_interval, 31)
        self.assertEqual(p.tx_hold, 42)
        self.assertEqual(p.reinitiate_delay, 23)
        self.assertEqual(p.max_neighbors_per_port, 15)
        self.assertEqual(p.tx_delay, 22)
        self.assertEqual(p.interfaces["name"], '1.0')
        self.assertEqual(p.interfaces['enabled'], False)
        self.assertEqual(p.interfaces['tlv_advertisement_state'], 'txonly')
        self.assertEqual(p.interfaces['tlv_map'], 'chassis-id port-id ttl')
        self.assertEqual(p.state, 'present')

    def test_default_module_parameters(self):
        args = dict(
            interfaces=dict(
                name='1.0',
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.enabled, False)
        self.assertEqual(p.system_name, '')
        self.assertEqual(p.system_description, '')
        self.assertEqual(p.tx_interval, 30)
        self.assertEqual(p.tx_hold, 4)
        self.assertEqual(p.reinitiate_delay, 2)
        self.assertEqual(p.max_neighbors_per_port, 10)
        self.assertEqual(p.tx_delay, 2)
        self.assertEqual(p.interfaces['name'], '1.0')
        self.assertEqual(p.interfaces['enabled'], False)
        self.assertEqual(p.interfaces['tlv_advertisement_state'], 'txonly')
        self.assertEqual(p.interfaces['tlv_map'], 'chassis-id port-id ttl')
        self.assertEqual(p.state, 'present')

    def test_module_parameters_invalid_tx_interval(self):
        args = dict(
            tx_interval=65536,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.tx_interval()

        self.assertIn('Valid tx_interval must be in range 0 - 65535.', err.exception.args[0])

    def test_module_parameters_invalid_tx_hold(self):
        args = dict(
            tx_hold=65536,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.tx_hold()

        self.assertIn('Valid tx_hold must be in range 0 - 65535.', err.exception.args[0])

    def test_module_parameters_invalid_reinitiate_delay(self):
        args = dict(
            reinitiate_delay=65536
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.reinitiate_delay()

        self.assertIn('Valid reinitiate_delay must be in range 0 - 65535.', err.exception.args[0])

    def test_module_parameters_invalid_tx_delay(self):
        args = dict(
            tx_delay=65536
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.tx_delay()

        self.assertIn('Valid tx_delay must be in range 0 - 65535.', err.exception.args[0])

    def test_module_parameters_invalid_max_neighbors_per_port(self):
        args = dict(
            max_neighbors_per_port=65536,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.max_neighbors_per_port()

        self.assertIn('Valid max_neighbors_per_port must be in range 0 - 65535.', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_lldp_config.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_lldp_config.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_enable_lldp_config(self, *args):
        set_module_args(dict(
            enabled=True,
            system_name='test',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            max_neighbors_per_port=15,
            tx_delay=22,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(code=200, contents=dict(load_fixture('f5os_lldp_config.json'))))
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=201, contents=dict()),
        ])
        mm.client.patch = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_enable_lldp_fails(self, *args):
        set_module_args(dict(
            enabled=True,
            system_name='test',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            max_neighbors_per_port=15,
            tx_delay=22,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value=dict(code=400, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])
        self.assertTrue(mm.client.patch.called)

    def test_update_lldp_config(self, *args):
        set_module_args(dict(
            enabled=True,
            system_name='test',
            system_description='Test Description Updated',
            tx_interval=32,
            tx_hold=43,
            reinitiate_delay=24,
            max_neighbors_per_port=15,
            tx_delay=23,
            interfaces=dict(
                name=1.0,
                enabled=True,
                tlv_advertisement_state='rxonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        # mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_lldp_interface.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_lldp_interface.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_lldp_interface.json')))
        ])
        mm.client.patch = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_remove_lldp_config(self, *args):
        set_module_args(dict(
            enabled=True,
            system_name='test',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            tx_delay=22,
            max_neighbors_per_port=15,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        mm.exists = Mock(side_effect=[True])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_lldp_interface.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_lldp_interface.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_lldp_interface.json')))
        ])
        mm.client.delete = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict())
        ])
        mm.client.patch = Mock(return_value=dict(code=204, contents=dict()))
        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(f5os_lldp_config, 'Connection')
    @patch.object(f5os_lldp_config.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            enabled=True,
            system_name='test',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            max_neighbors_per_port=15,
            tx_delay=22,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_lldp_config.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_lldp_config, 'Connection')
    @patch.object(f5os_lldp_config.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            enabled=True,
            system_name='test',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            max_neighbors_per_port=15,
            tx_delay=22,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_lldp_config.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            enabled=True,
            system_name='test1',
            system_description='Test Description',
            tx_interval=31,
            tx_hold=42,
            reinitiate_delay=23,
            max_neighbors_per_port=15,
            tx_delay=22,
            interfaces=dict(
                name=1.0,
                enabled=False,
                tlv_advertisement_state='txonly',
                tlv_map="chassis-id port-id ttl"
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[dict(code=200, contents=dict(load_fixture('f5os_lldp_config.json'))),
                                          dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertFalse(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)
