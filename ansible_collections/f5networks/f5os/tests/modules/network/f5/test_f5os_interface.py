# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_interface
from ansible_collections.f5networks.f5os.plugins.modules.f5os_interface import (
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


class DummyClient:
    def __init__(self, plat):
        self.plat = plat

    @property
    def platform(self):
        return self.plat


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            name='1.0',
            trunk_vlans=[444],
            native_vlan=111,
            enabled=False,
            description="Test Description",
            forward_error_correction="auto",
            state='present'
        )

        p = ModuleParameters(params=args, client=DummyClient('rSeries Platform'))

        self.assertEqual(p.name, '1.0')
        self.assertListEqual(p.trunk_vlans, [444])
        self.assertEqual(p.native_vlan, 111)
        self.assertEqual(p.enabled, False)
        self.assertEqual(p.description, 'Test Description')
        self.assertEqual(p.forward_error_correction, 'auto')

    def test_api_parameters(self):
        args = load_fixture('load_velos_partition_interface_config.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.name, '2/1.0')
        self.assertEqual(p.native_vlan, 666)
        self.assertEqual(p.interface_type, 'ethernetCsmacd')
        self.assertListEqual(p.trunk_vlans, [444])

    def test_missing_parameters(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.trunk_vlans)
        self.assertIsNone(p.native_vlan)

        p = ApiParameters(params={'openconfig-if-ethernet:ethernet': dict()})

        self.assertIsNone(p.trunk_vlans)
        self.assertIsNone(p.native_vlan)

        p = ModuleParameters(params=dict())

        self.assertIsNone(p.trunk_vlans)
        self.assertIsNone(p.native_vlan)
        self.assertIsNone(p.lag_type)

    def test_module_parameters_invalid_vlan(self):
        p = ModuleParameters(params=dict())

        with self.assertRaises(F5ModuleError) as err:
            p._validate_vlan_ids(9999)

        self.assertIn('must be in range 0 - 4095', err.exception.args[0])

    def test_name_raises(self):
        args = dict(
            name='1.1'
        )

        p = ModuleParameters(params=args, client=DummyClient('Velos Partition'))

        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('Valid interface name must be formatted', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_interface.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_interface.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_f5os_interface_add_vlan(self, *args):
        set_module_args(dict(
            name='2/1.0',
            native_vlan=666,
            trunk_vlans=[333, 444],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.put = Mock(return_value=dict(code=201, contents={}))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_interface.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['native_vlan'] == 666)
        self.assertListEqual(results['trunk_vlans'], [333, 444])

    def test_f5os_interface_update_vlans_fails(self, *args):
        set_module_args(dict(
            name='2/1.0',
            trunk_vlans=[444, 555],
            native_vlan=222,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.put = Mock(return_value=dict(code=500, contents='server error'))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_interface.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_f5os_interface_update_no_change(self, *args):
        set_module_args(dict(
            name='2/1.0',
            trunk_vlans=[444],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_interface.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_f5os_interface_no_interface(self, *args):
        set_module_args(dict(
            name='2/1.0',
            trunk_vlans=[444, 555],
            native_vlan=222,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Interface 2/1.0 does not exist', err.exception.args[0])

    def test_f5os_interface_remove_vlans(self, *args):
        set_module_args(dict(
            name='2/1.0',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm._vlans_exist_on_interface = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_interface.json')))
        mm.client.delete = Mock(return_value=dict(code=201))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 2)

    def test_f5os_interface_remove_vlans_failed_to_remove_trunk(self, *args):
        set_module_args(dict(
            name='2/1.0',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm._vlans_exist_on_interface = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_interface.json')))
        mm.client.delete = Mock(side_effect=[dict(code=201), dict(code=500, contents='internal server error')])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])
        self.assertTrue(mm.client.delete.call_count == 2)

    def test_f5os_interface_remove_vlans_failed_to_remove_native(self, *args):
        set_module_args(dict(
            name='2/1.0',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm._vlans_exist_on_interface = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_interface.json')))
        mm.client.delete = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])
        self.assertTrue(mm.client.delete.call_count == 1)

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Target device is a VELOS controller', err.exception.args[0])

    @patch.object(f5os_interface, 'Connection')
    @patch.object(f5os_interface.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_interface.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_interface, 'Connection')
    @patch.object(f5os_interface.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_interface.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='foobar',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.read_current_from_device()
        self.assertIn('access denied', err2.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())

    def test_vlan_exist_on_interface(self):
        set_module_args(dict(
            name='1.0',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=204), dict(code=500, contents='server error')])

        self.assertTrue(mm._vlans_exist_on_interface())
        self.assertFalse(mm._vlans_exist_on_interface())

        with self.assertRaises(F5ModuleError) as err:
            mm._vlans_exist_on_interface()

        self.assertIn('server error', err.exception.args[0])
