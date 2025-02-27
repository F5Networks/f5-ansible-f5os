# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_lag
from ansible_collections.f5networks.f5os.plugins.modules.f5os_lag import (
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
            name='Arista',
            trunk_vlans=[444],
            native_vlan=111,
            config_members=['1.1'],
            state='present'
        )

        p = ModuleParameters(params=args, client=DummyClient('rSeries Platform'))

        self.assertEqual(p.name, 'Arista')
        self.assertListEqual(p.trunk_vlans, [444])
        self.assertListEqual(p.config_members, ['1.1'])
        self.assertEqual(p.native_vlan, 111)

    def test_lacp_module_parameters(self):
        args = dict(
            lag_type='lacp',
        )
        p = ModuleParameters(params=args, client=DummyClient('rSeries Platform'))
        self.assertEqual(p.lag_type, 'LACP')
        self.assertEqual(p.mode, 'ACTIVE')
        self.assertEqual(p.interval, 'SLOW')

        args['mode'] = 'PASSIVE'
        args['interval'] = 'FAST'

        p = ModuleParameters(params=args, client=DummyClient('rSeries Platform'))

        self.assertEqual(p.lag_type, 'LACP')
        self.assertEqual(p.mode, 'PASSIVE')
        self.assertEqual(p.interval, 'FAST')

    def test_api_parameters(self):
        args = load_fixture('load_velos_partition_lag_config.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.interface_type, 'ieee8023adLag')
        self.assertListEqual(p.trunk_vlans, [580, 590])
        self.assertEqual(p.native_vlan, 579)
        self.assertEqual(p.lag_type, 'LACP')

    def test_missing_parameters(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.trunk_vlans)
        self.assertIsNone(p.native_vlan)
        self.assertIsNone(p.lag_type)

        p = ApiParameters(params={'openconfig-if-aggregate:aggregation': dict()})

        self.assertIsNone(p.trunk_vlans)
        self.assertIsNone(p.native_vlan)

        p = ModuleParameters(params=dict())

        self.assertIsNone(p.trunk_vlans)
        self.assertIsNone(p.lag_type)

    def test_module_parameters_invalid_vlan(self):
        p = ModuleParameters(params=dict())

        with self.assertRaises(F5ModuleError) as err:
            p._validate_vlan_ids(9999)

        self.assertIn('must be in range 0 - 4095', err.exception.args[0])

    def test_config_members_raises(self):
        args = dict(
            config_members=['1.1']
        )

        p = ModuleParameters(params=args, client=DummyClient('Velos Partition'))

        with self.assertRaises(F5ModuleError) as err:
            p.config_members()

        self.assertIn('Valid interface name must be formatted', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_lag.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_lag.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_lag_interface(self, *args):
        set_module_args(dict(
            name='Arista',
            trunk_vlans=[444, 333],
            native_vlan=666,
            config_members=['1.1', '1.2'],
            lag_type='lacp',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(side_effect=[dict(code=201), dict(code=201), dict(code=201), dict(code=201)])

        results = mm.exec_module()
        assert results['changed'] is True

    def test_create_lag_interface_response_error(self, *args):
        set_module_args(dict(
            name='Arista',
            trunk_vlans=[444, 333],
            native_vlan=666,
            config_members=['1.1', '1.2'],
            lag_type='lacp',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value=dict(code=401, contents='authorization failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('authorization failed', err.exception.args[0])

    def test_create_lag_interface_parameter_missing(self, *args):
        set_module_args(dict(
            name='Arista',
            trunk_vlans=[444, 333],
            native_vlan=666,
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

        self.assertIn('must not be empty when creating new LAG interface', err.exception.args[0])

    def test_update_lag_interface(self, *args):
        set_module_args(dict(
            name='foobar',
            trunk_vlans=[444, 333],
            native_vlan=666,
            config_members=['1.0'],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected_patch = {
            'openconfig-interfaces:interfaces': {
                'interface': [{'name': '1.0', 'config': {'name': '1.0'},
                               'openconfig-if-ethernet:ethernet': {
                                   'config': {'openconfig-if-aggregate:aggregate-id': 'foobar'}}}]
            }
        }
        expected_put = {'openconfig-vlan:switched-vlan': {'config': {'trunk-vlans': [333, 444], 'native-vlan': 666}}}
        expected_delete = '/openconfig-interfaces:interfaces/interface=2.0/' \
                          'openconfig-if-ethernet:ethernet/config/openconfig-if-aggregate:aggregate-id'

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm._get_interfaces = Mock(return_value=['2.0'])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')),
            dict(code=200, contents={'openconfig-if-aggregate:aggregate-id': 'foobar'})
        ])
        mm.client.put = Mock(return_value=dict(code=200))
        mm.client.patch = Mock(return_value=dict(code=200))
        mm.client.delete = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['native_vlan'], 666)
        self.assertListEqual(results['trunk_vlans'], [333, 444])
        self.assertListEqual(results['config_members'], ['1.0'])
        self.assertDictEqual(mm.client.patch.call_args[1]['data'], expected_patch)
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_put)
        self.assertTrue(mm.client.delete.call_args[0], expected_delete)

    def test_update_lag_interface_configure_member_fails(self, *args):
        set_module_args(dict(
            name='foobar',
            trunk_vlans=[444, 333],
            native_vlan=666,
            config_members=['1.0'],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        expected_put = {'openconfig-vlan:switched-vlan': {'config': {'trunk-vlans': [333, 444], 'native-vlan': 666}}}

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm._get_interfaces = Mock(return_value=['2.0'])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')),
            dict(code=200, contents={'openconfig-if-aggregate:aggregate-id': 'foobar'})
        ])
        mm.client.put = Mock(return_value=dict(code=200))
        mm.client.patch = Mock(return_value=dict(code=404, contents='not found'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])
        self.assertDictEqual(mm.client.put.call_args[1]['data'], expected_put)
        self.assertTrue(mm.client.put.called)

    def test_update_lag_interface_failure(self, *args):
        set_module_args(dict(
            name='foobar',
            trunk_vlans=[444, 333],
            native_vlan=666,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm._get_interfaces = Mock(return_value=['2.0'])
        mm._is_lag_member = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')))
        mm.client.put = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_update_no_change(self, *args):
        set_module_args(dict(
            name='foobar',
            config_members=['1.0'],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.should_update = Mock(return_value=False)
        mm._get_interfaces = Mock(return_value=['1.0'])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')),
            dict(code=200, contents={'openconfig-if-aggregate:aggregate-id': 'foobar'})
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertTrue(mm.client.get.call_count == 2)

    def test_delete_lag_interface(self, *args):
        set_module_args(dict(
            name='Arista',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(side_effect=[True, False])
        mm._get_interfaces = Mock(return_value=['2.0'])
        mm._is_lag_member = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')))
        mm.client.delete = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.call_count == 3)

    def test_delete_lag_delete_member_fails(self, *args):
        set_module_args(dict(
            name='Arista',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm._get_interfaces = Mock(return_value=['2.0'])
        mm._is_lag_member = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')))
        mm.client.delete = Mock(return_value=dict(code=404, contents='not found'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])
        self.assertTrue(mm.client.delete.call_count == 1)

    def test_delete_lag_remove_device_fails(self, *args):
        set_module_args(dict(
            name='Arista',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm._get_interfaces = Mock(return_value=['2.0'])
        mm._is_lag_member = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_lag_interface.json')))
        mm.client.delete = Mock(side_effect=[dict(code=204), dict(code=404, contents='not found')])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not found', err.exception.args[0])
        self.assertTrue(mm.client.delete.call_count == 2)

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

    @patch.object(f5os_lag, 'Connection')
    @patch.object(f5os_lag.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_lag.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_lag, 'Connection')
    @patch.object(f5os_lag.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_lag.main()

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
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())

        mm.client.patch = Mock(return_value=dict(contents='access denied', code=401))
        with self.assertRaises(F5ModuleError) as err4:
            mm._add_lacp_config()
        self.assertIn('access denied', err4.exception.args[0])

        mm.client.delete = Mock(return_value=dict(contents='server error', code=500))
        with self.assertRaises(F5ModuleError) as err5:
            mm._remove_lacp_config("foobar")
        self.assertIn('server error', err5.exception.args[0])

    def test_get_interfaces_method(self):
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
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_f5os_interfaces.json')),
            dict(code=500, contents='internal server error')
        ])

        result = mm._get_interfaces()
        expected = ['1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0', '10.0', '11.0',
                    '12.0', '13.0', '14.0', '15.0', '16.0', '17.0', '18.0', '19.0', '20.0', 'mgmt']
        self.assertListEqual(result, expected)

        with self.assertRaises(F5ModuleError) as err:
            mm._get_interfaces()

        self.assertIn('internal server error', err.exception.args[0])

    def test_is_lag_member_method(self):
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
        mm.client.get = Mock(side_effect=[
            dict(code=204), dict(code=404), dict(code=500, contents='internal server error')
        ])

        self.assertFalse(mm._is_lag_member('1.1'))
        self.assertIn('interface=1.1/openconfig-if-ethernet:ethernet', mm.client.get.call_args[0][0])

        self.assertFalse(mm._is_lag_member('1.2'))
        self.assertIn('interface=1.2/openconfig-if-ethernet:ethernet', mm.client.get.call_args[0][0])

        with self.assertRaises(F5ModuleError) as err:
            mm._is_lag_member('1.3')

        self.assertIn('internal server error', err.exception.args[0])
