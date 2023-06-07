# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_vlan
from ansible_collections.f5networks.f5os.plugins.modules.f5os_vlan import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch
)
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json, AnsibleFailJson, AnsibleExitJson
)


from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError


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
            vlan_id=1234,
            name='foobar'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.vlan_id, 1234)
        self.assertEqual(p.name, "foobar")

    def test_module_parameters_invalid_vlan(self):
        args = dict(
            vlan_id=99999
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.vlan_id()

        self.assertIn("Valid 'vlan_id' must be in range 0 - 4095.", err.exception.args[0])

    def test_module_parameters_name_invalid_chars(self):
        args = dict(
            name='Services&_%$'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('Invalid characters detected in name parameter', err.exception.args[0])

    def test_module_parameters_name_not_starting_with_letter(self):
        args = dict(
            name='5ervices.foo.bar'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('The name parameter must begin with a letter', err.exception.args[0])

    def test_module_parameters_name_exceed_length(self):
        args = dict(
            name='this.is.a.very.long.name.to.cause.errors.or_give_you_a_headache_just_from_looking_at_it'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('The name parameter must not exceed 58 characters', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_vlan.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_vlan.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_vlan_create(self, *args):
        set_module_args(dict(
            name="foobar",
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-vlan:vlans': {'vlan': [{'vlan-id': 1234, 'config': {'vlan-id': 1234, 'name': 'foobar'}}]}}
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(mm.client.patch.call_args[1]['data'], expected)

    def test_vlan_create_fails(self, *args):
        set_module_args(dict(
            name="foobar",
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-vlan:vlans': {'vlan': [{'vlan-id': 1234, 'config': {'vlan-id': 1234, 'name': 'foobar'}}]}}
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=400, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])
        self.assertDictEqual(mm.client.patch.call_args[1]['data'], expected)

    def test_vlan_create_name_missing_raises(self, *args):
        set_module_args(dict(
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Name parameter is required when creating new resource', err.exception.args[0])

    def test_vlan_update_name(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="new_name",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=204, contents=""))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture("load_velos_vlan_config.json")))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.patch.assert_called_once_with(
            '/openconfig-vlan:vlans/vlan=3333/config/name', data=dict(name='new_name')
        )

    def test_vlan_update_no_change(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="addednow",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture("load_velos_vlan_config.json")))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_vlan_update_fails(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="changed_me",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture("load_velos_vlan_config.json")))
        mm.client.patch = Mock(return_value=dict(code=400))
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to update vlan 3333, name to changed_me', err.exception.args[0])

    def test_vlan_delete(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.platform = 'rSeries Platform'
        mm.client.delete = Mock(return_value=dict(code=204, contents=""))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once_with('/openconfig-vlan:vlans/vlan=3333')

    def test_vlan_delete_raises(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.platform = 'rSeries Platform'
        mm.client.delete = Mock(return_value=dict(code=404, contents='object not found'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('object not found', err.exception.args[0])
        mm.client.delete.assert_called_once_with('/openconfig-vlan:vlans/vlan=3333')

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            vlan_id=3333,
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

        self.assertIn('Target device is a VELOS controller, aborting.', err.exception.args[0])

    @patch.object(f5os_vlan, 'Connection')
    @patch.object(f5os_vlan.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="new_name",
            state='present'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_vlan.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_vlan, 'Connection')
    @patch.object(f5os_vlan.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="new_name",
            state='present'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_vlan.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            vlan_id=3333,
            name="new_name",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

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
