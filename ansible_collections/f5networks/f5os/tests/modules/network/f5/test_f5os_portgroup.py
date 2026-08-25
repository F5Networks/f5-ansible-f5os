# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_portgroup
from ansible_collections.f5networks.f5os.plugins.modules.f5os_portgroup import (
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
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, '1/1')
        self.assertEqual(p.mode, 'MODE_4x25G')

    def test_api_parameters(self):
        args = dict(
            name='1/1',
            mode='MODE_1x100G',
        )

        p = ApiParameters(params=args)

        self.assertEqual(p.name, '1/1')
        self.assertEqual(p.mode, 'MODE_1x100G')

    def test_missing_parameters(self):
        p = ModuleParameters(params=dict())

        self.assertIsNone(p.name)
        self.assertIsNone(p.mode)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        clear_fixture_cache()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_portgroup.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_portgroup.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_portgroup_update(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        current_data = load_fixture('f5os_portgroup_current.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=current_data),  # exists
            dict(code=200, contents=current_data),  # read_current_from_device
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['mode'], 'MODE_4x25G')
        self.assertTrue(mm.client.patch.called)
        # Verify the URI contains URL-encoded portgroup name
        self.assertIn('portgroup=1%2F1', mm.client.get.call_args_list[0][0][0])

    def test_portgroup_update_fails(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        current_data = load_fixture('f5os_portgroup_current.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.patch = Mock(return_value=dict(code=400, contents='invalid mode'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('invalid mode', err.exception.args[0])
        # Verify PATCH targets the keyed config URI
        self.assertIn('portgroup=1%2F1/config', mm.client.patch.call_args[0][0])

    def test_portgroup_no_change(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_1x100G',
            state='present',
        ))

        current_data = load_fixture('f5os_portgroup_current.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=current_data),  # exists
            dict(code=200, contents=current_data),  # read_current_from_device
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_portgroup_not_found(self, *args):
        set_module_args(dict(
            name='99/99',
            mode='MODE_4x25G',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('does not exist', err.exception.args[0])
        # Verify the URI contains URL-encoded portgroup name
        self.assertIn('portgroup=99%2F99', mm.client.get.call_args[0][0])

    def test_portgroup_not_rseries(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not an rSeries platform', err.exception.args[0])

    def test_portgroup_velos_partition_raises(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('not an rSeries platform', err.exception.args[0])

    def test_portgroup_update_second_portgroup(self, *args):
        set_module_args(dict(
            name='1/2',
            mode='MODE_2x50G',
            state='present',
        ))

        current_data = load_fixture('f5os_portgroup_current_1_2.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=current_data),  # exists
            dict(code=200, contents=current_data),  # read_current_from_device
        ])
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['mode'], 'MODE_2x50G')
        # Verify the URI uses 1%2F2
        self.assertIn('portgroup=1%2F2', mm.client.get.call_args_list[0][0][0])

    def test_read_current_empty_response(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        # Response has no config data
        empty_data = {'f5-platform-port:portgroup': [{}]}

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=empty_data))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        # config.mode is None, want is MODE_4x25G → change detected
        self.assertTrue(results['changed'])

    def test_read_current_fails(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    @patch.object(f5os_portgroup, 'Connection')
    @patch.object(f5os_portgroup.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_portgroup.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_portgroup, 'Connection')
    @patch.object(f5os_portgroup.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_portgroup.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_exists_error_response(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_portgroup_update_verifies_payload(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        current_data = load_fixture('f5os_portgroup_current.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        expected_payload = {
            'f5-platform-port:config': {
                'name': '1/1',
                'mode': 'MODE_4x25G',
            }
        }
        expected_uri = (
            '/openconfig-platform:components/component=platform'
            '/port/f5-platform-port:portgroups'
            '/portgroup=1%2F1/config'
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=current_data),
            dict(code=200, contents=current_data),
        ])
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.patch.assert_called_once()
        self.assertEqual(mm.client.patch.call_args[0][0], expected_uri)
        self.assertDictEqual(mm.client.patch.call_args[1]['data'], expected_payload)

    def test_portgroup_delete(self, *args):
        set_module_args(dict(
            name='1/1',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)
        # Verify URI encoding
        self.assertIn('portgroup=1%2F1', mm.client.delete.call_args[0][0])

    def test_portgroup_delete_not_exist(self, *args):
        set_module_args(dict(
            name='1/1',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_portgroup_delete_fails(self, *args):
        set_module_args(dict(
            name='1/1',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_portgroup_delete_still_exists(self, *args):
        set_module_args(dict(
            name='1/1',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource', err.exception.args[0])

    def test_read_current_empty_portgroup_list(self, *args):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        # API returns an empty portgroup list
        empty_list_data = {'f5-platform-port:portgroup': []}

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=empty_list_data))
        mm.client.patch = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        # config.mode is None, want is MODE_4x25G → change detected
        self.assertTrue(results['changed'])

    def test_present_without_mode_fails(self, *args):
        set_module_args(dict(
            name='1/1',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            module = AnsibleModule(
                argument_spec=self.spec.argument_spec,
                supports_check_mode=self.spec.supports_check_mode,
                required_if=self.spec.required_if,
            )

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('mode', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='1/1',
            mode='MODE_4x25G',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm.client.get = Mock(side_effect=[
            dict(code=200), dict(code=404)
        ])

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())

        self.assertFalse(mm.update())
