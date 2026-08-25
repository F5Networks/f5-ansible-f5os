# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_appliance_mode
from ansible_collections.f5networks.f5os.plugins.modules.f5os_appliance_mode import (
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
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertTrue(p.enabled)

    def test_module_parameters_disabled(self):
        args = dict(
            enabled=False,
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertFalse(p.enabled)

    def test_api_parameters_enabled(self):
        data = load_fixture('f5os_appliance_mode_enabled.json')

        p = ApiParameters(params=data)

        self.assertTrue(p.enabled)

    def test_api_parameters_disabled(self):
        data = load_fixture('f5os_appliance_mode_disabled.json')

        p = ApiParameters(params=data)

        self.assertFalse(p.enabled)

    def test_api_parameters_missing(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.enabled)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_appliance_mode.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_appliance_mode.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_enable_appliance_mode(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current_data = load_fixture('f5os_appliance_mode_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertTrue(mm.client.put.called)

    def test_disable_appliance_mode(self, *args):
        set_module_args(dict(
            enabled=False,
            state='present',
        ))

        current_data = load_fixture('f5os_appliance_mode_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
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
            state='present',
        ))

        current_data = load_fixture('f5os_appliance_mode_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
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

        current_data = load_fixture('f5os_appliance_mode_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_fails(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current_data = load_fixture('f5os_appliance_mode_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=400, contents='bad request'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('bad request', err.exception.args[0])

    def test_update_verifies_payload(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        current_data = load_fixture('f5os_appliance_mode_disabled.json')

        expected_payload = {
            'f5-security-appliance-mode:appliance-mode': {
                'enabled': True,
            }
        }
        expected_uri = '/openconfig-system:system/f5-security-appliance-mode:appliance-mode'

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
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

    def test_read_current_fails(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
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

        current_data = load_fixture('f5os_appliance_mode_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
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

        current_data = load_fixture('f5os_appliance_mode_enabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(results['enabled'])

    @patch.object(f5os_appliance_mode, 'Connection')
    @patch.object(f5os_appliance_mode.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_appliance_mode.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_appliance_mode, 'Connection')
    @patch.object(f5os_appliance_mode.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_appliance_mode.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_check_mode_no_api_call(self, *args):
        set_module_args(dict(
            enabled=True,
            state='present',
            _ansible_check_mode=True,
        ))

        current_data = load_fixture('f5os_appliance_mode_disabled.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=current_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_read_current_404_enables(self, *args):
        """On a fresh device where appliance-mode was never configured,
        the API returns 404. The module should treat this as unconfigured
        (enabled=None) and proceed to enable appliance mode."""
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['enabled'])
        self.assertTrue(mm.client.put.called)

    def test_read_current_404_disable(self, *args):
        """On a fresh device (404), have.enabled is None.
        enabled=False vs None triggers a change because False != None.
        This is consistent with the collection's Difference pattern."""
        set_module_args(dict(
            enabled=False,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404, contents='not found'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        # False != None, so a change is detected and PUT is called
        self.assertTrue(results['changed'])
        self.assertFalse(results['enabled'])
        self.assertTrue(mm.client.put.called)

    def test_device_call_functions(self):
        set_module_args(dict(
            enabled=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())

        self.assertFalse(mm.update())
