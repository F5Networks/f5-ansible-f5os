# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_login_policy
from ansible_collections.f5networks.f5os.plugins.modules.f5os_login_policy import (
    ArgumentSpec, ModuleManager, ApiParameters
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


class TestParseVersion(unittest.TestCase):
    def test_parse_version_valid(self):
        from ansible_collections.f5networks.f5os.plugins.modules.f5os_login_policy import _parse_version
        self.assertEqual(_parse_version('2.0.0'), (2, 0, 0))
        self.assertEqual(_parse_version('2.0.0-9817'), (2, 0, 0))
        self.assertEqual(_parse_version('1.8.3'), (1, 8, 3))

    def test_parse_version_invalid_returns_zero(self):
        from ansible_collections.f5networks.f5os.plugins.modules.f5os_login_policy import _parse_version
        self.assertEqual(_parse_version('not-a-version'), (0, 0, 0))
        self.assertEqual(_parse_version(''), (0, 0, 0))


class TestParameters(unittest.TestCase):
    def test_api_parameters(self):
        params = {
            'admin_role_limit': True,
            'restconf_max_session_limit': 10,
            'ssh_max_session_limit': 5,
        }
        p = ApiParameters(params=params)
        self.assertTrue(p.admin_role_limit)
        self.assertEqual(p.restconf_max_session_limit, 10)
        self.assertEqual(p.ssh_max_session_limit, 5)

    def test_api_parameters_empty(self):
        p = ApiParameters(params={})
        self.assertIsNone(p.admin_role_limit)
        self.assertIsNone(p.restconf_max_session_limit)
        self.assertIsNone(p.ssh_max_session_limit)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_login_policy.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_login_policy.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_login_policy(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
            restconf_max_session_limit=10,
            ssh_max_session_limit=5,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 404, 'contents': {}})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(results['admin_role_limit'])
        self.assertEqual(results['restconf_max_session_limit'], 10)
        self.assertEqual(results['ssh_max_session_limit'], 5)
        self.assertTrue(mm.client.put.called)

    def test_update_login_policy(self, *args):
        set_module_args(dict(
            ssh_max_session_limit=8,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_login_policy_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['ssh_max_session_limit'], 8)
        self.assertTrue(mm.client.put.called)

    def test_no_change(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
            restconf_max_session_limit=10,
            ssh_max_session_limit=5,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_login_policy_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.put.call_count, 0)

    def test_delete_login_policy(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_login_policy_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_no_policy_exists(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 404, 'contents': {}})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 0)

    def test_version_gate_raises_on_pre_v2(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.8.3'
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('requires F5OS 2.0.0 or later', err.exception.args[0])

    def test_version_gate_passes_on_v2(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 404, 'contents': {}})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 503, 'contents': 'service unavailable'})
        with self.assertRaises(F5ModuleError) as err1:
            mm.read_current_from_device()
        self.assertIn('service unavailable', err1.exception.args[0])

        mm.client.put = Mock(return_value={'code': 503, 'contents': 'service unavailable'})
        mm.changes = Mock()
        mm.changes.to_return = Mock(return_value={'admin_role_limit': True})
        with self.assertRaises(F5ModuleError) as err2:
            mm.update_on_device()
        self.assertIn('service unavailable', err2.exception.args[0])

        mm.client.delete = Mock(return_value={'code': 503, 'contents': 'service unavailable'})
        with self.assertRaises(F5ModuleError) as err3:
            mm.remove_from_device()
        self.assertIn('service unavailable', err3.exception.args[0])

    @patch.object(f5os_login_policy, 'Connection')
    @patch.object(f5os_login_policy.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_login_policy.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_login_policy, 'Connection')
    @patch.object(f5os_login_policy.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            admin_role_limit=True,
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_login_policy.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
