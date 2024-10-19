# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_system
from ansible_collections.f5networks.f5os.plugins.modules.f5os_system import (
    ArgumentSpec, ModuleManager
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
    pass


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_change_hostname_setting(self, *args):
        set_module_args(
            dict(
                state='present',
                hostname='foobar',
                login_banner='foofoo'
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=load_fixture('system_settings.json'))
        mm.client.patch = Mock(return_value=dict(code=200))

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 4)

    def test_remove_hostname_setting(self, *args):
        set_module_args(
            dict(
                state='absent',
                hostname='foobar',
                login_banner='foofoo'
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204))

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 2)

    @patch.object(f5os_system, 'Connection')
    @patch.object(f5os_system.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            hostname='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_system.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_system, 'Connection')
    @patch.object(f5os_system.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            hostname='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_system.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
