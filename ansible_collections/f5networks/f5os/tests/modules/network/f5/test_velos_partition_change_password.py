# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import velos_partition_change_password
from ansible_collections.f5networks.f5os.plugins.modules.velos_partition_change_password import (
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
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.user_name, 'foo')
        self.assertEqual(p.old_password, 'barfoo')
        self.assertEqual(p.new_password, 'abc123@!')

    def test_new_password_raises(self):
        args = dict(
            new_password='foobar',
            old_password='foobar'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.new_password()

        self.assertIn('Old and new password cannot be the same', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.velos_partition_change_password.F5Client'
        )
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.velos_partition_change_password.send_teem'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_change_password_success(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        expected = {'input': [{'old-password': 'barfoo', 'new-password': 'abc123@!', 'confirm-password': 'abc123@!'}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=204, contents=''))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            '/authentication/users/user=foo/config/change-password', mm.client.post.call_args_list[0][0][0]
        )
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected)

    def test_change_password_fail(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post = Mock(return_value=dict(code=400, contents=load_fixture('password_change_error.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Incorrect old password', err.exception.args[0]['errors']['error'][0]['error-message'])

    def test_change_password_same_password_raises(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='barfoo'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Old and new password cannot be the same.', err.exception.args[0])
        self.assertEqual(mm.client.post.call_count, 0)

    @patch.object(velos_partition_change_password, 'Connection')
    @patch.object(velos_partition_change_password.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            velos_partition_change_password.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(velos_partition_change_password, 'Connection')
    @patch.object(velos_partition_change_password.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            user_name='foo',
            old_password='barfoo',
            new_password='abc123@!'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            velos_partition_change_password.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
