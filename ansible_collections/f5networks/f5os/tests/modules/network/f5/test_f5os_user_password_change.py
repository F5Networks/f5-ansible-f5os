# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_user_password_change
from ansible_collections.f5networks.f5os.plugins.modules.f5os_user_password_change import (
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


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            user_name='admin',
            old_password='oldpass',
            new_password='newpass'
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.old_password, 'oldpass')
        self.assertEqual(p.new_password, 'newpass')
        self.assertEqual(p.confirm_pass, 'newpass')

    def test_module_parameters_same_password_raises(self):
        args = dict(
            user_name='admin',
            old_password='samepass',
            new_password='samepass'
        )
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError):
            p.new_password
        with self.assertRaises(F5ModuleError):
            p.old_password


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_user_password_change.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_user_password_change.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_change_admin_password(self):
        set_module_args(dict(user_name='admin', old_password='oldpass', new_password='newpass'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post = Mock(return_value=dict(code=204, contents={}))
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_change_admin_password_fails(self):
        set_module_args(dict(user_name='admin', old_password='oldpass', new_password='newpass'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post = Mock(return_value=dict(code=500, contents='error'))
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_change_self_user_password(self):
        set_module_args(dict(user_name='bob', old_password='oldpass', new_password='newpass'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.plugin.get_option = Mock(return_value='bob')
        mm.client.post = Mock(return_value=dict(code=204, contents={}))
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_change_self_user_password_fails(self):
        set_module_args(dict(user_name='bob', old_password='oldpass', new_password='newpass'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.plugin.get_option = Mock(return_value='bob')
        mm.client.post = Mock(return_value=dict(code=500, contents='auth error'))
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_change_other_user_password(self):
        set_module_args(dict(user_name='bob', old_password='oldpass', new_password='newpass'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.plugin.get_option = Mock(return_value='admin')
        mm.client.post = Mock(return_value=dict(code=204, contents={}))
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_change_other_user_password_fails(self):
        set_module_args(dict(user_name='bob', old_password='oldpass', new_password='newpass'))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.plugin.get_option = Mock(return_value='admin')
        mm.client.post = Mock(return_value=dict(code=500, contents='set-password error'))
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_check_mode(self):
        set_module_args(dict(user_name='admin', old_password='oldpass', new_password='newpass',
                             _ansible_check_mode=True))
        module = AnsibleModule(argument_spec=self.spec.argument_spec, supports_check_mode=self.spec.supports_check_mode)
        mm = ModuleManager(module=module)
        mm.client = Mock()
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    @patch.object(f5os_user_password_change, 'Connection')
    @patch.object(f5os_user_password_change.ModuleManager, 'exec_module', Mock(return_value={'changed': True}))
    def test_main_success(self, *args):
        set_module_args(dict(user_name='admin', old_password='old', new_password='new'))
        with self.assertRaises(AnsibleExitJson):
            f5os_user_password_change.main()

    @patch.object(f5os_user_password_change, 'Connection')
    @patch.object(f5os_user_password_change.ModuleManager, 'exec_module', Mock(side_effect=F5ModuleError('fail')))
    def test_main_failure(self, *args):
        set_module_args(dict(user_name='admin', old_password='old', new_password='new'))
        with self.assertRaises(AnsibleFailJson):
            f5os_user_password_change.main()
