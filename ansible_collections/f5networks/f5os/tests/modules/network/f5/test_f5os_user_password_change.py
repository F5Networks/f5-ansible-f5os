# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json
from unittest.mock import MagicMock, patch
from unittest import TestCase

from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes
from ansible_collections.f5networks.f5os.plugins.modules import f5os_user_password_change
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError


def set_module_args(args):
    """Prepare arguments so that they will be picked up during module creation"""
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)


class TestParameters(TestCase):
    def test_module_parameters_old_new_password_same(self):
        # Test that an error is raised when old and new passwords are the same
        args = dict(
            user_name='admin',
            old_password='same_password',
            new_password='same_password'
        )
        with self.assertRaises(F5ModuleError) as error:
            p = f5os_user_password_change.ModuleParameters(params=args)
            p.old_password  # Access property to trigger validation
        self.assertIn("Old and new password cannot be the same", str(error.exception))

    def test_module_parameters_valid(self):
        # Test valid parameters
        args = dict(
            user_name='admin',
            old_password='old_pass',
            new_password='new_pass'
        )
        p = f5os_user_password_change.ModuleParameters(params=args)
        self.assertEqual(p.user_name, 'admin')
        self.assertEqual(p.old_password, 'old_pass')
        self.assertEqual(p.new_password, 'new_pass')
        self.assertEqual(p.confirm_pass, 'new_pass')  # Confirm password should match new password


class TestManager(TestCase):
    def setUp(self):
        self.spec = f5os_user_password_change.ArgumentSpec()
        self.mock_module = patch.multiple(basic.AnsibleModule,
                                          exit_json=MagicMock(return_value={}),
                                          fail_json=MagicMock(return_value={}))
        self.mock_module.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.module_utils.client.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_user_password_change.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module.stop()

    def test_change_admin_password(self):
        # Test changing admin password
        set_module_args(dict(
            user_name='admin',
            old_password='old_admin_pass',
            new_password='new_admin_pass'
        ))
        module = basic.AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Configure the mock objects
        mock_connection = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = {'code': 200}
        mm = f5os_user_password_change.ModuleManager(module=module, connection=mock_connection)
        mm.client = mock_client
        results = mm.exec_module()
        # Verify the correct API endpoint was called for admin user
        mock_client.post.assert_called_once_with(
            "/authentication/users/user=admin/config/change-password",
            data={'old-password': 'old_admin_pass', 'new-password': 'new_admin_pass', 'confirm-password': 'new_admin_pass'},
            scope="/restconf/operations/system/aaa"
        )
        self.assertTrue(results['changed'])

    def test_change_other_user_password(self):
        # Test changing a non-admin user password
        set_module_args(dict(
            user_name='user1',
            old_password='old_user_pass',
            new_password='new_user_pass'
        ))
        module = basic.AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Configure the mock objects
        mock_connection = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = {'code': 200}
        mm = f5os_user_password_change.ModuleManager(module=module, connection=mock_connection)
        mm.client = mock_client
        results = mm.exec_module()
        # Verify the correct API endpoint was called for non-admin user
        mock_client.post.assert_called_once_with(
            "/openconfig-system:system/aaa/authentication/f5-system-aaa:users/user=user1/config/set-password",
            data={'password': 'new_user_pass'}
        )
        self.assertTrue(results['changed'])

    def test_api_error_response(self):
        # Test handling of API error response
        set_module_args(dict(
            user_name='admin',
            old_password='old_admin_pass',
            new_password='new_admin_pass'
        ))
        module = basic.AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Configure the mock objects to return an error
        mock_connection = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = {'code': 400, 'contents': 'Invalid password'}
        mm = f5os_user_password_change.ModuleManager(module=module, connection=mock_connection)
        mm.client = mock_client
        with self.assertRaises(F5ModuleError) as error:
            mm.exec_module()
        self.assertEqual(str(error.exception), 'Invalid password')
