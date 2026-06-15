# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_auth_ldap
from ansible_collections.f5networks.f5os.plugins.modules.f5os_auth_ldap import (
    ModuleParameters,
    ApiParameters,
    ArgumentSpec,
    Difference,
    ModuleManager,
    ReportableChanges,
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

    def test_module_parameters_with_bind_password(self):
        args = dict(
            base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret123",
            update_password='always',
            bind_timeout=10,
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.base_dn, "dc=example,dc=com")
        self.assertEqual(p.bind_dn, "cn=admin,dc=example,dc=com")
        self.assertEqual(p.bind_password, "secret123")
        self.assertEqual(p.bind_timeout, 10)

    def test_api_parameters_with_encrypted_bindpw(self):
        args = {
            'base': ['dc=example,dc=com'],
            'binddn': 'cn=admin,dc=example,dc=com',
            'bindpw': '$8$encrypted_aes_string',
            'bind_timelimit': 10,
            'timelimit': 30,
            'idle_timelimit': 300,
            'ldap_version': 3,
            'ssl': 'off',
        }
        p = ApiParameters(params=args)
        self.assertEqual(p.base_dn, "dc=example,dc=com")
        self.assertEqual(p.bind_dn, "cn=admin,dc=example,dc=com")
        self.assertEqual(p.bind_password, "$8$encrypted_aes_string")
        self.assertEqual(p.bind_timeout, 10)

    def test_api_parameters_with_no_bindpw(self):
        args = {
            'base': ['dc=example,dc=com'],
            'binddn': 'cn=admin,dc=example,dc=com',
            'bind_timelimit': 10,
        }
        p = ApiParameters(params=args)
        self.assertIsNone(p.bind_password)


class TestDifference(unittest.TestCase):

    def test_bind_password_always_returns_wanted(self):
        want = ModuleParameters(params=dict(
            bind_password='newpassword',
            update_password='always',
        ))
        have = ApiParameters(params=dict(
            bindpw='$8$encrypted_aes_string',
        ))
        diff = Difference(want, have)
        result = diff.compare('bind_password')
        self.assertEqual(result, 'newpassword')

    def test_bind_password_always_returns_wanted_even_if_none_on_device(self):
        want = ModuleParameters(params=dict(
            bind_password='newpassword',
            update_password='always',
        ))
        have = ApiParameters(params=dict())
        diff = Difference(want, have)
        result = diff.compare('bind_password')
        self.assertEqual(result, 'newpassword')

    def test_bind_password_on_create_sets_when_no_existing(self):
        want = ModuleParameters(params=dict(
            bind_password='newpassword',
            update_password='on_create',
        ))
        have = ApiParameters(params=dict())
        diff = Difference(want, have)
        result = diff.compare('bind_password')
        self.assertEqual(result, 'newpassword')

    def test_bind_password_on_create_skips_when_existing(self):
        want = ModuleParameters(params=dict(
            bind_password='newpassword',
            update_password='on_create',
        ))
        have = ApiParameters(params=dict(
            bindpw='$8$encrypted_aes_string',
        ))
        diff = Difference(want, have)
        result = diff.compare('bind_password')
        self.assertIsNone(result)

    def test_bind_password_none_when_not_specified(self):
        want = ModuleParameters(params=dict(
            update_password='always',
        ))
        have = ApiParameters(params=dict(
            bindpw='$8$encrypted_aes_string',
        ))
        diff = Difference(want, have)
        result = diff.compare('bind_password')
        self.assertIsNone(result)


class TestReportableChanges(unittest.TestCase):

    def test_bind_password_not_returned(self):
        changes = ReportableChanges(params=dict(bind_password='secret'))
        self.assertIsNone(changes.bind_password)


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(
            AnsibleModule, exit_json=exit_json, fail_json=fail_json
        )
        self.mock_module_helper.start()
        self.p1 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.f5os_auth_ldap.F5Client'
        )
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.f5os_auth_ldap.send_teem'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_update_bind_password_always(self):
        """bind_password should be sent when update_password=always (default)."""
        set_module_args(dict(
            bind_password='newpassword',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_auth_ldap_current.json')
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_update_bind_password_on_create_no_existing(self):
        """bind_password should be sent when update_password=on_create and no password exists."""
        set_module_args(dict(
            bind_password='newpassword',
            update_password='on_create',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_auth_ldap_no_bindpw.json')
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_update_bind_password_on_create_skips_existing(self):
        """bind_password should NOT be sent when update_password=on_create and password exists."""
        set_module_args(dict(
            bind_password='newpassword',
            update_password='on_create',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_auth_ldap_current.json')
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        mm.client.put.assert_not_called()

    def test_update_without_bind_password(self):
        """When bind_password is not specified, changing another param should work."""
        set_module_args(dict(
            bind_timeout=20,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_auth_ldap_current.json')
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_no_change_when_nothing_different(self):
        """No change when all specified params match current state."""
        set_module_args(dict(
            base_dn='dc=example,dc=com',
            bind_dn='cn=admin,dc=example,dc=com',
            bind_timeout=10,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_auth_ldap_current.json')
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_bind_password_not_leaked_in_results(self):
        """Verify bind_password is not present in module results."""
        set_module_args(dict(
            bind_password='newpassword',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_auth_ldap_current.json')
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertNotIn('bind_password', results)

    @patch.object(f5os_auth_ldap, 'Connection')
    @patch.object(f5os_auth_ldap.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            base_dn='dc=example,dc=com',
        ))
        with self.assertRaises(AnsibleExitJson) as result:
            f5os_auth_ldap.main()
        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_auth_ldap, 'Connection')
    @patch.object(f5os_auth_ldap.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            base_dn='dc=example,dc=com',
        ))
        with self.assertRaises(AnsibleFailJson) as result:
            f5os_auth_ldap.main()
        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
