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
    UsableChanges,
    _parse_version,
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


class TestParseVersion(unittest.TestCase):

    def test_parse_version_valid(self):
        self.assertEqual(_parse_version('2.0.0'), (2, 0, 0))
        self.assertEqual(_parse_version('2.0.0-9817'), (2, 0, 0))
        self.assertEqual(_parse_version('1.8.3'), (1, 8, 3))

    def test_parse_version_invalid_returns_zero(self):
        self.assertEqual(_parse_version('not-a-version'), (0, 0, 0))
        self.assertEqual(_parse_version(''), (0, 0, 0))


class TestApiParameters(unittest.TestCase):

    def test_api_parameters_full(self):
        data = load_fixture('f5os_auth_ldap_current.json')
        params = data['f5-openconfig-aaa-ldap:ldap']

        p = ApiParameters(params=params)

        self.assertEqual(p.base_dn, 'dc=example,dc=com')
        self.assertEqual(p.bind_dn, 'cn=admin,dc=example,dc=com')
        self.assertEqual(p.bind_password, '$8$AAAAAAAAAAAAAAAAAAAAAA==')
        self.assertEqual(p.bind_timeout, 10)
        self.assertEqual(p.read_timeout, 30)
        self.assertEqual(p.idle_timeout, 300)
        self.assertEqual(p.ldap_version, 3)
        self.assertTrue(p.chase_referrals)
        self.assertEqual(p.tls, 'off')
        self.assertEqual(p.tls_certificate_validation, 'demand')
        self.assertEqual(p.tls_ciphers, 'HIGH:!aNULL:!MD5')
        self.assertTrue(p.active_directory)
        self.assertFalse(p.unix_attributes)
        self.assertEqual(p.tls_ca_certificate, '/path/to/ca.pem')

    def test_api_parameters_no_bindpw(self):
        data = load_fixture('f5os_auth_ldap_no_bindpw.json')
        params = data['f5-openconfig-aaa-ldap:ldap']

        p = ApiParameters(params=params)

        self.assertEqual(p.base_dn, 'dc=example,dc=com')
        self.assertEqual(p.bind_dn, 'cn=admin,dc=example,dc=com')
        self.assertIsNone(p.bind_password)

    def test_api_parameters_empty(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.base_dn)
        self.assertIsNone(p.bind_dn)
        self.assertIsNone(p.bind_password)
        self.assertIsNone(p.bind_timeout)
        self.assertIsNone(p.read_timeout)
        self.assertIsNone(p.idle_timeout)
        self.assertIsNone(p.ldap_version)
        self.assertIsNone(p.tls)
        self.assertIsNone(p.chase_referrals)
        self.assertIsNone(p.tls_certificate_validation)
        self.assertIsNone(p.tls_ciphers)
        self.assertIsNone(p.active_directory)
        self.assertIsNone(p.unix_attributes)
        self.assertIsNone(p.tls_certificate)
        self.assertIsNone(p.tls_key)
        self.assertIsNone(p.tls_ca_certificate)

    def test_api_parameters_with_tls_cert_and_key(self):
        params = {
            'tls_cert': '/path/to/cert.pem',
            'tls_key': '/path/to/key.pem',
            'tls_cacert': '/path/to/ca.pem',
        }

        p = ApiParameters(params=params)

        self.assertEqual(p.tls_certificate, '/path/to/cert.pem')
        self.assertEqual(p.tls_key, '/path/to/key.pem')
        self.assertEqual(p.tls_ca_certificate, '/path/to/ca.pem')

    def test_api_parameters_user_and_group_object_class(self):
        data = load_fixture('f5os_auth_ldap_v2.json')
        params = data['f5-openconfig-aaa-ldap:ldap']

        p = ApiParameters(params=params)

        self.assertEqual(p.user_object_class, ['posixAccount'])
        self.assertEqual(p.group_object_class, ['posixGroup'])

    def test_api_parameters_user_group_object_class_absent(self):
        p = ApiParameters(params={})

        self.assertIsNone(p.user_object_class)
        self.assertIsNone(p.group_object_class)


class TestModuleParameters(unittest.TestCase):

    def test_module_parameters_full(self):
        args = dict(
            base_dn='dc=test,dc=com',
            bind_dn='cn=admin,dc=test,dc=com',
            bind_password='secret123',
            update_password='always',
            bind_timeout=10,
            read_timeout=30,
            idle_timeout=300,
            ldap_version=3,
            chase_referrals=True,
            tls='start_tls',
            tls_certificate_validation='demand',
            tls_ciphers='HIGH:!aNULL:!MD5',
            active_directory=True,
            unix_attributes=False,
            tls_certificate='/path/to/cert.pem',
            tls_key='/path/to/key.pem',
            tls_ca_certificate='/path/to/ca.pem',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.base_dn, 'dc=test,dc=com')
        self.assertEqual(p.bind_dn, 'cn=admin,dc=test,dc=com')
        self.assertEqual(p.bind_password, 'secret123')
        self.assertEqual(p.bind_timeout, 10)
        self.assertEqual(p.read_timeout, 30)
        self.assertEqual(p.idle_timeout, 300)
        self.assertEqual(p.ldap_version, 3)
        self.assertTrue(p.chase_referrals)
        self.assertEqual(p.tls, 'start_tls')
        self.assertEqual(p.tls_certificate_validation, 'demand')
        self.assertEqual(p.tls_ciphers, 'HIGH:!aNULL:!MD5')
        self.assertTrue(p.active_directory)
        self.assertFalse(p.unix_attributes)
        self.assertEqual(p.tls_certificate, '/path/to/cert.pem')
        self.assertEqual(p.tls_key, '/path/to/key.pem')
        self.assertEqual(p.tls_ca_certificate, '/path/to/ca.pem')

    def test_module_parameters_minimal(self):
        args = dict(
            base_dn='dc=test,dc=com',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.base_dn, 'dc=test,dc=com')


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

    def test_tls_params_with_start_tls_changed(self):
        want = ModuleParameters(params=dict(
            tls='start_tls',
            tls_certificate_validation='demand',
            tls_ciphers='HIGH',
            tls_certificate='/path/cert.pem',
            tls_key='/path/key.pem',
            tls_ca_certificate='/path/ca.pem',
        ))
        have = ApiParameters(params=dict(
            ssl='start_tls',
            tls_reqcert='never',
            tls_ciphers='LOW',
            tls_cert='/old/cert.pem',
            tls_key='/old/key.pem',
            tls_cacert='/old/ca.pem',
        ))

        diff = Difference(want, have)
        self.assertEqual(diff.compare('tls_certificate_validation'), 'demand')
        self.assertEqual(diff.compare('tls_ciphers'), 'HIGH')
        self.assertEqual(diff.compare('tls_certificate'), '/path/cert.pem')
        self.assertEqual(diff.compare('tls_key'), '/path/key.pem')
        self.assertEqual(diff.compare('tls_ca_certificate'), '/path/ca.pem')

    def test_tls_params_with_tls_on(self):
        want = ModuleParameters(params=dict(
            tls='on',
            tls_certificate_validation='allow',
        ))
        have = ApiParameters(params=dict(
            ssl='on',
            tls_reqcert='never',
        ))

        diff = Difference(want, have)
        self.assertEqual(diff.compare('tls_certificate_validation'), 'allow')

    def test_tls_params_with_tls_off_ignores(self):
        want = ModuleParameters(params=dict(
            tls='off',
            tls_certificate_validation='demand',
            tls_ciphers='HIGH',
        ))
        have = ApiParameters(params=dict(
            ssl='off',
            tls_reqcert='never',
        ))

        diff = Difference(want, have)
        self.assertIsNone(diff.compare('tls_certificate_validation'))
        self.assertIsNone(diff.compare('tls_ciphers'))
        self.assertIsNone(diff.compare('tls_certificate'))
        self.assertIsNone(diff.compare('tls_key'))
        self.assertIsNone(diff.compare('tls_ca_certificate'))

    def test_tls_params_with_tls_none_ignores(self):
        want = ModuleParameters(params=dict(
            tls=None,
            tls_certificate_validation='demand',
        ))
        have = ApiParameters(params=dict(
            ssl='off',
            tls_reqcert='never',
        ))

        diff = Difference(want, have)
        self.assertIsNone(diff.compare('tls_certificate_validation'))
        self.assertIsNone(diff.compare('tls_ca_certificate'))

    def test_default_compare_changed(self):
        want = ModuleParameters(params=dict(
            base_dn='dc=new,dc=com',
        ))
        have = ApiParameters(params=dict(
            base=['dc=old,dc=com'],
        ))

        diff = Difference(want, have)
        self.assertEqual(diff.compare('base_dn'), 'dc=new,dc=com')

    def test_default_compare_no_change(self):
        want = ModuleParameters(params=dict(
            base_dn='dc=example,dc=com',
        ))
        have = ApiParameters(params=dict(
            base=['dc=example,dc=com'],
        ))

        diff = Difference(want, have)
        self.assertIsNone(diff.compare('base_dn'))

    def test_default_compare_have_missing_attr(self):
        want = ModuleParameters(params=dict(
            base_dn='dc=new,dc=com',
        ))
        have = ApiParameters(params=dict())

        diff = Difference(want, have)
        self.assertEqual(diff.compare('base_dn'), 'dc=new,dc=com')


class TestReportableChanges(unittest.TestCase):

    def test_bind_password_not_returned(self):
        changes = ReportableChanges(params=dict(bind_password='secret'))
        self.assertIsNone(changes.bind_password)

    def test_to_return(self):
        changes = ReportableChanges(params=dict(base_dn='dc=test,dc=com'))
        result = changes.to_return()
        self.assertIsInstance(result, dict)


class TestUsableChanges(unittest.TestCase):

    def test_to_return(self):
        changes = UsableChanges(params=dict(base_dn='dc=test,dc=com'))
        result = changes.to_return()
        self.assertIsInstance(result, dict)


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

    def test_configure_ldap_full_settings(self, *args):
        set_module_args(dict(
            base_dn='dc=example,dc=com',
            bind_dn='cn=admin,dc=example,dc=com',
            bind_password='password',
            bind_timeout=10,
            read_timeout=30,
            idle_timeout=300,
            ldap_version=3,
            chase_referrals=True,
            tls='start_tls',
            tls_certificate_validation='demand',
            tls_ciphers='HIGH:!aNULL:!MD5',
            active_directory=True,
            unix_attributes=False,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_bind_password_always(self, *args):
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

    def test_update_bind_password_on_create_no_existing(self, *args):
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

    def test_update_bind_password_on_create_skips_existing(self, *args):
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

    def test_update_base_dn(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_bind_timeout(self, *args):
        set_module_args(dict(
            bind_timeout=20,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_update_read_timeout(self, *args):
        set_module_args(dict(
            read_timeout=60,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_update_idle_timeout(self, *args):
        set_module_args(dict(
            idle_timeout=600,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_update_tls_to_on(self, *args):
        set_module_args(dict(
            tls='on',
            tls_certificate_validation='allow',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_chase_referrals(self, *args):
        set_module_args(dict(
            chase_referrals=False,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_active_directory(self, *args):
        set_module_args(dict(
            active_directory=False,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_unix_attributes(self, *args):
        set_module_args(dict(
            unix_attributes=True,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_tls_certificate_and_key(self, *args):
        set_module_args(dict(
            tls='on',
            tls_certificate='/path/to/cert.pem',
            tls_key='/path/to/key.pem',
            tls_ca_certificate='/path/to/ca.pem',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        self.assertEqual(ldap_data['tls_cert'], '/path/to/cert.pem')
        self.assertEqual(ldap_data['tls_key'], '/path/to/key.pem')
        self.assertEqual(ldap_data['tls_cacert'], '/path/to/ca.pem')

    def test_no_change_when_nothing_different(self, *args):
        set_module_args(dict(
            base_dn='dc=example,dc=com',
            bind_dn='cn=admin,dc=example,dc=com',
            bind_timeout=10,
            read_timeout=30,
            idle_timeout=300,
            ldap_version=3,
            chase_referrals=True,
            tls='off',
            active_directory=True,
            unix_attributes=False,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_tls_off_ignores_tls_params(self, *args):
        set_module_args(dict(
            tls='off',
            tls_certificate_validation='demand',
            tls_ciphers='HIGH',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        results = mm.exec_module()

        # tls is already 'off' and tls params are ignored when tls is off
        self.assertFalse(results['changed'])

    def test_read_current_from_device_empty_response(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_read_current_from_device_api_failure(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_update_on_device_api_failure_400(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=400, contents='bad request'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('bad request', err.exception.args[0])

    def test_update_on_device_api_failure_500(self, *args):
        set_module_args(dict(
            bind_timeout=99,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_update_on_device_response_201(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_update_on_device_response_204(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_check_mode_with_change(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
            _ansible_check_mode=True,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_check_mode_no_change(self, *args):
        set_module_args(dict(
            base_dn='dc=example,dc=com',
            _ansible_check_mode=True,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_payload_structure(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
            bind_dn='cn=newadmin,dc=new,dc=com',
            bind_password='newpass',
            bind_timeout=20,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        self.assertEqual(ldap_data['base'], ['dc=new,dc=com'])
        self.assertEqual(ldap_data['binddn'], 'cn=newadmin,dc=new,dc=com')
        self.assertEqual(ldap_data['bindpw'], 'newpass')
        self.assertEqual(ldap_data['bind_timelimit'], 20)

    def test_update_removes_none_values_from_payload(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        # None values should be removed from payload
        self.assertNotIn('bindpw', ldap_data)
        self.assertNotIn('bind_timelimit', ldap_data)
        self.assertNotIn('timelimit', ldap_data)
        self.assertNotIn('idle_timelimit', ldap_data)
        self.assertNotIn('tls_cacert', ldap_data)

    def test_bind_password_not_leaked_in_results(self, *args):
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

    def test_update_multiple_fields(self, *args):
        set_module_args(dict(
            base_dn='dc=newdomain,dc=org',
            bind_timeout=60,
            read_timeout=120,
            idle_timeout=600,
            ldap_version=2,
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_configure_user_and_group_object_class_v2(self, *args):
        set_module_args(dict(
            user_object_class=['posixAccount'],
            group_object_class=['posixGroup'],
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        self.assertEqual(ldap_data['user-object-class'], ['posixAccount'])
        self.assertEqual(ldap_data['group-object-class'], ['posixGroup'])

    def test_user_group_object_class_round_trip_v2(self, *args):
        set_module_args(dict(
            user_object_class=['posixAccount'],
            group_object_class=['posixGroup'],
        ))

        current = load_fixture('f5os_auth_ldap_v2.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        # values already match what is on the device — no change expected
        self.assertFalse(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_user_group_object_class_omitted_on_pre_v2(self, *args):
        set_module_args(dict(
            user_object_class=['posixAccount'],
            group_object_class=['posixGroup'],
            base_dn='dc=example,dc=com',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '1.8.3'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        # base_dn is unchanged so the only change candidates are the new fields;
        # on pre-2.0 those are silently omitted — no PUT should be issued
        self.assertFalse(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_user_group_object_class_omitted_silently_no_error(self, *args):
        """Pre-v2 device: specifying the new fields raises no error."""
        set_module_args(dict(
            user_object_class=['posixAccount'],
            group_object_class=['posixGroup'],
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '1.5.0'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        # Should complete without raising any exception
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_payload_excludes_object_class_on_pre_v2(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
            user_object_class=['posixAccount'],
            group_object_class=['posixGroup'],
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '1.8.3'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        self.assertNotIn('user-object-class', ldap_data)
        self.assertNotIn('group-object-class', ldap_data)

    def test_payload_includes_object_class_on_v2(self, *args):
        set_module_args(dict(
            base_dn='dc=new,dc=com',
            user_object_class=['posixAccount'],
            group_object_class=['posixGroup'],
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        self.assertIn('user-object-class', ldap_data)
        self.assertIn('group-object-class', ldap_data)
        self.assertEqual(ldap_data['user-object-class'], ['posixAccount'])
        self.assertEqual(ldap_data['group-object-class'], ['posixGroup'])

    def test_version_suffix_parsed_correctly(self, *args):
        """Version strings like '2.0.0-9817' must be treated as >= 2.0.0."""
        set_module_args(dict(
            user_object_class=['posixAccount'],
            base_dn='dc=new,dc=com',
        ))

        current = load_fixture('f5os_auth_ldap_current.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.software_version = '2.0.0-9817'
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        put_payload = mm.client.put.call_args[1]['data']
        ldap_data = put_payload['f5-openconfig-aaa-ldap:ldap']
        self.assertIn('user-object-class', ldap_data)

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
