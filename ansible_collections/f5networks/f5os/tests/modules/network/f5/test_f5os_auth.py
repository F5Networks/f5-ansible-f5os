# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_auth
from ansible_collections.f5networks.f5os.plugins.modules.f5os_auth import (
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
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_tacacs_server_auth(self):
        set_module_args(dict(
            servergroups=[
                dict(
                    name='tacacs_server',
                    protocol='tacacs',
                    servers=[
                        {'address': '1.2.3.4', 'secret': 'supersecret', 'port': 49},
                        {'address': '1.2.3.5', 'secret': 'secret', 'port': 49}
                    ]
                ),
                dict(
                    name='radius_server',
                    protocol='radius',
                    servers=[
                        {'address': '10.2.3.4', 'secret': 'TOPSECRET', 'port': 1812, 'timeout': 3},
                        {'address': '10.2.3.5', 'secret': 'TOPSECRET', 'port': 1812, 'timeout': 3}
                    ]
                ),
                dict(
                    name='ldap_server',
                    protocol='ldap',
                    servers=[
                        {'address': '11.22.33.44', 'port': 389},
                        {'address': '21.22.33.44', 'port': 636, 'security': 'tls'},
                    ]
                ),
                dict(
                    name='ocsp_server',
                    protocol='ocsp',
                    servers=[
                        {'address': '21.34.56.33', 'port': 80},
                        {'address': '10.198.168.11', 'port': 80},
                    ]
                )
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=404))
        mm.client.post = Mock(return_value=dict(code=200))

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 4)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_tacacs_server_auth(self):
        set_module_args(dict(
            servergroups=[
                dict(
                    name='tacacs_server',
                    protocol='tacacs',
                    servers=[
                        {'address': '1.2.3.4', 'secret': 'supersecret', 'port': 49},
                        {'address': '1.2.3.5', 'secret': 'secret', 'port': 49}
                    ]
                ),
                dict(
                    name='radius_server',
                    protocol='radius',
                    servers=[
                        {'address': '10.2.3.4', 'secret': 'TOPSECRET', 'port': 1812, 'timeout': 3},
                        {'address': '10.2.3.5', 'secret': 'TOPSECRET', 'port': 1812, 'timeout': 3}
                    ]
                ),
                dict(
                    name='ldap_server',
                    protocol='ldap',
                    servers=[
                        {'address': '11.22.33.44', 'port': 389},
                        {'address': '21.22.33.44', 'port': 636, 'security': 'tls'},
                    ]
                ),
                dict(
                    name='ocsp_server',
                    protocol='ocsp',
                    servers=[
                        {'address': '21.34.56.33', 'port': 80},
                        {'address': '10.198.168.11', 'port': 80},
                    ]
                )
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.all_exist = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=404, conetents={}))
        mm.client.put = Mock(return_value=dict(code=200))

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 4)
        self.assertEqual(mm.client.get.call_count, 4)

    def test_remove_server_groups(self):
        set_module_args(dict(
            servergroups=[dict(name='tacacs_server')],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[{'code': 200}, {'code': 404}])
        mm.client.delete = Mock(return_value={'code': 204})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_create_remote_roles_auth(self):
        set_module_args(dict(
            remote_roles=[
                dict(rolename='admin', remote_gid=10, ldap_group='admins'),
                dict(rolename='resource-admin', remote_gid=20, ldap_group='resource-admins')
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 200, 'contents': {'f5-system-aaa:role': [{'config': ''}]}})
        mm.client.patch = Mock(return_value={'code': 200})

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.patch.call_count, 2)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_remote_roles_auth(self):
        set_module_args(dict(
            remote_roles=[
                dict(rolename='admin', remote_gid=10, ldap_group='admins'),
                dict(rolename='resource-admin', remote_gid=20, ldap_group='resource-admins')
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(
            return_value={
                'code': 200,
                'contents': {
                    'f5-system-aaa:role': [
                        {'config': {'remote-gid': 9, 'ldap-group': 'non-admin', 'rolename': 'admin'}},
                        {'config': {'remote-gid': 7, 'ldap-group': 'non-admin', 'rolename': 'resource-admin'}}
                    ]
                }
            }
        )

        mm.client.patch = Mock(return_value={'code': 200})

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.patch.call_count, 2)

    def test_remove_remote_roles_auth(self):
        set_module_args(dict(
            remote_roles=[
                dict(rolename='admin', remote_gid=10, ldap_group='admins'),
                dict(rolename='resource-admin', remote_gid=20, ldap_group='resource-admins')
            ],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': {'f5-system-aaa:role': [{'config': {'ldap-group': ''}}]}},
            {'code': 200, 'contents': {'f5-system-aaa:role': [{'config': ''}]}},
            {'code': 200, 'contents': {'f5-system-aaa:role': [{'config': ''}]}},
        ])
        mm.client.delete = Mock(return_value={'code': 204})

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 4)
        self.assertEqual(mm.client.get.call_count, 3)

    def test_create_password_policy(self):
        set_module_args(dict(
            password_policy=dict(
                apply_to_root=True,
                max_age=10,
                max_class_repeat=3,
                max_letter_repeat=3,
                max_login_failures=3,
                max_retries=3,
                max_sequence_repeat=3,
                min_differences=3,
                min_length=8,
                min_lower=1,
                min_number=1,
                min_special=1,
                min_upper=1,
                reject_username=True,
                root_lockout=True,
                root_unlock_time=10,
                unlock_time=10,
            )
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            {'code': 200},
            {'code': 200, 'contents': {'f5-openconfig-aaa-password-policy:password-policy': {'config': {}}}}
        ])
        mm.client.put = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_remove_password_policy(self):
        set_module_args(dict(
            password_policy=dict(
                apply_to_root=True,
                max_age=10,
                max_class_repeat=3,
                max_letter_repeat=3,
                max_login_failures=3,
                max_retries=3,
                max_sequence_repeat=3,
                min_differences=3,
                min_length=8,
                min_lower=1,
                min_number=1,
                min_special=1,
                min_upper=1,
                reject_username=True,
                root_lockout=True,
                root_unlock_time=10,
                unlock_time=10,
            ),
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value={'code': 200})
        mm.client.delete = Mock(return_value={'code': 204})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_create_auth_order(self):
        set_module_args(dict(
            auth_order=['radius', 'tacacs', 'ldap', 'local'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.put = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_auth_order(self):
        set_module_args(dict(
            auth_order=['radius', 'tacacs', 'ldap', 'local'],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(
            return_value={
                'code': 200,
                'contents': {
                    'openconfig-system:authentication-method': ['openconfig-aaa-types:RADIUS_ALL', 'openconfig-aaa-types:TACACS_ALL']
                }
            }
        )
        mm.client.put = Mock(return_value={'code': 200})

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_remove_auth_order(self):
        set_module_args(dict(
            auth_order=['radius', 'tacacs', 'ldap', 'local'],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.delete = Mock(return_value={'code': 204})
        mm.still_exists = Mock(return_value=False)

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)

    @patch.object(f5os_auth, 'Connection')
    @patch.object(f5os_auth.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            auth_order=['radius', 'tacacs', 'ldap', 'local'],
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_auth.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_auth, 'Connection')
    @patch.object(f5os_auth.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            auth_order=['radius', 'tacacs', 'ldap', 'local'],
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_auth.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
