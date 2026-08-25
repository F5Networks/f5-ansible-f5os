# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import pytest

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_auth
from ansible_collections.f5networks.f5os.plugins.modules.f5os_auth import (
    ArgumentSpec, ModuleManager, ApiParameters
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch
)
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json, AnsibleFailJson, AnsibleExitJson
)

from ansible_collections.f5networks.f5os.plugins.modules.f5os_auth import ModuleParameters
from ansible_collections.f5networks.f5os.plugins.module_utils.client import F5Client

fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


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

    def test_read_current_from_device_password_policy_error(self):
        set_module_args(dict(password_policy=dict(apply_to_root=True)))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.want = Mock()
        mm.want.servergroups = None
        mm.want.password_policy = True
        mm.want.auth_order = None
        mm.want.remote_roles = None
        mm.client = Mock()
        mm.client.get = Mock(return_value={'code': 400, 'contents': {'f5-openconfig-aaa-password-policy:password-policy': 'error'}})
        with self.assertRaises(F5ModuleError):
            mm.read_current_from_device()

    def test_read_current_from_device_auth_order_error(self):
        set_module_args(dict(auth_order=['radius']))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.want = Mock()
        mm.want.servergroups = None
        mm.want.password_policy = None
        mm.want.auth_order = True
        mm.want.remote_roles = None
        mm.client = Mock()
        mm.client.get = Mock(return_value={'code': 400, 'contents': {'openconfig-system:authentication-method': 'error'}})
        with self.assertRaises(F5ModuleError):
            mm.read_current_from_device()

    def test_read_current_from_device_remote_roles_error(self):
        set_module_args(dict(remote_roles=[dict(rolename='admin')]))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.want = Mock()
        mm.want.servergroups = None
        mm.want.password_policy = None
        mm.want.auth_order = None
        mm.want.remote_roles = [dict(rolename='admin')]
        mm.client = Mock()
        mm.client.get = Mock(return_value={'code': 400, 'contents': {'f5-system-aaa:role': 'error'}})
        with self.assertRaises(Exception):
            mm.read_current_from_device()


class AuthProcessor:
    def __init__(self, values):
        self._values = values

    def process_server_groups(self):
        try:
            return_list = []
            servergroups = self._values.get('servergroups')
            if not isinstance(servergroups, list):
                return None

            for api in servergroups:
                config = api.get('config')
                if not config or 'type' not in config:
                    continue

                auth_module = config['type']
                protocol = auth_module.split(":")[1].lower() if ":" in auth_module else auth_module.lower()
                return_item = {
                    'name': api.get('name'),
                    'protocol': protocol
                }

                if 'servers' in api and 'server' in api['servers']:
                    return_item['servers'] = []
                    for server in api['servers']['server']:
                        address = server.get('address')
                        server_conf = {
                            'address': address,
                            'security': None,
                            'secret': None,
                            'timeout': 3  # Default fallback timeout
                        }

                        # Assign auth_name for protocol-specific configurations
                        if protocol in ['radius', 'tacacs']:
                            auth_name = f"f5-openconfig-aaa-{protocol}:{protocol}"
                        elif protocol in ['ldap', 'ocsp']:
                            auth_name = auth_module.lower()
                        else:
                            auth_name = protocol

                        config_section = server.get(auth_name, {}).get('config', {})

                        # Extract the "port"
                        if 'port' in config_section:
                            server_conf['port'] = config_section['port']
                        elif 'auth-port' in config_section:
                            server_conf['port'] = config_section['auth-port']

                        # Identify special "type" for LDAPS
                        if 'type' in config_section:
                            if config_section['type'].lower() == 'f5-openconfig-aaa-ldap:ldaps':
                                server_conf['security'] = 'tls'

                        # Include "secret-key" if available
                        if 'secret-key' in config_section:
                            server_conf['secret'] = config_section['secret-key']

                        # Include "timeout" (generic or radius-specific)
                        if 'f5-openconfig-aaa-radius:timeout' in config_section:
                            server_conf['timeout'] = config_section['f5-openconfig-aaa-radius:timeout']
                        elif 'timeout' in config_section:
                            server_conf['timeout'] = config_section['timeout']

                        # Add the processed server configuration
                        return_item['servers'].append(server_conf)

                # Append the configured group
                return_list.append(return_item)

            return return_list
        except (TypeError, ValueError):
            # Handle invalid data structures
            return None
        except KeyError:
            # Handle unexpected missing keys
            return []


def test_return_item_with_ldap_protocol():
    values = {
        'servergroups': [
            {
                'name': 'ldap_server',
                'config': {'type': 'f5-openconfig-aaa-ldap:LDAP'},
                'servers': {
                    'server':
                    [
                        {
                            'address': '192.168.1.1',
                            'f5-openconfig-aaa-ldap:ldap': {
                                'config': {
                                    'port': 389,
                                    'type': 'f5-openconfig-aaa-ldap:ldaps',
                                    'secret-key': 'supersecret',
                                    'timeout': 10
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
    processor = AuthProcessor(values)
    result = processor.process_server_groups()

    # Debugging output
    print("RESULT:", result)
    expected = [
        {
            'name': 'ldap_server',
            'protocol': 'ldap',
            'servers': [
                {'address': '192.168.1.1', 'security': 'tls', 'secret': 'supersecret', 'timeout': 10, 'port': 389}
            ]
        }
    ]
    print("EXPECTED:", expected)

    assert result == expected


def test_return_item_with_radius_protocol():
    values = {
        'servergroups': [
            {
                'name': 'radius_server',
                'config': {'type': 'f5-openconfig-aaa:RADIUS'},
                'servers': {
                    'server': [
                        {'address': '192.168.1.1', 'f5-openconfig-aaa-radius:radius': {'config': {'port': 1812}}}
                    ]
                }
            }
        ]
    }
    processor = AuthProcessor(values)
    result = processor.process_server_groups()
    expected = [
        {
            'name': 'radius_server',
            'protocol': 'radius',
            'servers': [
                {'address': '192.168.1.1', 'security': None, 'secret': None, 'timeout': 3, 'port': 1812}
            ]
        }
    ]
    assert result == expected


def test_api_parameters_servergroups_full_coverage():
    params = {
        'servergroups': [
            {
                'name': 'radius_group',
                'config': {'type': 'openconfig-aaa:RADIUS'},
                'servers': {
                    'server': [
                        {
                            'address': '1.1.1.1',
                            'radius': {
                                'config': {
                                    'port': 1812,
                                    'secret-key': 'radsecret',
                                    'f5-openconfig-aaa-radius:timeout': 5
                                }
                            }
                        }
                    ]
                }
            },
            {
                'name': 'tacacs_group',
                'config': {'type': 'openconfig-aaa:TACACS'},
                'servers': {
                    'server': [
                        {
                            'address': '2.2.2.2',
                            'tacacs': {
                                'config': {
                                    'port': 49,
                                    'secret-key': 'tacsecret'
                                }
                            }
                        }
                    ]
                }
            },
            {
                'name': 'ldap_group',
                'config': {'type': 'f5-openconfig-aaa-ldap:LDAP'},
                'servers': {
                    'server': [
                        {
                            'address': '3.3.3.3',
                            'f5-openconfig-aaa-ldap:ldap': {
                                'config': {
                                    'auth-port': 636,
                                    'type': 'f5-openconfig-aaa-ldap:ldaps'
                                }
                            }
                        }
                    ]
                }
            },
            {
                'name': 'ocsp_group',
                'config': {'type': 'f5-openconfig-aaa-ocsp:OCSP'},
                'servers': {
                    'server': [
                        {
                            'address': '4.4.4.4',
                            'f5-openconfig-aaa-ocsp:ocsp': {
                                'config': {
                                    'port': 80
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
    p = f5os_auth.ApiParameters(params=params)
    result = p.servergroups
    assert result is not None, "Expected a list, got None"
    assert result[0]['protocol'] == 'radius'
    assert result[0]['servers'][0]['port'] == 1812
    assert result[0]['servers'][0]['secret'] == 'radsecret'
    assert result[0]['servers'][0]['timeout'] == 5

    assert result[1]['protocol'] == 'tacacs'
    assert result[1]['servers'][0]['port'] == 49
    assert result[1]['servers'][0]['secret'] == 'tacsecret'

    assert result[2]['protocol'] == 'ldap'
    assert result[2]['servers'][0]['port'] == 636
    assert result[2]['servers'][0]['security'] == 'tls'

    assert result[3]['protocol'] == 'ocsp'
    assert result[3]['servers'][0]['port'] == 80


def test_api_parameters_servergroups_typeerror():
    # Triggers TypeError by passing None instead of a list
    params = {'servergroups': None}
    p = f5os_auth.ApiParameters(params=params)
    result = p.servergroups
    assert result is None


def test_api_parameters_servergroups_valueerror():
    # Triggers ValueError by passing a custom object that raises ValueError on iteration
    class BadList(list):
        def __iter__(self):
            raise ValueError("bad value")
    params = {'servergroups': BadList()}
    p = f5os_auth.ApiParameters(params=params)
    result = p.servergroups
    assert result is None


def test_api_parameters_servergroups_keyerror():
    # Triggers KeyError by omitting required keys in the dict
    params = {'servergroups': [{'name': 'sg1'}]}  # missing 'config'
    p = f5os_auth.ApiParameters(params=params)
    result = p.servergroups
    assert result == []


def test_auth_processor_typeerror():
    # Triggers TypeError in AuthProcessor
    values = {'servergroups': None}
    processor = AuthProcessor(values)
    result = processor.process_server_groups()
    assert result is None


def test_auth_processor_valueerror():
    # Triggers ValueError in AuthProcessor
    class BadList(list):
        def __iter__(self):
            raise ValueError("bad value")
    values = {'servergroups': BadList()}
    processor = AuthProcessor(values)
    result = processor.process_server_groups()
    assert result is None


def test_auth_processor_keyerror():
    # Triggers KeyError in AuthProcessor
    values = {'servergroups': [{'name': 'sg1'}]}  # missing 'config'
    processor = AuthProcessor(values)
    result = processor.process_server_groups()
    assert result == []


def test_api_parameters_auth_order_coverage():
    params = {
        'auth_order': [
            'f5-openconfig-aaa-ldap:LDAP_ALL',
            'openconfig-aaa-types:LOCAL'
        ]
    }
    p = f5os_auth.ApiParameters(params=params)
    result = p.auth_order
    assert result is not None
    assert 'ldap' in result
    assert 'local' in result


class DummyClient(F5Client):
    def __init__(self, responses=None):
        super().__init__(module=None, client=None)
        self._responses = responses or {}
        self._calls = []

    def get(self, url, **kwargs):
        self._calls.append(('get', url))
        return self._responses.get(url, self._responses.get('default', {'code': 200, 'contents': {}}))

    def post(self, url, data=None, **kwargs):
        self._calls.append(('post', url, data))
        return self._responses.get('post', {'code': 200})

    def put(self, url, data=None, **kwargs):
        self._calls.append(('put', url, data))
        return self._responses.get('put', {'code': 200})

    def patch(self, url, data=None, **kwargs):
        self._calls.append(('patch', url, data))
        return self._responses.get('patch', {'code': 200})

    def delete(self, url, **kwargs):
        self._calls.append(('delete', url))
        # Return the response for this URL or a default
        return self._responses.get(url, self._responses.get('delete', {'code': 204}))


def test_remove_from_device_servergroup_error():
    params = {'servergroups': [{'name': 'sg1'}]}
    responses = {
        '/openconfig-system:system/aaa/server-groups/server-group="sg1"': {'code': 500, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.remove_from_device()


def test_remove_from_device_password_policy_error():
    params = {'password_policy': {'apply_to_root': True}}
    responses = {
        '/openconfig-system:system/aaa/f5-openconfig-aaa-password-policy:password-policy': {'code': 500, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.remove_from_device()


def test_remove_from_device_auth_order_error():
    params = {'auth_order': ['radius']}
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {'code': 500, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.remove_from_device()


def test_remove_from_device_remote_roles_error():
    params = {'remote_roles': [{'rolename': 'admin'}]}
    responses = {
        '/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="admin"/config/remote-gid': {'code': 500, 'contents': {'error': 'fail'}},
        '/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="admin"/config/ldap-group': {'code': 500, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.remove_from_device()


def make_mgr_with_want_and_client(want_params, responses):
    class DummyModule:
        def __init__(self, params):
            self.params = params
    dummy_module = DummyModule(want_params)
    mgr = f5os_auth.ModuleManager(module=dummy_module)
    mgr.client = DummyClient(responses)
    mgr.want = ModuleParameters(params=want_params)
    return mgr


def test_exists_servergroup_200_any():
    params = {'servergroups': [{'name': 'sg1'}]}
    responses = {
        '/openconfig-system:system/aaa/server-groups/server-group="sg1"': {'code': 200, 'contents': {}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    assert mgr.exists(query='any') is True


def test_exists_servergroup_404_all():
    params = {'servergroups': [{'name': 'sg1'}]}
    responses = {
        '/openconfig-system:system/aaa/server-groups/server-group="sg1"': {'code': 404, 'contents': {}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    assert mgr.exists(query='all') is False


def test_exists_servergroup_error():
    params = {'servergroups': [{'name': 'sg1'}]}
    responses = {
        '/openconfig-system:system/aaa/server-groups/server-group="sg1"': {'code': 500, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.exists(query='any')


def test_exists_password_policy_error():
    params = {'password_policy': {'apply_to_root': True}}
    responses = {
        '/openconfig-system:system/aaa/f5-openconfig-aaa-password-policy:password-policy': {'code': 400, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.exists(query='any')


def test_exists_auth_order_200_any():
    params = {'auth_order': ['radius']}
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {'code': 200, 'contents': {}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    assert mgr.exists(query='any') is True


def test_exists_auth_order_404_all():
    params = {'auth_order': ['radius']}
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {'code': 404, 'contents': {}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    assert mgr.exists(query='all') is False


def test_exists_auth_order_error():
    params = {'auth_order': ['radius']}
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {'code': 500, 'contents': {'error': 'fail'}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    with pytest.raises(f5os_auth.F5ModuleError):
        mgr.exists(query='any')


def test_manage_auth_order_absent_without_target_property():
    params = {
        'servergroups': None,
        'password_policy': None,
        'auth_order': None,
        'remote_roles': None,
        'state': 'absent',
    }
    mgr = make_mgr_with_want_and_client(params, {})
    assert mgr._manage_auth_order() is False


def test_manage_auth_order_absent_with_auth_order_target_property():
    params = {
        'servergroups': None,
        'password_policy': None,
        'auth_order': ['radius'],
        'remote_roles': None,
        'state': 'absent',
    }
    mgr = make_mgr_with_want_and_client(params, {})
    assert mgr._manage_auth_order() is True


def test_read_current_auth_order_keypath_not_found_returns_empty_list():
    params = {
        'auth_order': ['radius'],
        'state': 'present',
    }
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {
            'code': 400,
            'contents': {
                'ietf-restconf:errors': {
                    'error': [
                        {'error-message': 'uri keypath not found'}
                    ]
                }
            }
        }
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    result = mgr.read_current_from_device()
    assert result.auth_order == []


def test_read_current_auth_order_exact_restconf_error_payload_returns_empty_list():
    params = {
        'auth_order': ['radius'],
        'state': 'present',
    }
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {
            'code': 400,
            'contents': {
                'ietf-restconf:errors': {
                    'error': [
                        {
                            'error-type': 'application',
                            'error-tag': 'invalid-value',
                            'error-message': 'uri keypath not found'
                        }
                    ]
                }
            }
        }
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    result = mgr.read_current_from_device()
    assert result.auth_order == []


def test_remove_auth_order_absent_without_target_property_404_is_noop():
    params = {
        'servergroups': None,
        'password_policy': None,
        'auth_order': None,
        'remote_roles': None,
        'state': 'absent',
    }
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {'code': 404, 'contents': {}}
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    mgr.remove_from_device()
    assert mgr.client._calls == []


def test_remove_from_device_auth_order_not_configured_still_removes_remote_roles():
    params = {
        'auth_order': ['radius'],
        'remote_roles': [{'rolename': 'admin'}],
        'state': 'absent',
    }
    responses = {
        '/openconfig-system:system/aaa/authentication/config/authentication-method': {'code': 404, 'contents': {}},
        '/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="admin"/config/remote-gid': {'code': 204, 'contents': {}},
        '/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="admin"/config/ldap-group': {'code': 204, 'contents': {}},
    }
    mgr = make_mgr_with_want_and_client(params, responses)
    mgr.remove_from_device()
    assert ('delete', '/openconfig-system:system/aaa/authentication/config/authentication-method') in mgr.client._calls
    assert ('delete', '/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="admin"/config/remote-gid') in mgr.client._calls
    assert ('delete', '/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="admin"/config/ldap-group') in mgr.client._calls


class DummyModule:
    def __init__(self, params):
        self.params = params


def test_read_current_from_device_servergroup_error():
    responses = {
        '/openconfig-system:system/aaa/server-groups/server-group="sg1"': {
            'code': 500,
            'contents': {'openconfig-system:server-group': 'error!'}
        }
    }
    params = {
        'servergroups': [{'name': 'sg1'}],
        'password_policy': None,
        'auth_order': None,
        'remote_roles': None
    }
    dummy_module = DummyModule(params)
    mgr = f5os_auth.ModuleManager(module=dummy_module)
    mgr.client = DummyClient(responses)
    mgr.want = ModuleParameters(params=params)
    import pytest
    with pytest.raises(f5os_auth.F5ModuleError) as exc:
        mgr.read_current_from_device()
    assert 'error!' in str(exc.value)


class TestAuthProcessor(unittest.TestCase):
    def test_return_item_with_radius_protocol(self):
        values = {
            'servergroups': [
                {
                    'name': 'radius_server',
                    'config': {'type': 'f5-openconfig-aaa:RADIUS'},
                    'servers': {
                        'server': [
                            {'address': '192.168.1.1', 'f5-openconfig-aaa-radius:radius': {'config': {'port': 1812}}}
                        ]
                    }
                }
            ]
        }
        processor = AuthProcessor(values)
        result = processor.process_server_groups()

        expected = [
            {
                'name': 'radius_server',
                'protocol': 'radius',
                'servers': [
                    {'address': '192.168.1.1', 'security': None, 'secret': None, 'timeout': 3, 'port': 1812}
                ]
            }
        ]
        self.assertEqual(result, expected)

    def test_return_item_with_empty_input(self):
        values = {'servergroups': []}
        processor = AuthProcessor(values)
        result = processor.process_server_groups()
        self.assertEqual(result, [])


def test_api_parameters_password_policy_type_error():
    class BadValue:
        def get(self, key):
            raise TypeError("bad type")
    p = ApiParameters(params={'password_policy': BadValue()})
    assert p.password_policy is None


def test_api_parameters_remote_roles_type_error():
    p = ApiParameters(params={'remote_roles': 'not_a_list'})
    assert p.remote_roles is None


def test_api_parameters_remote_roles_with_description_and_gid():
    p = ApiParameters(params={
        'remote_roles': [{'config': {'rolename': 'admin', 'remote-gid': 100, 'description': 'test', 'gid': 50}}]
    })
    result = p.remote_roles
    assert result == [{'rolename': 'admin', 'remote_gid': 100}]


def test_exists_remote_roles_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    remote_roles=[dict(rolename='admin', remote_gid=100)],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.get = Mock(return_value=dict(code=500, contents='server error'))
                with pytest.raises(F5ModuleError) as err:
                    mgr.exists(query='any')
                assert 'server error' in str(err.value)


def test_exists_any_password_policy_only():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    password_policy=dict(max_age=90),
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.get = Mock(return_value=dict(code=200, contents={}))
                result = mgr.exists(query='any')
                assert result is True


def test_absent_not_exists():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    servergroups=[dict(name='test', protocol='radius')],
                    state='absent'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.any_exists = Mock(return_value=False)
                result = mgr.absent()
                assert result is False


def test_update_no_change():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    servergroups=[dict(name='test', protocol='radius')],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.have = Mock()
                mgr._update_changed_options = Mock(return_value=False)
                assert mgr.should_update() is False
                mgr.read_current_from_device = Mock(return_value=Mock())
                assert mgr.update() is False


def test_remove_still_exists():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    servergroups=[dict(name='test', protocol='radius')],
                    state='absent'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.remove_from_device = Mock(return_value=True)
                mgr.still_exists = Mock(return_value=True)
                with pytest.raises(F5ModuleError) as err:
                    mgr.remove()
                assert 'Failed to delete the resource.' in str(err.value)


def test_set_password_policy_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    password_policy=dict(max_age=90),
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.put = Mock(return_value=dict(code=400, contents='policy error'))
                with pytest.raises(F5ModuleError) as err:
                    mgr._set_password_policy({'password_policy': {'max_age': 90}})
                assert 'policy error' in str(err.value)


def test_set_auth_order_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    auth_order=['local'],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.put = Mock(return_value=dict(code=400, contents='auth order error'))
                with pytest.raises(F5ModuleError) as err:
                    mgr._set_auth_order({'auth_order': ['local']})
                assert 'auth order error' in str(err.value)


def test_set_auth_order_endpoint_unavailable_error_message():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    auth_order=['local'],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.put = Mock(return_value=dict(code=404, contents={}))
                with pytest.raises(F5ModuleError) as err:
                    mgr._set_auth_order({'auth_order': ['local']})
                assert 'endpoint is not available' in str(err.value)


def test_set_remote_roles_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    remote_roles=[dict(rolename='admin', remote_gid=100)],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.patch = Mock(return_value=dict(code=400, contents='role error'))
                with pytest.raises(F5ModuleError) as err:
                    mgr._set_remote_roles({'remote_roles': [{'rolename': 'admin', 'remote_gid': 100}]})
                assert 'role error' in str(err.value)


def test_create_on_device_servergroup_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    servergroups=[dict(name='test', protocol='radius')],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.changes = Mock()
                mgr.changes.api_params = Mock(return_value={
                    'servergroups': [{'name': 'test', 'protocol': 'radius'}]
                })
                mgr.client.post = Mock(return_value=dict(code=400, contents='create error'))
                with pytest.raises(F5ModuleError) as err:
                    mgr.create_on_device()
                assert 'create error' in str(err.value)


def test_create_on_device_with_password_policy():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    password_policy=dict(max_age=90),
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.changes = Mock()
                mgr.changes.api_params = Mock(return_value={
                    'password_policy': {'max_age': 90}
                })
                mgr._set_password_policy = Mock()
                mgr.create_on_device()
                mgr._set_password_policy.assert_called_once()


def test_update_on_device_servergroup_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    servergroups=[dict(name='test', protocol='radius')],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.changes = Mock()
                mgr.changes.api_params = Mock(return_value={
                    'servergroups': [{'name': 'test', 'protocol': 'radius'}]
                })
                mgr.client.put = Mock(return_value=dict(code=400, contents='update error'))
                with pytest.raises(F5ModuleError) as err:
                    mgr.update_on_device()
                assert 'update error' in str(err.value)


def test_remove_from_device_remote_roles_ldap_error():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    remote_roles=[dict(rolename='admin', remote_gid=100)],
                    state='absent'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.delete = Mock(side_effect=[
                    dict(code=204),
                    dict(code=500, contents='ldap delete error'),
                ])
                with pytest.raises(F5ModuleError) as err:
                    mgr.remove_from_device()
                assert 'ldap delete error' in str(err.value)


def test_read_current_servergroup_success():
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    servergroups=[dict(name='test', protocol='radius')],
                    state='present'
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )
                mgr = ModuleManager(module=module)
                mgr.client.get = Mock(return_value=dict(
                    code=200,
                    contents={'openconfig-system:server-group': [{'name': 'test'}]}
                ))
                result = mgr.read_current_from_device()
                assert result.servergroups is not None


def test_password_policy_new_fields_read_mapping():
    """Test that new password policy fields (min_days, remember, warn_age) are read correctly."""
    api_response = {
        'max-age': 90,
        'min-days': 7,
        'remember': 5,
        'warn-age': 14,
    }

    api_params = ApiParameters(params={'password_policy': api_response})

    # Verify read mapping works
    assert api_params.password_policy['min_days'] == 7
    assert api_params.password_policy['remember'] == 5
    assert api_params.password_policy['warn_age'] == 14


def test_password_policy_new_fields_write_mapping_2_0_0():
    """Test that new password policy fields are written on F5OS 2.0.0+."""
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    password_policy=dict(
                        max_age=90,
                        min_days=7,
                        remember=5,
                        warn_age=14,
                    )
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )

                mgr = ModuleManager(module=module)
                mgr.client.software_version = '2.0.0'

                payload_sent = {}

                def capture_put(uri, data=None):
                    payload_sent['data'] = data
                    return {'code': 200}

                mgr.client.put = Mock(side_effect=capture_put)

                # Call _set_password_policy
                mgr._set_password_policy({
                    'password_policy': {
                        'max_age': 90,
                        'min_days': 7,
                        'remember': 5,
                        'warn_age': 14,
                    }
                })

                # Verify new fields were included in the PUT request
                config = payload_sent['data']['f5-openconfig-aaa-password-policy:password-policy']['config']
                assert config.get('min-days') == 7
                assert config.get('remember') == 5
                assert config.get('warn-age') == 14


def test_password_policy_new_fields_omitted_on_1_8_3():
    """Test that new password policy fields are omitted on F5OS 1.8.3."""
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    password_policy=dict(
                        max_age=90,
                        min_days=7,
                        remember=5,
                        warn_age=14,
                    )
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )

                mgr = ModuleManager(module=module)
                mgr.client.software_version = '1.8.3'

                payload_sent = {}

                def capture_put(uri, data=None):
                    payload_sent['data'] = data
                    return {'code': 200}

                mgr.client.put = Mock(side_effect=capture_put)

                # Call _set_password_policy
                mgr._set_password_policy({
                    'password_policy': {
                        'max_age': 90,
                        'min_days': 7,
                        'remember': 5,
                        'warn_age': 14,
                    }
                })

                # Verify new fields were NOT included in the PUT request
                config = payload_sent['data']['f5-openconfig-aaa-password-policy:password-policy']['config']
                assert 'min-days' not in config
                assert 'remember' not in config
                assert 'warn-age' not in config
                # But existing fields should still be present
                assert config.get('max-age') == 90


def test_password_policy_new_fields_with_old_fields():
    """Test new fields work alongside existing fields."""
    with patch.multiple(AnsibleModule, exit_json=exit_json, fail_json=fail_json):
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.F5Client'):
            with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
                set_module_args(dict(
                    password_policy=dict(
                        apply_to_root=True,
                        max_age=90,
                        min_length=16,
                        min_days=7,
                        remember=5,
                        warn_age=14,
                    )
                ))
                spec = ArgumentSpec()
                module = AnsibleModule(
                    argument_spec=spec.argument_spec,
                    supports_check_mode=spec.supports_check_mode,
                )

                mgr = ModuleManager(module=module)
                mgr.client.software_version = '2.0.0'

                payload_sent = {}

                def capture_put(uri, data=None):
                    payload_sent['data'] = data
                    return {'code': 200}

                mgr.client.put = Mock(side_effect=capture_put)

                # Call _set_password_policy
                mgr._set_password_policy({
                    'password_policy': {
                        'apply_to_root': True,
                        'max_age': 90,
                        'min_length': 16,
                        'min_days': 7,
                        'remember': 5,
                        'warn_age': 14,
                    }
                })

                # Verify all fields are present
                config = payload_sent['data']['f5-openconfig-aaa-password-policy:password-policy']['config']
                assert config.get('apply-to-root') is True
                assert config.get('max-age') == 90
                assert config.get('min-length') == 16
                assert config.get('min-days') == 7
                assert config.get('remember') == 5
                assert config.get('warn-age') == 14


class TestVersionHandling(unittest.TestCase):
    def test_password_policy_gated_fields_raise_when_version_unknown(self):
        set_module_args(dict(
            password_policy={'min_days': 1},
            state='present'
        ))

        spec = ArgumentSpec()
        module = AnsibleModule(
            argument_spec=spec.argument_spec,
            supports_check_mode=spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.software_version = None
        mm.exists = Mock(return_value=False)
        mm.client.put = Mock(return_value={'code': 200})

        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
            with self.assertRaises(F5ModuleError):
                mm.exec_module()

    def test_password_policy_gated_fields_omitted_when_version_unknown(self):
        set_module_args(dict(
            password_policy={'max_age': 30},
            state='present'
        ))

        spec = ArgumentSpec()
        module = AnsibleModule(
            argument_spec=spec.argument_spec,
            supports_check_mode=spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.software_version = None
        mm.exists = Mock(return_value=False)
        mm.client.put = Mock(return_value={'code': 200})

        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_auth.send_teem'):
            results = mm.exec_module()
        self.assertTrue(results['changed'])
