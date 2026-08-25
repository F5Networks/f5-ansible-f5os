# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_snmp
from ansible_collections.f5networks.f5os.plugins.modules.f5os_snmp import (
    ArgumentSpec, ModuleManager, ModuleParameters, ApiParameters, UsableChanges
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


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_snmp.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_snmp.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_snmp_community(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_snmp_user(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='user1',
                auth_proto="MD5",
                auth_passwd="pass1",
                privacy_proto="DES",
                privacy_passwd="pass2",
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_snmp_target(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model="v1",
                community="community1",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:0000:130F:0000:0000:09C0:876A:130B",
                port="8080",
                # user="user1",
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_snmp_mib(self, *args):
        set_module_args(dict(
            snmp_mib=dict(
                syscontact='user user@email.com',
                sysname='appliance-x',
                syslocation="appliance-x.chassis.local",
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.patch = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)

    def test_update_snmp_community(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})
        mm.client.put = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 2)

    def test_update_snmp_target(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model="v1",
                community="community1",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:0000:130F:0000:0000:09C0:876A:130B",
                port="8080",
                # user="user1",
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    @patch.object(f5os_snmp, 'Connection')
    @patch.object(f5os_snmp.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_snmp.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_snmp, 'Connection')
    @patch.object(f5os_snmp.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_snmp.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_delete_snmp_community(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2'],
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # First exists() → True; second exists() after delete → False (404)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': {
                'f5-system-snmp:snmp': {'communities': {'community': [{'config': {'name': 'test1_com'}}]}}
            }},
            {'code': 404},
        ])
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once()

    def test_delete_snmp_target(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model='v1',
                community='community1',
                ipv4_address='1.2.3.4',
                port=8080,
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': {
                'f5-system-snmp:snmp': {'targets': {'target': [{'config': {'name': 'target1'}}]}}
            }},
            {'code': 404},
        ])
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once()

    def test_delete_snmp_user(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='user1',
                auth_proto='MD5',
                auth_passwd='pass1',
                privacy_proto='DES',
                privacy_passwd='pass2',
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': {
                'f5-system-snmp:snmp': {'users': {'user': [{'config': {'name': 'user1'}}]}}
            }},
            {'code': 404},
        ])
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.delete.assert_called_once()

    def test_delete_snmp_community_api_error(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1'],
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': {
            'f5-system-snmp:snmp': {'communities': {'community': [{'config': {'name': 'test1_com'}}]}}
        }})
        mm.client.delete = Mock(return_value={'code': 500, 'contents': 'delete error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('delete error', err.exception.args[0])

    def test_delete_snmp_target_api_error(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model='v1',
                community='com1',
                ipv4_address='1.2.3.4',
                port=161,
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': {
            'f5-system-snmp:snmp': {'targets': {'target': [{'config': {'name': 'target1'}}]}}
        }})
        mm.client.delete = Mock(return_value={'code': 500, 'contents': 'target delete error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('target delete error', err.exception.args[0])

    def test_delete_snmp_user_api_error(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='user1',
                auth_proto='MD5',
                auth_passwd='pass1',
                privacy_proto='DES',
                privacy_passwd='pass2',
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': {
            'f5-system-snmp:snmp': {'users': {'user': [{'config': {'name': 'user1'}}]}}
        }})
        mm.client.delete = Mock(return_value={'code': 500, 'contents': 'user delete error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('user delete error', err.exception.args[0])

    def test_state_absent_not_exists(self, *args):
        """state=absent when nothing exists returns no change."""
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1'],
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_exists_api_error(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1'],
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'exists error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('exists error', err.exception.args[0])

    def test_create_snmp_community_api_error(self, *args):
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1'],
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'community create error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('community create error', err.exception.args[0])

    def test_update_no_change(self, *args):
        """Update path where nothing changed (should_update returns False)."""
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2', 'v3'],
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_snmp_target_api_error(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model='v1',
                community='com1',
                ipv4_address='1.2.3.4',
                port=161,
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'target create error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('target create error', err.exception.args[0])

    def test_create_snmp_user_api_error(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='user1',
                auth_proto='MD5',
                auth_passwd='pass1',
                privacy_proto='DES',
                privacy_passwd='pass2',
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'user create error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('user create error', err.exception.args[0])

    def test_create_snmp_mib_get_not_found(self, *args):
        set_module_args(dict(
            snmp_mib=dict(
                syscontact='admin@test.com',
                sysname='test-sys',
                syslocation='DC1',
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.patch = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.patch.assert_called_once()

    def test_create_snmp_mib_api_error(self, *args):
        set_module_args(dict(
            snmp_mib=dict(
                syscontact='admin@test.com',
            ),
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.patch = Mock(return_value={'code': 500, 'contents': 'mib create error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('mib create error', err.exception.args[0])

    def test_create_snmp_target_ipv6(self, *args):
        """Test target creation with IPv6 address (no IPv4)."""
        set_module_args(dict(
            snmp_target=[dict(
                name='v6_target',
                security_model='v2c',
                community='com1',
                ipv4_address=None,
                ipv6_address='2001:db8::1',
                port=162,
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        target_config = post_payload['target'][0]['config']
        self.assertIn('ipv6', target_config)
        self.assertNotIn('ipv4', target_config)
        self.assertEqual(target_config['ipv6']['address'], '2001:db8::1')
        self.assertEqual(target_config['ipv6']['port'], 162)

    def test_create_snmp_target_with_user(self, *args):
        """Target with user (v3) instead of community."""
        set_module_args(dict(
            snmp_target=[dict(
                name='v3_target',
                user='v3user',
                ipv4_address='10.0.0.1',
                port=162,
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        target_config = post_payload['target'][0]['config']
        self.assertEqual(target_config['user'], 'v3user')
        self.assertNotIn('community', target_config)

    def test_create_snmp_community_none_security_model(self, *args):
        """Community with security_model=None defaults to 'v1' in UsableChanges."""
        set_module_args(dict(
            snmp_community=[dict(
                name='default_com',
                security_model=None,
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        self.assertEqual(post_payload['community'][0]['config']['security-model'], 'v1')

    def test_update_snmp_user(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='test2_user',
                auth_proto='SHA',
                auth_passwd='newpass',
                privacy_proto='AES',
                privacy_passwd='newprivpass',
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.patch.assert_called_once()

    def test_update_snmp_mib(self, *args):
        set_module_args(dict(
            snmp_mib=dict(
                syscontact='newcontact@example.com',
                sysname='new-sysname',
                syslocation='new-location',
            ),
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.put = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.put.assert_called_once()

    def test_update_snmp_target_api_error(self, *args):
        set_module_args(dict(
            snmp_target=[dict(
                name='target1',
                security_model='v1',
                community='community1',
                ipv4_address='10.0.0.1',
                port=162,
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 500, 'contents': 'update target error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('update target error', err.exception.args[0])

    def test_update_snmp_user_api_error(self, *args):
        set_module_args(dict(
            snmp_user=[dict(
                name='test2_user',
                auth_proto='SHA',
                auth_passwd='newpass',
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 500, 'contents': 'update user error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('update user error', err.exception.args[0])

    def test_update_snmp_mib_api_error(self, *args):
        set_module_args(dict(
            snmp_mib=dict(
                syscontact='contact@test.com',
            ),
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.put = Mock(return_value={'code': 500, 'contents': 'update mib error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('update mib error', err.exception.args[0])

    def test_update_community_create_new_in_update(self, *args):
        """Update with a community that doesn't exist yet triggers patch for new communities."""
        set_module_args(dict(
            snmp_community=[dict(
                name='new_com',
                security_model=['v1', 'v2c'],
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.patch.assert_called_once()

    def test_update_community_create_api_error(self, *args):
        """Update with new community — API error on patch."""
        set_module_args(dict(
            snmp_community=[dict(
                name='new_com',
                security_model=['v1'],
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 500, 'contents': 'community patch error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('community patch error', err.exception.args[0])

    def test_update_community_put_api_error(self, *args):
        """Update existing community — API error on put."""
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1', 'v2c'],
            )],
        ))

        existing_data = load_fixture("f5os_snmp_community_user_target.json")
        existing_data_mib = load_fixture("f5os_snmp_mib.json")

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[existing_data, existing_data_mib])
        mm.client.patch = Mock(return_value={'code': 200})
        mm.client.put = Mock(return_value={'code': 500, 'contents': 'community put error'})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('community put error', err.exception.args[0])

    def test_read_current_from_device_error(self, *args):
        """read_current_from_device raises on non-2xx.
        Note: The module accesses contents['f5-system-snmp:snmp'] before checking
        the code, so we provide a dict-like contents with a non-2xx code."""
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1'],
            )],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        # Provide dict contents so indexing succeeds but code is non-2xx
        mm.client.get = Mock(side_effect=[
            {'code': 500, 'contents': {'f5-system-snmp:snmp': {}}},
            {'code': 200, 'contents': {'SNMPv2-MIB:system': {}}},
        ])

        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_remove_fails_if_still_exists(self, *args):
        """remove() raises if resource still exists after delete."""
        set_module_args(dict(
            snmp_community=[dict(
                name='test1_com',
                security_model=['v1'],
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # exists() returns True both before and after delete
        mm.client.get = Mock(return_value={'code': 200, 'contents': {
            'f5-system-snmp:snmp': {'communities': {'community': [{'config': {'name': 'test1_com'}}]}}
        }})
        mm.client.delete = Mock(return_value={'code': 204})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource', err.exception.args[0])


class TestParameters(unittest.TestCase):

    def test_module_parameters_community(self):
        args = dict(
            snmp_community=[dict(name='com1', security_model=['v1', 'v2c'])],
            snmp_target=None,
            snmp_user=None,
            snmp_mib=None,
            state='present',
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.snmp_community, [dict(name='com1', security_model=['v1', 'v2c'])])
        self.assertIsNone(p.snmp_target)
        self.assertIsNone(p.snmp_user)
        self.assertIsNone(p.snmp_mib)

    def test_api_parameters_community(self):
        params = {
            'communities': {'community': [{'config': {'name': 'com1', 'security-model': ['v1']}}]},
        }
        p = ApiParameters(params=params)
        self.assertEqual(p.snmp_community, [{'name': 'com1', 'security-model': ['v1']}])

    def test_api_parameters_target(self):
        params = {
            'targets': {'target': [{'config': {'name': 't1', 'ipv4': {'address': '1.2.3.4', 'port': 161}}}]},
        }
        p = ApiParameters(params=params)
        self.assertEqual(p.snmp_target, [{'name': 't1', 'ipv4': {'address': '1.2.3.4', 'port': 161}}])

    def test_api_parameters_user(self):
        params = {
            'users': {'user': [{'config': {'name': 'u1', 'authentication-protocol': 'MD5'}}]},
        }
        p = ApiParameters(params=params)
        self.assertEqual(p.snmp_user, [{'name': 'u1', 'authentication-protocol': 'MD5'}])

    def test_usable_changes_snmp_target_ipv6_only(self):
        params = dict(
            snmp_target=[dict(
                name='v6t',
                security_model='v2c',
                community='com1',
                user=None,
                ipv4_address=None,
                ipv6_address='2001:db8::1',
                port=162,
            )],
            snmp_community=None,
            snmp_user=None,
            snmp_mib=None,
        )
        c = UsableChanges(params=params)
        targets = c.snmp_target
        self.assertEqual(targets[0]['config']['ipv6']['address'], '2001:db8::1')
        self.assertNotIn('ipv4', targets[0]['config'])
