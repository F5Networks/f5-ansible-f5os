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
    ApiParameters, ArgumentSpec, ModuleManager
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
    def test_api_paramaeters_ciphers(self):
        args2 = {
            'ciphers': [
                {
                    'name': 'sshd',
                    'config': {
                        'ciphers': ['aes256-ctr', 'aes256-gcm@openssh.com'],
                        'kexalgorithms': ['ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'],
                        'macs': ['hmac-sha1', 'hmac-sha1-96'],
                        'host-key-algorithms': ['ssh-rsa', 'ssh-ecdsa'],
                    }
                },
            ]
        }

        p = ApiParameters(params=args2)

        self.assertEqual(p.sshd_ciphers, ['aes256-ctr', 'aes256-gcm@openssh.com'])
        self.assertEqual(p.sshd_kex_alg, ['ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'])
        self.assertEqual(p.sshd_mac_alg, ['hmac-sha1', 'hmac-sha1-96'])
        self.assertEqual(p.sshd_hkey_alg, ['ssh-ecdsa', 'ssh-rsa'])

    def test_api_parameters_none_values(self):
        args = {}

        p = ApiParameters(params=args)

        self.assertIsNone(p.hostname)
        self.assertIsNone(p.motd)
        self.assertIsNone(p.login_banner)
        self.assertIsNone(p.timezone)
        self.assertIsNone(p.cli_timeout)
        self.assertIsNone(p.httpd_ciphersuite)
        self.assertIsNone(p.sshd_idle_timeout)
        self.assertIsNone(p.sshd_ciphers)
        self.assertIsNone(p.sshd_kex_alg)
        self.assertIsNone(p.sshd_mac_alg)
        self.assertIsNone(p.sshd_hkey_alg)
        self.assertIsNone(p.gui_advisory)


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

    def test_create_system_settings(self):
        set_module_args(
            dict(
                state='present',
                hostname='foobar',
                motd='Todays weather is great!',
                login_banner='foofoo',
                timezone='America/New_York',
                cli_timeout=300,
                sshd_idle_timeout=1800,
                httpd_ciphersuite='ECDHE-RSA-AES256-GCM-SHA384',
                sshd_ciphers=['aes256-ctr', 'aes256-gcm@openssh.com'],
                sshd_kex_alg=['ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'],
                sshd_mac_alg=['hmac-sha1', 'hmac-sha1-96'],
                sshd_hkey_alg=['ssh-rsa']
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 404},
            {'code': 200, 'contents': load_fixture('system_settings_hostname.json')},
            {'code': 200, 'contents': load_fixture('system_settings_clock.json')},
            {'code': 200, 'contents': load_fixture('system_settings_ciphers.json')},
            {'code': 200, 'contents': load_fixture('system_settings.json')},
            {'code': 200, 'contents': load_fixture('system_settings_lifetime.json')},
        ])

        mm.client.patch = Mock(return_value=dict(code=200))
        mm.client.put = Mock(return_value=dict(code=200))

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 5)
        self.assertEqual(mm.client.patch.call_count, 2)

    def test_remove_system_settings(self):
        set_module_args(
            dict(
                state='absent',
                hostname='foobar',
                motd='Todays weather is great!',
                login_banner='foofoo',
                timezone='America/New_York',
                cli_timeout=300,
                sshd_idle_timeout=1800,
                httpd_ciphersuite='ECDHE-RSA-AES256-GCM-SHA384',
                sshd_ciphers=['aes256-ctr', 'aes256-gcm@openssh.com'],
                sshd_kex_alg=['ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'],
                sshd_mac_alg=['hmac-sha1', 'hmac-sha1-96'],
                sshd_hkey_alg=['ssh-rsa']
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(return_value=dict(code=200))
        mm.client.delete = Mock(return_value=dict(code=204))
        mm.still_exists = Mock(return_value=False)

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 10)

    def test_update_hostname_setting(self, *args):
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
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': load_fixture('system_settings_hostname.json')},
            {'code': 200, 'contents': load_fixture('system_settings_clock.json')},
            {'code': 200, 'contents': load_fixture('system_settings_ciphers.json')},
            {'code': 200, 'contents': load_fixture('system_settings.json')},
            {'code': 200, 'contents': load_fixture('system_settings_lifetime.json')},
        ])
        mm.client.patch = Mock(return_value=dict(code=200))

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 5)

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

    def test_device_call_functions(self):
        set_module_args(
            dict(
                state='absent',
                hostname='foobar',
                motd='Todays weather is great!',
                login_banner='foofoo',
                timezone='America/New_York',
                cli_timeout=300,
                sshd_idle_timeout=1800,
                httpd_ciphersuite='ECDHE-RSA-AES256-GCM-SHA384',
                sshd_ciphers=['aes256-ctr', 'aes256-gcm@openssh.com'],
                sshd_kex_alg=['ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'],
                sshd_mac_alg=['hmac-sha1', 'hmac-sha1-96'],
                sshd_hkey_alg=['ssh-rsa']
            )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.any_exists = Mock(return_value=False)
        res1 = mm.absent()
        self.assertFalse(res1)

        mm._update_changed_options = Mock(return_value=False)
        res2 = mm.should_update()
        self.assertFalse(res2)

        mm.read_current_from_device = Mock()
        mm.should_update = Mock(return_value=False)
        res3 = mm.update()
        self.assertFalse(res3)

        mm.remove_from_device = Mock()
        mm.still_exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err1:
            mm.remove()
        self.assertIn('Failed to delete the resource.', err1.exception.args[0])
