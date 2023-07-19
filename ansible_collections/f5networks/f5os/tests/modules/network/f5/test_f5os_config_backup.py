# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_config_backup
from ansible_collections.f5networks.f5os.plugins.modules.f5os_config_backup import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch, PropertyMock
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
            name='foo_config',
            remote_host='1.2.3.4',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'foo_config')
        self.assertEqual(p.remote_host, '1.2.3.4')
        self.assertEqual(p.remote_user, 'admin')
        self.assertEqual(p.remote_password, 'admin')
        self.assertEqual(p.remote_path, '/test/upload.php')
        self.assertEqual(p.local_path, 'configs/foo_config')
        self.assertEqual(p.protocol, 'https')
        self.assertEqual(p.state, 'present')
        self.assertTupleEqual(p.timeout, (6.0, 100))

    def test_module_parameter_failures(self):
        args = dict(
            timeout=100
        )
        p = ModuleParameters(params=args)

        self.assertIsNone(p.remote_path)

        with self.assertRaises(F5ModuleError) as err:
            p.timeout()

        self.assertIn('Timeout value must be between 150 and 3600 seconds.', err.exception.args[0])

    def test_alternative_module_parameter_choices(self):
        args = dict(
            name='foo_config',
            remote_host='fake.host.net',
            remote_path='/test/upload.php',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.local_path, 'configs/foo_config')
        self.assertEqual(p.remote_host, 'fake.host.net')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_config_backup.F5Client')
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p3 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_config_backup.send_teem')
        self.m3 = self.p3.start()
        self.m3.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_import_backup_success(self, *args):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        expected = {'input': [{'insecure': '', 'local-file': 'configs/foo_conf',
                               'password': 'admin', 'protocol': 'https', 'remote-file': '/test/upload.php',
                               'remote-host': '192.168.1.1', 'username': 'admin'}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_created.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_start.json')))
        ])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_progress.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_success.json'))),
        ])
        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn(results['message'], 'Config foo_conf backup and upload successful.')
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected)
        self.assertEqual(results['local_path'], 'configs/foo_conf')

    def test_import_backup_idempotent(self, *args):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_import_backup_force_on(self, *args):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            force=True,
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        expected = {'input': [{'insecure': '', 'local-file': 'configs/foo_conf',
                               'password': 'admin', 'protocol': 'https', 'remote-file': '/test/upload.php',
                               'remote-host': '192.168.1.1', 'username': 'admin'}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_created.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_start.json')))
        ])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_progress.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_success.json'))),
        ])
        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn(results['message'], 'Config foo_conf backup and upload successful.')
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected)
        self.assertEqual(results['local_path'], 'configs/foo_conf')

    def test_backup_failed(self, *args):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=400, contents=dict(load_fixture('f5os_backup_failed.json'))))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to create backup: foo_conf, system returned', err.exception.args[0])

    def test_import_backup_failed(self, *args):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_created.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_start_2.json')))
        ])
        mm.client.get = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_backup_import_failure.json'))
        ))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('File export failed with the following result', err.exception.args[0])

    def test_import_backup_job_not_started(self, *args):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_created.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_import_start.json')))
        ])
        mm.client.get = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_backup_import_failure.json'))
        ))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            'File export job not has not started, check device logs for more information', err.exception.args[0]
        )

    def test_remove_backup(self, *args):
        set_module_args(dict(
            name='foo_conf',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_filelist.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_delete_success.json'))),
            dict(code=204, contents=dict())
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_remove_backup_idempotent(self, *args):
        set_module_args(dict(
            name='foo_conf',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_backup_failed(self, *args):
        set_module_args(dict(
            name='foo_conf',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_filelist.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_backup_delete_failed.json')))
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn("Operation failed with: File doesn't exist", err.exception.args[0])

    @patch.object(ModuleParameters, 'timeout', new_callable=PropertyMock)
    def test_backup_import_progress_check_timeout(self, mock_timeout):
        set_module_args(dict(
            name='foo_conf',
            remote_host='192.168.1.1',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/upload.php',
            protocol='https',
            state='present',
            timeout=600

        ))
        mock_timeout.return_value = (1, 2)
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.create_backup = Mock(return_value=True)
        mm.export_file = Mock(return_value=True)
        mm.is_still_uploading = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Module timeout reached, state change is unknown', err.exception.args[0])

    @patch.object(f5os_config_backup, 'Connection')
    @patch.object(f5os_config_backup.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='barfoo_config',
            state='absent',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_config_backup.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_config_backup, 'Connection')
    @patch.object(f5os_config_backup.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='barfoo_config',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_config_backup.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='bazbar',
            remote_host='192.168.1.1',
            remote_path='/test/upload.php',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.client.post = Mock(side_effect=[
            dict(code=400, contents='server error'),
            dict(code=200, contents=dict(load_fixture('f5os_backup_filelist.json'))),
            dict(code=401),
            dict(code=401, contents='access denied'),
        ])
        mm.client.get = Mock(side_effect=[dict(code=204), dict(code=500, contents='server crashed')])

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err2:
            mm.export_file()
        self.assertIn('Failed to export backup file', err2.exception.args[0])

        res2 = mm.is_still_uploading()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err3:
            mm.is_still_uploading()
        self.assertIn('server crashed', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove_from_device()
        self.assertIn('access denied', err4.exception.args[0])

        mm.remove_from_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err5:
            mm.remove()
        self.assertIn('Failed to delete the resource.', err5.exception.args[0])
