# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_config_restore
from ansible_collections.f5networks.f5os.plugins.modules.f5os_config_restore import (
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


def clear_fixture_cache():
    fixture_data.clear()


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
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            state='present',
            timeout=600
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'my-backup')
        self.assertEqual(p.remote_host, '10.1.1.100')
        self.assertEqual(p.remote_user, 'admin')
        self.assertEqual(p.remote_password, 'secret')
        self.assertEqual(p.remote_path, '/backups/my-backup')
        self.assertEqual(p.local_path, 'configs/my-backup')
        self.assertEqual(p.protocol, 'scp')
        self.assertEqual(p.state, 'present')
        self.assertTupleEqual(p.timeout, (6.0, 100))

    def test_module_parameters_local_only(self):
        args = dict(
            name='my-backup',
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'my-backup')
        self.assertEqual(p.local_path, 'configs/my-backup')
        self.assertIsNone(p.remote_host)

    def test_module_parameters_hostname(self):
        args = dict(
            name='my-backup',
            remote_host='backup.example.com',
            remote_path='/backups/my-backup',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.remote_host, 'backup.example.com')

    def test_module_parameter_name_path_traversal(self):
        args = dict(
            name='../etc/passwd',
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.name

        self.assertIn('must not be empty or contain', err.exception.args[0])

    def test_module_parameter_name_slash(self):
        args = dict(
            name='foo/bar',
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.name

        self.assertIn('must not be empty or contain', err.exception.args[0])

    def test_module_parameter_name_empty(self):
        args = dict(
            name='',
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.name

        self.assertIn('must not be empty', err.exception.args[0])

    def test_module_parameter_name_whitespace_only(self):
        args = dict(
            name='   ',
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.name

        self.assertIn('must not be empty', err.exception.args[0])

    def test_module_parameter_name_stripped(self):
        args = dict(
            name='  my-backup  ',
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'my-backup')

    def test_local_path_validates_name(self):
        args = dict(
            name='../etc/passwd',
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.local_path

        self.assertIn('must not', err.exception.args[0])

    def test_module_parameter_timeout_failure(self):
        args = dict(
            timeout=100
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.timeout

        self.assertIn('Timeout value must be between 150 and 3600 seconds.', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        clear_fixture_cache()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.f5os_config_restore.F5Client'
        )
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p3 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.f5os_config_restore.send_teem'
        )
        self.m3 = self.p3.start()
        self.m3.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_restore_local_backup(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.backup_exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_restore_success.json'))
        ))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('Config restore from my-backup successful', results['message'])

    def test_restore_import_and_restore(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_progress.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_complete.json'))),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('Config restore from my-backup successful', results['message'])

    def test_restore_local_file_not_found_no_remote(self, *args):
        set_module_args(dict(
            name='missing-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value=dict(code=204, contents=dict()))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('does not exist on the device', err.exception.args[0])

    def test_restore_config_fails(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.backup_exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=400, contents='restore failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to restore config from backup', err.exception.args[0])

    def test_restore_import_fails(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=400, contents='import failed'),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to import backup file', err.exception.args[0])

    def test_restore_import_transfer_fails(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
        ])
        mm.client.get = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_restore_import_failure.json'))
        ))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('File import failed with the following result', err.exception.args[0])

    @patch.object(ModuleParameters, 'timeout', new_callable=PropertyMock)
    def test_restore_import_timeout(self, mock_timeout):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))
        mock_timeout.return_value = (1, 2)

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.backup_exists = Mock(return_value=False)
        mm.import_file = Mock(return_value=True)
        mm._is_still_importing = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Module timeout reached', err.exception.args[0])

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('VELOS controller', err.exception.args[0])

    def test_velos_partition_allowed(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'
        mm.backup_exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_restore_success.json'))
        ))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_check_mode(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
            _ansible_check_mode=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock()

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(mm.client.post.called)

    def test_check_mode_invalid_name(self, *args):
        set_module_args(dict(
            name='../etc/passwd',
            state='present',
            _ansible_check_mode=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('must not', err.exception.args[0])

    def test_restore_verifies_payload(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        expected_uri = '/openconfig-system:system/f5-database:database/f5-database:config-restore'
        expected_payload = {'f5-database:name': 'my-backup'}

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.backup_exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_restore_success.json'))
        ))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.post.assert_called_once()
        self.assertEqual(mm.client.post.call_args[0][0], expected_uri)
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected_payload)

    def test_required_by_remote_host(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            module = AnsibleModule(
                argument_spec=self.spec.argument_spec,
                supports_check_mode=self.spec.supports_check_mode,
                required_by=self.spec.required_by,
            )

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('remote_host', result.exception.args[0]['msg'])

    def test_backup_exists_found_in_list(self, *args):
        set_module_args(dict(
            name='foo_conf',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_backup_filelist.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('Config restore from foo_conf successful', results['message'])

    def test_backup_exists_not_in_list(self, *args):
        set_module_args(dict(
            name='nonexistent-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_backup_filelist.json'))
        ))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('does not exist on the device', err.exception.args[0])

    def test_backup_exists_error(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_import_job_not_yet_visible(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        # Fixture with a different operation-id so our job is not found
        not_our_job = {
            "f5-utils-file-transfer:transfer-operation": [
                {
                    "local-file-path": "configs/other-file",
                    "operation": "Import file",
                    "operation-id": "IMPORT-OTHER",
                    "status": "         Completed",
                    "timestamp": "Mon Jan 15 10:00:00 2024"
                }
            ]
        }

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])
        # First poll: job not visible, second poll: completed
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=not_our_job),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_complete.json'))),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_import_unknown_error_status(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        # Status that doesn't match any known error prefix — should be treated as still importing
        # until timeout
        unknown_status = {
            "f5-utils-file-transfer:transfer-operation": [
                {
                    "local-file-path": "configs/my-backup",
                    "operation": "Import file",
                    "operation-id": "IMPORT-abc12345",
                    "status": "Connecting to server",
                    "timestamp": "Mon Jan 15 10:00:00 2024"
                }
            ]
        }

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.backup_exists = Mock(return_value=False)
        mm.import_file = Mock(return_value=True)
        mm.operation_id = 'IMPORT-abc12345'
        mm.client.get = Mock(return_value=dict(code=200, contents=unknown_status))

        # Unknown status treated as still importing (not a known error prefix)
        result = mm._is_still_importing()
        self.assertTrue(result)

    def test_is_still_importing_status_check_error(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
        ])
        # 3 consecutive 500s to exceed transient error threshold
        mm.client.get = Mock(return_value=dict(code=500, contents='server crashed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server crashed', err.exception.args[0])

    def test_is_still_importing_interleaved_transient_errors(self, *args):
        """Verify that transient error counter resets on success,
        so non-consecutive 5xx errors don't accumulate to the threshold."""
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])
        # Interleave: success -> 500 -> success -> 500 -> success -> 500 -> completed
        # Without counter reset, 3 total 500s would trigger the threshold
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_progress.json'))),
            dict(code=500, contents='transient 1'),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_progress.json'))),
            dict(code=500, contents='transient 2'),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_progress.json'))),
            dict(code=500, contents='transient 3'),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_complete.json'))),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_is_still_importing_transient_error_recovers(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])
        # One transient 500 then recovery
        mm.client.get = Mock(side_effect=[
            dict(code=500, contents='transient error'),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_complete.json'))),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_is_still_importing_no_active_transfers(self, *args):
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # 204 on status check now means still importing, so second call returns completed
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])
        mm.client.get = Mock(side_effect=[
            dict(code=204),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_complete.json'))),
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_import_payload_includes_credentials(self, *args):
        """Verify the import payload includes username and password.
        This is the regression test for the credential omission bug."""
        set_module_args(dict(
            name='my-backup',
            remote_host='10.1.1.100',
            remote_user='admin',
            remote_password='secret',
            remote_path='/backups/my-backup',
            protocol='scp',
            timeout=300,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=200, contents=dict(load_fixture('f5os_restore_import_start.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_restore_success.json'))),
        ])
        mm.client.get = Mock(return_value=dict(
            code=200, contents=dict(load_fixture('f5os_restore_import_complete.json'))
        ))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # The import call is the second post call (first is backup_exists)
        import_call = mm.client.post.call_args_list[1]
        import_payload = import_call[1]['data']
        self.assertEqual(import_payload['input'][0]['username'], 'admin')
        self.assertEqual(import_payload['input'][0]['password'], 'secret')
        # Verify credentials are NOT in the return values
        self.assertNotIn('remote_user', results)
        self.assertNotIn('remote_password', results)

    @patch.object(f5os_config_restore, 'Connection')
    @patch.object(f5os_config_restore.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_config_restore.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_config_restore, 'Connection')
    @patch.object(f5os_config_restore.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='my-backup',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_config_restore.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
