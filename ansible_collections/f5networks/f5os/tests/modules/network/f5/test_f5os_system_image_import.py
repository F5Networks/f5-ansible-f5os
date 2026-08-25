# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_import import (
    ArgumentSpec, ModuleManager, ModuleParameters
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json
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


class TestModuleParameters(unittest.TestCase):
    def test_timeout_valid(self):
        args = dict(timeout=300, remote_image_url=None, remote_user=None, remote_password=None,
                    local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        delay, divisor = p.timeout
        self.assertEqual(divisor, 100)
        self.assertEqual(delay, 3.0)

    def test_timeout_too_low(self):
        args = dict(timeout=100, remote_image_url=None, remote_user=None, remote_password=None,
                    local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.timeout
        self.assertIn("Timeout value must be between 150 and 3600 seconds", str(err.exception))

    def test_timeout_too_high(self):
        args = dict(timeout=4000, remote_image_url=None, remote_user=None, remote_password=None,
                    local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.timeout
        self.assertIn("Timeout value must be between 150 and 3600 seconds", str(err.exception))

    def test_image_name_from_url(self):
        args = dict(timeout=300, remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.iso',
                    remote_user=None, remote_password=None, local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        self.assertEqual(p.image_name, 'F5OS-A-1.8.0-14139.iso')

    def test_image_name_none(self):
        args = dict(timeout=300, remote_image_url=None, remote_user=None, remote_password=None,
                    local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        self.assertIsNone(p.image_name)

    def test_remote_image_url_none(self):
        args = dict(timeout=300, remote_image_url=None, remote_user=None, remote_password=None,
                    local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        self.assertIsNone(p.remote_image_url)

    def test_remote_image_url_value(self):
        args = dict(timeout=300, remote_image_url='https://server.com/path/image.iso',
                    remote_user=None, remote_password=None, local_path=None, operation_id=None, state='import')
        p = ModuleParameters(params=args)
        self.assertEqual(p.remote_image_url, 'https://server.com/path/image.iso')


@patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_import.time.sleep', Mock())
class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_import.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_import.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_system_image_exist_import(self):
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso", "date": "string", "size": "string"}]}}
        mm.client.post = Mock(return_value={'code': 201, 'contents': get_data})

        results = mm.exec_module()
        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)

    def test_system_image_import(self):
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14136.R5R10.CANDIDATE.iso", "date": "string", "size": "string"}]}}
        mm.client.post = Mock(return_value={'code': 201, 'contents': get_data})

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 2)

    def test_system_image_import_v_15(self):
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14136.R5R10.CANDIDATE.iso", "date": "string", "size": "string"}]}}
        post_data = {"f5-utils-file-transfer:output": {"result": "File transfer is initiated.(images/staging/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso)"}}
        status_data = {"f5-utils-file-transfer:output": {"result": "/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso|Completed\n"}}
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=get_data),
            dict(code=201, contents=post_data),
            dict(code=204, contents=status_data),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 3)

    def test_system_image_import_v_15_in_progress_then_completed(self):
        """Test pre-1.7 transfer status polling with In Progress then Completed."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other-image.iso", "date": "string", "size": "string"}]}}
        post_data = {"f5-utils-file-transfer:output": {"result": "File transfer is initiated.(images/staging/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso)"}}
        in_progress = {"f5-utils-file-transfer:output": {"result": "In Progress (50%)"}}
        completed = {"f5-utils-file-transfer:output": {"result": "Completed"}}
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=get_data),
            dict(code=201, contents=post_data),
            dict(code=200, contents=in_progress),
            dict(code=200, contents=completed),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_system_image_import_v_15_timeout(self):
        """Test pre-1.7 transfer status polling timeout."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other-image.iso", "date": "string", "size": "string"}]}}
        post_data = {"f5-utils-file-transfer:output": {"result": "File transfer is initiated.(images/staging/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso)"}}
        # Always returns something other than In Progress or Completed (e.g., empty/unknown)
        other_status = {"f5-utils-file-transfer:output": {"result": "Queued"}}
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents=get_data),
            dict(code=201, contents=post_data),
        ] + [dict(code=200, contents=other_status)] * 100)
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_system_image_import_status(self):
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data1 = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345",
                 "operation": "Import", "protocol": "string", "local-file-path": "string",
                 "remote-host": "string", "remote-file-path": "string", "status": "Completed", "timestamp": "string"}]
        }
        get_data2 = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "ready", "date": "2023-12-19", "size": "3.52GB", "type": ""}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 201, 'contents': get_data1},
            {'code': 201, 'contents': get_data2},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 2)

    def test_system_image_import_remove(self):
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data1 = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso", "date": "string", "size": "string"}]}}
        get_data2 = {"f5-system-image:output": {"response": "Success"}}
        # After remove, exists() returns False (no entries match)
        get_data3 = {"f5-utils-file-transfer:output": {"entries": [{"name": "other-image.iso", "date": "string", "size": "string"}]}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': get_data1},
            {'code': 201, 'contents': get_data2},
            {'code': 201, 'contents': get_data3},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_absent_image_not_found(self):
        """Test absent state when image doesn't exist (idempotent)."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other-image.iso", "date": "string", "size": "string"}]}}
        mm.client.post = Mock(return_value={'code': 201, 'contents': get_data})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_exists_404_response(self):
        """Test exists() returns False on 404 response."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value={'code': 404, 'contents': {}})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_exists_error_response(self):
        """Test exists() raises on unexpected response code."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'Internal Server Error'})
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_exists_operation_id_with_import_state_raises(self):
        """Test that operation_id with state=import raises error."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='import',
            operation_id='Import_12345',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("operation_id is provided state must be not import", str(err.exception))

    def test_present_image_valid(self):
        """Test present state when image exists and is valid (idempotent)."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso", "date": "string", "size": "string"}]}}
        mm.client.post = Mock(return_value={'code': 201, 'contents': get_data})
        results = mm.exec_module()
        # exists() sets image_is_valid=True, present() returns False
        self.assertFalse(results['changed'])

    def test_create_on_device_error_response(self):
        """Test create_on_device raises on bad response code."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other.iso", "date": "s", "size": "s"}]}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 500, 'contents': 'server error'},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to import system image", str(err.exception))

    def test_create_on_device_local_file_already_exists(self):
        """Test create_on_device raises when local file already exists."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other.iso", "date": "s", "size": "s"}]}}
        import_data = {
            "f5-utils-file-transfer:output": {
                "result": "Aborted: local-file already exists at "
                          "images/staging/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso"
            }
        }
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': import_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("local-file already exists", str(err.exception))

    def test_create_on_device_file_import_in_progress(self):
        """Test create_on_device raises when same file import is in progress."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other.iso", "date": "s", "size": "s"}]}}
        import_data = {"f5-utils-file-transfer:output": {"result": "File import with same local file name is in progress"}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': import_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("File import with same local file name is in progress", str(err.exception))

    def test_create_on_device_with_operation_id(self):
        """Test create_on_device returns operation-id in response."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "other.iso", "date": "s", "size": "s"}]}}
        import_data = {"f5-utils-file-transfer:output": {"result": "File transfer is initiated.", "operation-id": "Import_99999"}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': import_data},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_import_status_complete_still_uploading(self):
        """Test import_status_complete when upload is still in progress then completes."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # First call: still uploading (In Progress)
        uploading_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "In Progress (50%)"}
            ]
        }
        # Second call: upload completed
        completed_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        # Third call: is_imported check
        image_data = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "ready", "date": "2023-12-19", "size": "3.52GB", "type": ""}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': uploading_data},
            {'code': 200, 'contents': completed_data},
            {'code': 200, 'contents': image_data},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_import_status_complete_timeout(self):
        """Test import_status_complete raises timeout."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # Always in progress
        uploading_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "In Progress (50%)"}
            ]
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': uploading_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_import_status_not_imported_yet_then_ready(self):
        """Test import_status_complete when upload done but image not imported yet."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # Upload completed (204 = no transfer ops)
        # is_imported first returns verifying, then ready
        verifying_data = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "verifying", "date": "2023-12-19", "size": "3.52GB", "type": ""}
        ]}
        ready_data = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "ready", "date": "2023-12-19", "size": "3.52GB", "type": ""}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 204, 'contents': {}},  # is_still_uploading returns False
            {'code': 200, 'contents': verifying_data},  # is_imported returns False (verifying)
            {'code': 204, 'contents': {}},  # is_still_uploading returns False
            {'code': 200, 'contents': ready_data},  # is_imported returns True
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_is_still_uploading_error_response(self):
        """Test is_still_uploading raises on error response."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'server error'})
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_is_still_uploading_no_operation_id_in_item(self):
        """Test is_still_uploading skips items without operation-id."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # Item without operation-id, so loop ends without finding our op -> raises error
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"status": "Completed", "local-file-path": "something"}
            ]
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': transfer_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("File upload job not has not started", str(err.exception))

    def test_is_still_uploading_file_transfer_initiated(self):
        """Test is_still_uploading returns True for 'File Transfer Initiated' status."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # Always returns File Transfer Initiated -> always uploading -> timeout
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "File Transfer Initiated"}
            ]
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': transfer_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_is_still_uploading_failed_status(self):
        """Test is_still_uploading raises on failed upload status."""
        set_module_args(dict(
            remote_image_url='https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "File Not Found, HTTP Error 404"}
            ]
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': transfer_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("File upload failed", str(err.exception))

    def test_is_imported_controller_image_ready(self):
        """Test is_imported for CONTROLLER image."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.CONTROLLER.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        # is_still_uploading: completed
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        # is_imported: controller ready
        controller_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-controller": "1.8.0-14139", "status": "ready"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': controller_data},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_is_imported_controller_image_verifying(self):
        """Test is_imported for CONTROLLER image in verifying state."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.CONTROLLER.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        controller_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-controller": "1.8.0-14139", "status": "verifying"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': controller_data},
        ] * 100)
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_is_imported_controller_verification_failed(self):
        """Test is_imported for CONTROLLER image verification failure."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.CONTROLLER.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        controller_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-controller": "1.8.0-14139", "status": "verification-failed"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': controller_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("failed signature verification", str(err.exception))

    def test_is_imported_partition_image_ready(self):
        """Test is_imported for PARTITION image."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.PARTITION.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        partition_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-partition": "1.8.0-14139", "status": "ready"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': partition_data},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_is_imported_partition_verifying(self):
        """Test is_imported for PARTITION image in verifying state."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.PARTITION.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        partition_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-partition": "1.8.0-14139", "status": "verifying"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': partition_data},
        ] * 100)
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_is_imported_partition_verification_failed(self):
        """Test is_imported for PARTITION image verification failure."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.PARTITION.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        partition_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-partition": "1.8.0-14139", "status": "verification-failed"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': partition_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("failed signature verification", str(err.exception))

    def test_is_imported_rseries_verification_failed(self):
        """Test is_imported for rSeries image verification failure."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        image_data = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "verification-failed", "date": "", "size": "", "type": ""}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': image_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("failed signature verification", str(err.exception))

    def test_is_imported_error_response(self):
        """Test is_imported raises on error response."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 500, 'contents': 'error'},
        ])
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_remove_controller_image(self):
        """Test remove_from_device for CONTROLLER image."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.CONTROLLER.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-C-1.8.0-14139.CONTROLLER.iso", "date": "s", "size": "s"}]}}
        remove_data = {"f5-system-image:output": {"response": "Success"}}
        not_exists = {"f5-utils-file-transfer:output": {"entries": [{"name": "other.iso", "date": "s", "size": "s"}]}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': remove_data},
            {'code': 201, 'contents': not_exists},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_remove_partition_image(self):
        """Test remove_from_device for PARTITION image."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.PARTITION.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-C-1.8.0-14139.PARTITION.iso", "date": "s", "size": "s"}]}}
        remove_data = {"f5-system-image:output": {"response": "Success"}}
        not_exists = {"f5-utils-file-transfer:output": {"entries": [{"name": "other.iso", "date": "s", "size": "s"}]}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': remove_data},
            {'code': 201, 'contents': not_exists},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_remove_from_device_post_error(self):
        """Test remove_from_device raises on post error."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14139.R5R10.iso", "date": "s", "size": "s"}]}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 500, 'contents': 'error removing image'},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to remove system", str(err.exception))

    def test_remove_from_device_not_success(self):
        """Test remove_from_device raises when response is not Success."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14139.R5R10.iso", "date": "s", "size": "s"}]}}
        remove_data = {"f5-system-image:output": {"response": "Failed: image is in use"}}
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': remove_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to remove system image", str(err.exception))

    def test_remove_exists_after_delete_raises(self):
        """Test remove() raises when image still exists after deletion."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            state="absent",
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        exists_data = {"f5-utils-file-transfer:output": {"entries": [{"name": "F5OS-A-1.8.0-14139.R5R10.iso", "date": "s", "size": "s"}]}}
        remove_data = {"f5-system-image:output": {"response": "Success"}}
        # After remove, exists() still finds the image
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': exists_data},
            {'code': 200, 'contents': remove_data},
            {'code': 201, 'contents': exists_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to delete the resource", str(err.exception))

    def test_is_imported_rseries_verifying_then_ready(self):
        """Test is_imported for rSeries verifying then ready."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        verifying_data = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "verifying", "date": "", "size": "", "type": ""}
        ]}
        ready_data = {"f5-system-image:iso": [
            {"version-iso": "1.8.0-14139", "status": "ready", "date": "", "size": "", "type": ""}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': verifying_data},
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': ready_data},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_controller_image_not_found_returns_false(self):
        """Test is_imported for CONTROLLER when image version not found in list."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.CONTROLLER.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        # Image version not in list
        controller_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-controller": "1.7.0-99999", "status": "ready"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': controller_data},
        ] * 100)
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_partition_image_not_found_returns_false(self):
        """Test is_imported for PARTITION when image version not found in list."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-C-1.8.0-14139.PARTITION.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        partition_data = {"f5-system-image:controller": [
            {"iso": {"iso": [{"version-iso-partition": "1.7.0-99999", "status": "ready"}]}}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': partition_data},
        ] * 100)
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_is_imported_rseries_version_not_in_list(self):
        """Test is_imported for rSeries when image version not found in iso list."""
        set_module_args(dict(
            remote_image_url='https://server.com/path/F5OS-A-1.8.0-14139.R5R10.iso',
            local_path="images/staging",
            state='present',
            operation_id='Import_12345',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        transfer_data = {
            "f5-utils-file-transfer:transfer-operation": [
                {"operation-id": "Import_12345", "status": "Completed"}
            ]
        }
        # Image list doesn't contain our version
        image_data = {"f5-system-image:iso": [
            {"version-iso": "1.7.0-99999", "status": "ready", "date": "", "size": "", "type": ""}
        ]}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': transfer_data},
            {'code': 200, 'contents': image_data},
        ] * 100)
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))
