# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

# from ansible_collections.f5networks.f5os.plugins.modules import f5os_system_image_import
from ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_import import (
    ArgumentSpec, ModuleManager
)

# from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json
    # AnsibleFailJson, AnsibleExitJson
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

    def test_system_image_exist_import(self, *args):
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

    def test_system_image_import(self, *args):
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
        # self.assertEqual(mm.client.get.call_count, 1)

    def test_system_image_import_status(self, *args):
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
            {
                "version-iso": "1.8.0-14139",
                "status": "ready",
                "date": "2023-12-19",
                "size": "3.52GB",
                "type": ""
            },
            {
                "version-iso": "1.5.1-12283",
                "status": "ready",
                "date": "2023-08-14",
                "size": "4.61GB",
                "type": ""
            },
            {
                "version-iso": "1.5.0-5781",
                "status": "ready",
                "date": "2023-04-30",
                "size": "3.32GB",
                "type": ""
            }]
        }
        mm.client.get = Mock(side_effect=[
            {'code': 201, 'contents': get_data1},
            {'code': 201, 'contents': get_data2},
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 2)

    def test_system_image_import_remove(self, *args):
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
        mm.client.post = Mock(side_effect=[
            {'code': 201, 'contents': get_data1},
            {'code': 201, 'contents': get_data2}])
        for _var in range(2):  # Attempt to call it three times
            try:
                results = mm.exec_module()
                self.assertTrue(results['changed'])
                self.assertEqual(mm.client.post.call_count, 2)
            except StopIteration:
                pass
