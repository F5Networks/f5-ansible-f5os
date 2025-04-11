# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_qos_meter_group
from ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_meter_group import (
    ApiParameters, ModuleParameters, ArgumentSpec, ModuleManager
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


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(name="test_meter")
        p = ModuleParameters(params=args)
        self.assertIsNone(p.interfaces)
        self.assertIsNone(p.meters)

    def test_api_parameters(self):
        args = dict(name="test_meter")
        p = ApiParameters(params=args)
        self.assertIsNone(p.interfaces)
        self.assertIsNone(p.meters)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_meter_group.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_meter_group.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.mock_module_helper.stop()
        self.p1.stop()
        self.p2.stop()

    def test_create_meter_group(self, *args):
        set_module_args(dict(
            name="test_tp",
            meters=[
                dict(name="dummy_meter1", weight=2),
                dict(name="dummy_meter2", weight=3),
            ],
            interfaces=["1.0", "2.0"],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 200, 'contents': 'OK'})
        mm.client.patch = Mock(return_value={'code': 200, 'contents': 'OK'})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.get.call_count, 1)
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.patch.call_count, 1)

    def test_update_meter_group(self, *args):
        set_module_args(dict(
            name="test_meter",
            meters=[
                dict(name="dummy_meter1", weight=2),
                dict(name="dummy_meter2", weight=3),
            ],
            interfaces=["1.0", "2.0"],
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        existing_meter = load_fixture('f5os_qos_meter_group.json')
        qos_interfaces = load_fixture('f5os_qos_interfaces.json')
        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            {'code': 200},
            {'code': 200, 'contents': existing_meter},
            {'code': 200, 'contents': qos_interfaces}
        ])

        mm.client.put = Mock(return_value={'code': 200})
        mm.client.delete = Mock(return_value={'code': 200})
        mm.client.patch = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.get.call_count, 3)
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.delete.call_count, 1)
        self.assertEqual(mm.client.patch.call_count, 1)

    def test_delete_meter_group(self, *args):
        set_module_args(dict(
            name="test_meter",
            state="absent",
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        qos_interfaces = load_fixture('f5os_qos_interfaces.json')
        mm = ModuleManager(module=module)

        mm.exists = Mock(side_effect=[True, False])
        mm.client.get = Mock(return_value={'code': 200, 'contents': qos_interfaces})
        mm.client.delete = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.get.call_count, 1)
        self.assertEqual(mm.client.delete.call_count, 3)

    @patch.object(f5os_qos_meter_group, 'Connection')
    @patch.object(f5os_qos_meter_group.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name="test_tp",
            meters=[
                dict(name="dummy_meter1", weight=2),
                dict(name="dummy_meter2", weight=3),
            ],
            interfaces=["1.0", "2.0"],
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_qos_meter_group.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_qos_meter_group, 'Connection')
    @patch.object(f5os_qos_meter_group.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name="test_tp",
            meters=[
                dict(name="dummy_meter1", weight=2),
                dict(name="dummy_meter2", weight=3),
            ],
            interfaces=["1.0", "2.0"],
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_qos_meter_group.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
