# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_qos_mapping
from ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_mapping import (
    ModuleParameters, ArgumentSpec, ModuleManager
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
        args = {
            'mapping_type': '802.1p',
            'traffic_priority': 'dummy',
            'mapping_values': ['1-6', '99'],
        }

        m = ModuleParameters(params=args)

        self.assertEqual(m.mapping_type, 'mapping-8021p')
        self.assertEqual(m.traffic_priority, 'dummy')

        with self.assertRaises(F5ModuleError) as res:
            m.mapping_values

        self.assertIn(
            'for the mapping type 802.1p, the mapping values must be between 0 and 7',
            str(res.exception)
        )

        args = {
            'mapping_type': '802.1p',
            'traffic_priority': 'dummy',
            'mapping_values': ['xyz'],
        }

        m = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as res:
            m.mapping_values

        self.assertIn(
            'Invalid mapping value: xyz',
            str(res.exception)
        )


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_mapping.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_mapping.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.mock_module_helper.stop()
        self.p1.stop()
        self.p2.stop()

    def test_create(self, *args):
        set_module_args(dict(
            mapping_type="dscp",
            traffic_priority="test_tp",
            mapping_values=["34-37", "39"]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 200})

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update(self, *args):
        set_module_args(dict(
            mapping_type="dscp",
            traffic_priority="test_tp",
            mapping_values=["34-40", "41"]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        existing_mapping = {
            "f5-qos:traffic-priority": [
                {
                    "name": "test_tp",
                    "value": [27, 28, 29]
                }
            ]
        }

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': existing_mapping})
        mm.client.put = Mock(return_value={'code': 200})

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_delete(self, *args):
        set_module_args(dict(
            mapping_type="dscp",
            traffic_priority="test_tp",
            state="absent",
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods in the specific type of manager
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value={'code': 200})

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)

    @patch.object(f5os_qos_mapping, 'Connection')
    @patch.object(f5os_qos_mapping.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            mapping_type="dscp",
            traffic_priority="test_tp",
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_qos_mapping.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_qos_mapping, 'Connection')
    @patch.object(f5os_qos_mapping.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            mapping_type="dscp",
            traffic_priority="test_tp",
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_qos_mapping.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            mapping_type="dscp",
            traffic_priority="test_tp",
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err1:
            mm.create_on_device()
        self.assertIn("The parameter 'mapping_values' is required", err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.update_on_device()
        self.assertIn("The parameter 'mapping_values' is required", err2.exception.args[0])

        mm.client.delete = Mock(return_value={'code': 503, 'contents': 'server not available'})

        with self.assertRaises(F5ModuleError) as err3:
            mm.remove_from_device()
        self.assertIn("server not available", err3.exception.args[0])

        mm.client.get = Mock(return_value={'code': 503, 'contents': 'server not available'})

        with self.assertRaises(F5ModuleError) as err4:
            mm.exists()
        self.assertIn("server not available", err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.read_current_from_device()
        self.assertIn("server not available", err5.exception.args[0])

        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock()

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove()
        self.assertIn("Failed to delete the resource.", err6.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        res1 = mm.should_update()
        self.assertFalse(res1)

        mm.read_current_from_device = Mock()
        res2 = mm.update()
        self.assertFalse(res2)

        mm.exists = Mock(return_value=False)
        res3 = mm.absent()
        self.assertFalse(res3)
