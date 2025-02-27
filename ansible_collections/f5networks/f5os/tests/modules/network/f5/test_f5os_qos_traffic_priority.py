# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_qos_traffic_priority
from ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_traffic_priority import (
    ArgumentSpec, ModuleManager, ModuleParameters
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
        args = dict(
            qos_status="disable",
            default_qos="802.1p"
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.qos_status, "QoS-disabled")
        self.assertEqual(p.default_qos, "mapping-8021p")


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_traffic_priority.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qos_traffic_priority.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.mock_module_helper.stop()
        self.p1.stop()
        self.p2.stop()

    def test_create_traffic_priority(self):
        set_module_args(dict(
            qos_status="disable",
            name="test_tp",
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404))
        mm.client.post = Mock(return_value=dict(code=200))
        mm.client.put = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_traffic_priority(self):
        set_module_args(dict(
            name="test_tp",
            default_qos="dscp",
            qos_status="dscp"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(
            side_effect=[
                {"code": 200},
                {"code": 200, "contents": {"f5-qos:default-traffic-priority": "dummy_tp"}},
                {"code": 200, "contents": {"f5-qos:default-traffic-priority": "dummy_tp"}},
                {"code": 200, "contents": {"f5-qos:status": "QoS-disabled"}}
            ]
        )
        mm.client.patch = Mock(return_value=dict(code=204))
        mm.client.put = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results["changed"])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 4)

    def test_remove_traffic_priority(self):
        set_module_args(dict(
            name="test_tp",
            state="absent"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results["changed"])
        self.assertEqual(mm.client.delete.call_count, 1)

    def test_delete_traffic_priority(self):
        pass

    @patch.object(f5os_qos_traffic_priority, 'Connection')
    @patch.object(f5os_qos_traffic_priority.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            qos_status="disable",
            name="test_tp",
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_qos_traffic_priority.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_qos_traffic_priority, 'Connection')
    @patch.object(f5os_qos_traffic_priority.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            qos_status="disable",
            name="test_tp",
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_qos_traffic_priority.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="test_tp",
            default_qos="dscp",
            qos_status="dscp"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm._update_changed_options = Mock(return_value=False)
        res2 = mm.should_update()
        self.assertFalse(res2)

        mm.read_current_from_device = Mock()
        mm.should_update = Mock(return_value=False)
        res3 = mm.update()
        self.assertFalse(res3)

        mm.client.get = Mock(return_value=dict(code=503, contents="server error"))
        with self.assertRaises(F5ModuleError) as err2:
            mm.exists()
        self.assertIn("server error", err2.exception.args[0])

        mm.exists = Mock(return_value=False)
        res1 = mm.absent()
        self.assertFalse(res1)

        mm.remove_from_device = Mock()
        mm.exists = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as err1:
            mm.remove()
        self.assertIn("Failed to delete the resource.", err1.exception.args[0])
