# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_stp_config
from ansible_collections.f5networks.f5os.plugins.modules.f5os_stp_config import (
    ModuleParameters, ArgumentSpec, ModuleManager
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
    def test_module_parameters(self):
        args = dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name='1.0',
                cost=2,
                port_priority=128,
                edge_port='EDGE_DISABLE',
                link_type='SHARED'
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.hello_time, 2)
        self.assertEqual(p.max_age, 7)
        self.assertEqual(p.forwarding_delay, 16)
        self.assertEqual(p.hold_count, 7)
        self.assertEqual(p.bridge_priority, 28672)
        self.assertEqual(p.interfaces["name"], '1.0')
        self.assertEqual(p.interfaces['cost'], 2)
        self.assertEqual(p.interfaces['port_priority'], 128)
        self.assertEqual(p.interfaces['edge_port'], 'EDGE_DISABLE')
        self.assertEqual(p.interfaces['link_type'], 'SHARED')
        self.assertEqual(p.state, 'present')

    def test_default_module_parameters(self):
        args = dict(
            interfaces=dict(
                name='1.0',
            ),
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.hello_time, 2)
        self.assertEqual(p.max_age, 20)
        self.assertEqual(p.forwarding_delay, 15)
        self.assertEqual(p.hold_count, 6)
        self.assertEqual(p.bridge_priority, 32768)
        self.assertEqual(p.interfaces["name"], '1.0')
        # self.assertEqual(p.interfaces['cost'], 1)
        # self.assertEqual(p.interfaces['port_priority'], 128)
        # self.assertEqual(p.interfaces['edge_port'], 'EDGE_ENABLE')
        # self.assertEqual(p.interfaces['link_type'], 'P2P')
        self.assertEqual(p.state, 'present')

    def test_module_parameters_invalid_hello_time(self):
        args = dict(
            hello_time=11
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.hello_time()

        self.assertIn('Valid hello_time must be in range 0 - 10.', err.exception.args[0])

    def test_module_parameters_invalid_max_age(self):
        args = dict(
            max_age=5
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.max_age()

        self.assertIn('Valid max_age must be in range 6 - 40.', err.exception.args[0])

    def test_module_parameters_invalid_forwarding_delay(self):
        args = dict(
            forwarding_delay=3
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.forwarding_delay()

        self.assertIn('Valid forwarding_delay must be in range 4 - 30.', err.exception.args[0])

    def test_module_parameters_invalid_hold_count(self):
        args = dict(
            hold_count=0
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.hold_count()

        self.assertIn('Valid hold_count must be in range 1 - 10.', err.exception.args[0])

    def test_module_parameters_invalid_bridge_priority(self):
        args = dict(
            bridge_priority=1
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.bridge_priority()

        self.assertIn('Valid bridge_priority must be in range 0-61440 and a multiple of 4096.', err.exception.args[0])

    def test_module_parameters_invalid_interface(self):
        args = dict(
            interfaces=dict(
                name=1.0,
                port_priority=113
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.interfaces()

        self.assertIn('Valid port_priority must be in range 0-240 and a multiple of 16.', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_stp_config.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_stp_config.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_enable_lldp_config(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=128,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        # mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict()),
        ])
        mm.client.patch = Mock(side_effect=[
            dict(code=204, contents=dict()),
        ])
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_stp_config_global.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_stp_config.json'))),
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_enable_lldp_fails(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=128,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=400, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_update_lldp_config(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=144,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_stp_config.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_stp_interfaces.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_stp_interfaces_config.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_stp_config.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_stp_interfaces.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_stp_interfaces_config.json'))),
        ])
        mm.client.patch = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict()),
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_remove_lldp_config(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=129,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        mm.exists = Mock(side_effect=[True])
        mm.client.delete = Mock(side_effect=[
            dict(code=204, contents=dict()),
            dict(code=204, contents=dict())
        ])
        # mm.client.patch = Mock(return_value=dict(code=204, contents=dict()))
        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_create_mstp_config(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            mode='mstp',
            mstp_instances=[
                dict(
                    instance_id=1,
                    bridge_priority=28672,
                    vlans=[444, 555],
                    interface=dict(
                        name=1.0,
                        cost=2,
                        port_priority=129,
                        edge_port='EDGE_DISABLE',
                        link_type='SHARED',
                    )
                )
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=204))
        mm.client.patch = Mock(return_value=dict(code=204))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 3)
        self.assertEqual(mm.client.patch.call_count, 1)

    def test_update_mstp_config(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            mode='mstp',
            mstp_instances=[
                dict(
                    instance_id=1,
                    bridge_priority=28672,
                    vlans=[444, 555],
                    interface=dict(
                        name=2.0,
                        cost=3,
                        port_priority=129,
                        edge_port='EDGE_DISABLE',
                        link_type='P2P',
                    )
                )
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_mstp = dict(load_fixture('f5os_mstp_config.json'))

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=current_mstp))
        mm.client.patch = Mock(return_value=dict(code=204))
        mm.client.put = Mock(return_value=dict(code=204))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 2)
        self.assertEqual(mm.client.put.call_count, 1)

    @patch.object(f5os_stp_config, 'Connection')
    @patch.object(f5os_stp_config.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=129,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='present'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_stp_config.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_stp_config, 'Connection')
    @patch.object(f5os_stp_config.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=129,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='present'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_stp_config.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            hello_time=2,
            max_age=7,
            forwarding_delay=16,
            hold_count=7,
            bridge_priority=28672,
            interfaces=dict(
                name=1.0,
                cost=2,
                port_priority=129,
                edge_port='EDGE_DISABLE',
                link_type='SHARED',
            ),
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[dict(code=200, contents=dict(load_fixture('f5os_stp_config_global.json'))),
                                          dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertFalse(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)
