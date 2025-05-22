# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_device_info
from ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info import (
    Parameters, ArgumentSpec, ModuleManager, InterfacesParameters, PartitionSoftwareInfoParameters
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


class TestBaseParameters(unittest.TestCase):
    def test_gather_subset(self):
        args = dict(
            gather_subset=['system-info'],
        )
        p = Parameters(params=args)
        assert p.gather_subset == ['system-info']

    def test_gather_subset_cast_to_list(self):
        args = dict(
            gather_subset='system-info',
        )
        p = Parameters(params=args)
        assert p.gather_subset == ['system-info']

    def test_gather_subset_raises(self):
        args = dict(
            gather_subset=tuple('system-info'),
        )
        p = Parameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.gather_subset()

        self.assertIn('must be a list', err.exception.args[0])


class TestMainManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_module_manager_execution(self):
        set_module_args(dict(
            gather_subset=['system-info', 'all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=dict(fake_output='some data'))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(results, {'fake_output': 'some data', 'queried': True})

    def test_module_manager_no_query(self):
        set_module_args(dict(
            gather_subset=['!system-info', 'vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=dict())

        results = mm.exec_module()

        self.assertFalse(results['queried'])

    def test_module_manager_no_specific_module_manager(self):
        set_module_args(dict(
            gather_subset=['!all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=None)

        self.assertFalse(mm.get_manager('foobar'))

        results = mm.exec_module()

        self.assertFalse(results['queried'])

    def test_module_manager_invalid_subset_options(self):
        set_module_args(dict(
            gather_subset=['!all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=None)

        results = mm.exec_module()

        self.assertFalse(results['queried'])

    def test_execute_managers(self):
        set_module_args(dict(
            gather_subset=['all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        fake_manager = Mock(return_value=Mock())
        fake_manager.exec_module.return_value = dict(response='none')
        managers = list()
        managers.append(fake_manager)
        results = mm.execute_managers(managers)

        self.assertDictEqual(results, {'response': 'none'})

    @patch.object(f5os_device_info, 'Connection')
    @patch.object(f5os_device_info.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_device_info.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_device_info, 'Connection')
    @patch.object(f5os_device_info.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_device_info.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])


class TestVlansModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_vlans_facts(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('vlans')
        vm.client.platform = 'rSeries Platform'
        vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_vlans.json')))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(results['vlans'][0], {'name': 'Internal-VLAN', 'vlan_id': 444})
        self.assertDictEqual(results['vlans'][-1], {'name': 'External-VLAN', 'vlan_id': 555})

    def test_get_vlans_facts_velos_controller(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('vlans')
        vm.client.platform = 'Velos Controller'

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['vlans'])

    def test_get_vlans_facts_read_empty(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('vlans')
        vm.client.platform = 'rSeries Platform'
        vm.client.get = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['vlans'])

    def test_get_vlans_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['vlans']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('vlans')
        vm.client.platform = 'rSeries Platform'
        vm.client.get = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])


# class TestControllerImagesModuleManager(unittest.TestCase):
#     def setUp(self):
#         self.spec = ArgumentSpec()
#         self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
#         self.m1 = self.p1.start()
#         self.m1.return_value = Mock()
#         self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
#         self.m2 = self.p2.start()
#         self.m2.return_value = True

#     def tearDown(self):
#         self.p1.stop()
#         self.p2.stop()

#     def test_get_controller_images_facts(self, *args):
#         set_module_args(dict(
#             gather_subset=['controller-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('controller-images')
#         vm.client.platform = 'Velos Controller'
#         vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_controller_images.json')))

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertDictEqual(
#             results['velos_controller_images'][0],
#             {'version': '1.2.1-10781', 'service': '1.2.1-10781', 'os': '1.2.1-10781'})
#         self.assertDictEqual(
#             results['velos_controller_images'][-1],
#             {'version': '1.5.1-10014', 'service': '1.5.1-10014', 'os': '1.5.1-10014'})

#     def test_get_controller_images_facts_read_empty(self, *args):
#         set_module_args(dict(
#             gather_subset=['controller-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('controller-images')
#         vm.client.platform = 'Velos Controller'
#         vm.client.get = Mock(return_value=dict(code=204))

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertFalse(results['velos_controller_images'])

#     def test_get_controller_images_facts_invalid_platform(self, *args):
#         set_module_args(dict(
#             gather_subset=['controller-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('controller-images')
#         vm.client.platform = 'rSeries Platform'

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertFalse(results['velos_controller_images'])

#     def test_get_controller_images_facts_raises(self, *args):
#         set_module_args(dict(
#             gather_subset=['controller-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('controller-images')
#         vm.client.platform = 'Velos Controller'
#         vm.client.get = Mock(return_value=dict(code=500, contents='server error'))

#         with self.assertRaises(F5ModuleError) as err:
#             mm.exec_module()

#         self.assertIn('server error', err.exception.args[0])


# class TestPartitionImagesModuleManager(unittest.TestCase):
#     def setUp(self):
#         self.spec = ArgumentSpec()
#         self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
#         self.m1 = self.p1.start()
#         self.m1.return_value = Mock()
#         self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
#         self.m2 = self.p2.start()
#         self.m2.return_value = True

#     def tearDown(self):
#         self.p1.stop()
#         self.p2.stop()

#     def test_get_partition_images_facts(self, *args):
#         set_module_args(dict(
#             gather_subset=['partition-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('partition-images')
#         vm.client.platform = 'Velos Controller'
#         vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_partition_images.json')))

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertDictEqual(
#             results['velos_partition_images'][0],
#             {'version': '1.3.1-5968', 'service': '1.3.1-5968', 'os': '1.3.1-5968'})
#         self.assertDictEqual(
#             results['velos_partition_images'][-1],
#             {'version': '1.5.1-10014', 'service': '1.5.1-10014', 'os': '1.5.1-10014'})

#     def test_get_partition_images_facts_read_empty(self, *args):
#         set_module_args(dict(
#             gather_subset=['partition-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('partition-images')
#         vm.client.platform = 'Velos Controller'
#         vm.client.get = Mock(return_value=dict(code=204))

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertFalse(results['velos_partition_images'])

#     def test_get_partition_images_facts_invalid_platform(self, *args):
#         set_module_args(dict(
#             gather_subset=['partition-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('partition-images')
#         vm.client.platform = 'rSeries Platform'

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertFalse(results['velos_partition_images'])

#     def test_get_partition_images_facts_raises(self, *args):
#         set_module_args(dict(
#             gather_subset=['partition-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('partition-images')
#         vm.client.platform = 'Velos Controller'
#         vm.client.get = Mock(return_value=dict(code=500, contents='server error'))

#         with self.assertRaises(F5ModuleError) as err:
#             mm.exec_module()

#         self.assertIn('server error', err.exception.args[0])


# class TestTenantImagesModuleManager(unittest.TestCase):
#     def setUp(self):
#         self.spec = ArgumentSpec()
#         self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
#         self.m1 = self.p1.start()
#         self.m1.return_value = Mock()
#         self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
#         self.m2 = self.p2.start()
#         self.m2.return_value = True

#     def tearDown(self):
#         self.p1.stop()
#         self.p2.stop()

#     def test_get_tenant_images_facts(self, *args):
#         set_module_args(dict(
#             gather_subset=['tenant-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('tenant-images')
#         vm.client.platform = 'rSeries Platform'
#         vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_tenant_images.json')))

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertDictEqual(
#             results['tenant_images'][0],
#             {'name': 'BIGIP-15.1.5-0.0.10.ALL-F5OS.qcow2.zip.bundle', 'in_use': 'yes', 'status': 'verified'})
#         self.assertDictEqual(
#             results['tenant_images'][-1],
#             {'name': 'BIGIP-15.1.6.1-0.0.10.ALL-F5OS.qcow2.zip.bundle', 'in_use': 'no', 'status': 'verified'})

#     def test_get_tenant_images_facts_read_empty(self, *args):
#         set_module_args(dict(
#             gather_subset=['tenant-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('tenant-images')
#         vm.client.platform = 'rSeries Platform'
#         vm.client.get = Mock(return_value=dict(code=204))

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertFalse(results['tenant_images'])

#     def test_get_tenant_images_facts_invalid_platform(self, *args):
#         set_module_args(dict(
#             gather_subset=['tenant-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('tenant-images')
#         vm.client.platform = 'Velos Controller'

#         results = mm.exec_module()

#         self.assertTrue(results['queried'])
#         self.assertFalse(results['tenant_images'])

#     def test_get_tenant_images_facts_raises(self, *args):
#         set_module_args(dict(
#             gather_subset=['tenant-images']
#         ))

#         module = AnsibleModule(
#             argument_spec=self.spec.argument_spec,
#             supports_check_mode=self.spec.supports_check_mode
#         )

#         # Override methods to force specific logic in the module to happen
#         mm = ModuleManager(module=module)
#         vm = mm.get_manager('tenant-images')
#         vm.client.platform = 'rSeries Platform'
#         vm.client.get = Mock(return_value=dict(code=500, contents='server error'))

#         with self.assertRaises(F5ModuleError) as err:
#             mm.exec_module()

#         self.assertIn('server error', err.exception.args[0])


class TestInterfacesModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_rseries_interfaces_facts(self):
        set_module_args(dict(
            gather_subset=['interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('interfaces')
        vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_interfaces.json')))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['interfaces']) == 22)
        self.assertEqual(results['interfaces'][-1]['name'], 'mgmt')

    def test_get_controller_interfaces_facts(self):
        set_module_args(dict(
            gather_subset=['interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('interfaces')
        vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_controller_interfaces.json')))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['interfaces']) == 54)
        self.assertEqual(results['interfaces'][0]['name'], '1/1.1')
        self.assertEqual(results['interfaces'][-1]['name'], 'cplagg_1.8')

    def test_get_interfaces_facts_raises(self):
        set_module_args(dict(
            gather_subset=['interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('interfaces')
        vm.client.get = Mock(return_value=dict(code=401, contents='unauthorized access'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('unauthorized access', err.exception.args[0])

    def test_filter_counters(self):
        mock_interfaces = InterfacesParameters(dict())
        self.assertIsNone(mock_interfaces._filter_counters(None, None))


class TestLagInterfacesModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_rseries_lag_facts(self):
        set_module_args(dict(
            gather_subset=['lag-interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('lag-interfaces')
        vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_f5os_interfaces_multiple_lags.json')))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['lag_interfaces']) == 4)
        self.assertEqual(results['lag_interfaces'][-1]['name'], 'test_lag_static_gui')

    def test_get_controller_lag_facts(self):
        set_module_args(dict(
            gather_subset=['lag-interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('lag-interfaces')
        vm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_velos_controller_interfaces.json')))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertTrue(len(results['lag_interfaces']) == 8)
        self.assertEqual(results['lag_interfaces'][0]['name'], 'cplagg_1.1')
        self.assertEqual(results['lag_interfaces'][-1]['name'], 'cplagg_1.8')

    def test_get_interfaces_facts_raises(self):
        set_module_args(dict(
            gather_subset=['lag-interfaces']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('lag-interfaces')
        vm.client.get = Mock(return_value=dict(code=401, contents='unauthorized access'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('unauthorized access', err.exception.args[0])


class TestSystemInfoModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_device_info.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_system_info_facts_rseries(self):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('system-info')
        vm.client.platform = 'rSeries Platform'
        vm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_rseries_components_info.json')),
            dict(code=200, contents=load_fixture('load_rseries_software_info.json')),
            dict(code=200, contents=load_fixture('load_f5os_license_info.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(
            results['system_info']['running_software'],
            {'os_version': '1.2.0-10139', 'service_version': '1.2.0-10139', 'software_installation_status': 'success'}
        )
        self.assertDictEqual(
            results['system_info']['components'][0],
            {'name': 'platform', 'serial_no': 'f5-jxie-yxfl', 'part_no': '200-0413-02 REV 2', 'description': 'r10800',
             'memory_usage': {'total': 17249722368, 'free': 14523379712, 'used_percent': 94},
             'system_temperature': {'current': 28.7, 'average': 28.8, 'minimum': 28.7, 'maximum': 29.0}}
        )
        self.assertEqual(results['system_info']['installed_license']['license_date'], '2022/09/08')
        self.assertEqual(results['system_info']['installed_license']['service_check_date'], '2022/10/14')
        self.assertEqual(results['system_info']['platform_type'], 'rSeries Platform')

    def test_get_system_info_facts_partition(self):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('system-info')
        vm.client.platform = 'Velos Partition'
        vm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_velos_partition_components_info.json')),
            dict(code=200, contents=load_fixture('load_velos_partition_components_info.json')),
            dict(code=200, contents=load_fixture('load_f5os_license_info.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertListEqual(
            results['system_info']['running_software'],
            [{'blade_name': 'blade-1', 'os_version': '1.5.1-10014', 'service_version': '1.5.1-10014'}]
        )
        self.assertDictEqual(
            results['system_info']['components'][0],
            {'name': 'blade-1', 'serial_no': 'bld427173s', 'part_no': '403-0086-02 REV C',
             'memory_usage': {'total': 18555600896, 'free': 14542594048, 'used_percent': 86},
             'system_temperature': {'current': 26.0, 'average': 26.0, 'minimum': 26.0, 'maximum': 26.0}}
        )
        self.assertEqual(results['system_info']['installed_license']['license_date'], '2022/09/08')
        self.assertEqual(results['system_info']['installed_license']['service_check_date'], '2022/10/14')
        self.assertEqual(results['system_info']['platform_type'], 'Velos Partition')

    def test_get_system_info_facts_controller(self):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('system-info')
        vm.client.platform = 'Velos Controller'
        vm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_velos_controller_components_info.json')),
            dict(code=200, contents=load_fixture('load_velos_controller_software_info.json')),
            dict(code=200, contents=load_fixture('load_f5os_license_info.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertListEqual(
            results['system_info']['running_software'],
            [{'controller_name': 'controller-1', 'os_version': '1.5.1-10014', 'service_version': '1.5.1-10014'},
             {'controller_name': 'controller-2', 'os_version': '1.5.1-10014', 'service_version': '1.5.1-10014'}]
        )
        self.assertEqual(len(results['system_info']['components']), 5)
        self.assertEqual(results['system_info']['installed_license']['license_date'], '2022/09/08')
        self.assertEqual(results['system_info']['installed_license']['service_check_date'], '2022/10/14')
        self.assertEqual(results['system_info']['platform_type'], 'Velos Controller')

    def test_read_from_methods(self):
        set_module_args(dict(
            gather_subset=['system-info']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        vm = mm.get_manager('system-info')
        vm.client.get = Mock(return_value=dict(code=400, contents='response error'))

        with self.assertRaises(F5ModuleError) as err:
            vm.read_components_from_device()

        self.assertIn('response error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            vm.read_partition_software_info_from_device()

        self.assertIn('response error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            vm.read_platform_software_info_from_device()

        self.assertIn('response error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            vm.read_controller_software_info_from_device()

        self.assertIn('response error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            vm.read_license_from_device()

        self.assertIn('response error', err.exception.args[0])

    def test_properties_none(self):
        mock_part = PartitionSoftwareInfoParameters(dict())

        self.assertIsNone(mock_part.os_version)
        self.assertIsNone(mock_part.service_version)
