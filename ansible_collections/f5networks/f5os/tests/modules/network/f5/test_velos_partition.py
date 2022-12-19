# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import velos_partition
from ansible_collections.f5networks.f5os.plugins.modules.velos_partition import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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
            name='testfoo2',
            os_version='1.1.1-5046',
            ipv4_mgmt_address='10.144.140.127/24',
            ipv4_mgmt_gateway='10.144.140.253',
            slots=[6],
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'testfoo2')
        self.assertEqual(p.os_version, '1.1.1-5046')
        self.assertEqual(p.ipv4_mgmt_address, '10.144.140.127/24')
        self.assertEqual(p.ipv4_mgmt_gateway, '10.144.140.253')
        self.assertListEqual(p.slots, [6])

    def test_alternative_module_parameter_choices(self):
        args1 = dict(
            ipv4_mgmt_gateway='none',
            ipv4_mgmt_address='192.168.1.1',
            ipv6_mgmt_gateway='none',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            slots=[],
        )

        p = ModuleParameters(params=args1)

        self.assertEqual('none', p.ipv6_mgmt_gateway)
        self.assertEqual('none', p.ipv4_mgmt_gateway)
        self.assertEqual('192.168.1.1', p.ipv4_mgmt_address)
        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:7334', p.ipv6_mgmt_address)
        self.assertListEqual([], p.slots)

        args2 = dict(
            ipv6_mgmt_gateway='2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334/64'
        )

        p = ModuleParameters(params=args2)

        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:7334', p.ipv6_mgmt_gateway)
        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:7334/64', p.ipv6_mgmt_address)

    def test_module_parameter_failures(self):
        args = dict(
            ipv6_mgmt_address='qwert.yuio.pasd.fghj',
            ipv6_mgmt_gateway='abcd.efgh.ijkl.mnop',
            ipv4_mgmt_address='300.300.300.300',
            ipv4_mgmt_gateway='287.123.123.123',
            slots=[32, 45]
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err1:
            p.ipv6_mgmt_address()
        self.assertIn("The specified 'ipv6_mgmt_address' is not a valid IP address", err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            p.ipv6_mgmt_gateway()
        self.assertIn("The specified 'ipv6_mgmt_gateway' is not a valid IP address", err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            p.ipv4_mgmt_address()
        self.assertIn("The specified 'ipv4_mgmt_address' is not a valid IP address", err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            p.ipv4_mgmt_gateway()
        self.assertIn("The specified 'ipv4_mgmt_gateway' is not a valid IP address", err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            p.slots()
        self.assertIn("Valid slot id's must be in range 0 - 32", err5.exception.args[0])

    def test_api_parameters(self):
        args = load_fixture('load_partition_info.json')

        p = ApiParameters(params=args)

        self.assertEqual('1.1.1-5046', p.os_version)
        self.assertEqual('10.144.140.124/24', p.ipv4_mgmt_address)
        self.assertEqual('10.144.140.254', p.ipv4_mgmt_gateway)
        self.assertTrue(p.enabled)

        args = load_fixture('load_partition_info_ipv6.json')

        p = ApiParameters(params=args)

        self.assertEqual('1.1.1-5046', p.os_version)
        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:7334/64', p.ipv6_mgmt_address)
        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:2334', p.ipv6_mgmt_gateway)
        self.assertIsNone(p.ipv4_mgmt_address)
        self.assertIsNone(p.ipv4_mgmt_gateway)
        self.assertTrue(p.enabled)

        p = ApiParameters(params=dict())

        self.assertIsNone(p.ipv4_mgmt_address)
        self.assertIsNone(p.ipv4_mgmt_gateway)
        self.assertIsNone(p.ipv6_mgmt_address)
        self.assertIsNone(p.ipv6_mgmt_gateway)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_partition_create(self, *args):
        set_module_args(dict(
            name='foo2',
            os_version='1.1.1-5046',
            ipv4_mgmt_address='10.144.140.127/24',
            ipv4_mgmt_gateway='10.144.140.255',
            slots=[5],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'partition': {'config': {'enabled': True, 'iso-version': '1.1.1-5046', 'mgmt-ip': {
            'ipv4': {'address': '10.144.140.127', 'gateway': '10.144.140.255', 'prefix-length': 24}}}, 'name': 'foo2'}}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=201, contents={}))
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(expected, mm.client.post.call_args[1]['data'])

    def test_partition_create_failure(self, *args):
        set_module_args(dict(
            name='foo2',
            os_version='1.1.1-5046',
            ipv4_mgmt_address='10.144.140.127/24',
            ipv4_mgmt_gateway='10.144.140.255',
            slots=[5],
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

    def test_partition_update(self, *args):
        set_module_args(dict(
            name='main',
            slots=[5, 6],
            os_version='1.2.1-9875',
            ipv4_mgmt_address='192.168.1.12/24',
            ipv4_mgmt_gateway='192.168.1.1'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.client.post = Mock(return_value=dict(code=202, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertListEqual([5, 6], results['slots'])
        self.assertEqual('192.168.1.12/24', results['ipv4_mgmt_address'])
        self.assertEqual('192.168.1.1', results['ipv4_mgmt_gateway'])

    def test_partition_update_ipv6(self, *args):
        set_module_args(dict(
            name='foo',
            ipv6_mgmt_gateway='2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334/64'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.client.post = Mock(return_value=dict(code=202, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:7334/64', results['ipv6_mgmt_address'])
        self.assertEqual('2001:0db8:85a3:0000:0000:8a2e:0370:7334', results['ipv6_mgmt_gateway'])

    def test_partition_update_no_change(self, *args):
        set_module_args(dict(
            name='main',
            ipv4_mgmt_gateway='10.144.140.254',
            os_version='1.1.1-5046'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.client.post = Mock(return_value=dict(code=202, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_partition_update_disable(self, *args):
        set_module_args(dict(
            name='main',
            state='disabled'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.client.post = Mock(return_value=dict(code=202, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertFalse(results['enabled'])

    def test_partition_update_ipv4_gw_ipv4mgmt_not_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv4_mgmt_gateway='10.144.140.230'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv4_mgmt_gateway'], '10.144.140.230')

    def test_partition_update_ipv4_gw_ipv4mgmt_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv4_mgmt_address='10.144.140.124/24',
            ipv4_mgmt_gateway='10.144.140.230',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv4_mgmt_gateway'], '10.144.140.230')

    def test_partition_update_ipv4mgmt_ipv4_gw_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv4_mgmt_address='10.144.140.120/24',
            ipv4_mgmt_gateway='10.144.140.254',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv4_mgmt_address'], '10.144.140.120/24')

    def test_partition_update_ipv4mgmt_ipv4_gw_not_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv4_mgmt_address='10.144.140.120/24',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv4_mgmt_address'], '10.144.140.120/24')

    def test_partition_update_ipv6_gw_ipv6mgmt_not_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv6_mgmt_gateway='2002::1234:abcd:ffff:c0a8:101'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured_ipv6.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv6_mgmt_gateway'], '2002::1234:abcd:ffff:c0a8:101')

    def test_partition_update_ipv6_gw_ipv6mgmt_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334/64',
            ipv6_mgmt_gateway='2002::1234:abcd:ffff:c0a8:101'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured_ipv6.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv6_mgmt_gateway'], '2002::1234:abcd:ffff:c0a8:101')

    def test_partition_update_ipv6mgmt_ipv6_gw_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:aced/64',
            ipv6_mgmt_gateway='2001:0db8:85a3:0000:0000:8a2e:0370:2334',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured_ipv6.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv6_mgmt_address'], '2001:0db8:85a3:0000:0000:8a2e:0370:aced/64')

    def test_partition_update_ipv6mgmt_ipv6_gw_not_defined(self, *args):
        set_module_args(dict(
            name='main',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:aced/64',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=204, contents={}))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured_ipv6.json')))

        results = mm.exec_module()

        self.assertEqual(results['ipv6_mgmt_address'], '2001:0db8:85a3:0000:0000:8a2e:0370:aced/64')

    def test_partition_update_iso_update_failed(self, *args):
        set_module_args(dict(
            name='main',
            os_version='1.2.1-9875',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=403, contents='forbidden'))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('forbidden', err.exception.args[0])

    def test_partition_update_failed(self, *args):
        set_module_args(dict(
            name='main',
            ipv4_mgmt_address='10.144.140.124/24',
            ipv4_mgmt_gateway='10.144.140.230',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.patch = Mock(return_value=dict(code=500, contents='failed to patch'))
        mm.get_slots_associated_with_partition = Mock(
            return_value=dict(code=200, contents=load_fixture('load_slot_info.json')))
        mm.client.get = Mock(
            return_value=dict(code=200, contents=load_fixture('load_partition_status_configured.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('failed to patch', err.exception.args[0])

    def test_partition_remove(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.patch = Mock(return_value=dict(code=200))
        mm.client.delete = Mock(return_value=dict(code=200))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_partition_status_configured.json')),
            dict(code=200, contents=load_fixture('load_slot_info.json'))
        ])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertDictEqual(
            mm.client.patch.call_args[1]['data'],
            {'f5-system-slot:slots': {'slot': [{'slot-num': 3, 'partition': 'none'}]}}
        )

    def test_partition_remove_failed(self, *args):
        set_module_args(dict(
            name='foo',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.patch = Mock(return_value=dict(code=200))
        mm.client.delete = Mock(return_value=dict(code=401, contents='forbidden access'))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=load_fixture('load_partition_status_configured.json')),
            dict(code=200, contents=load_fixture('load_slot_info.json'))
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('forbidden access', err.exception.args[0])

    @patch.object(velos_partition, 'Connection')
    @patch.object(velos_partition.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            os_version='1.1.1',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            velos_partition.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(velos_partition, 'Connection')
    @patch.object(velos_partition.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            velos_partition.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='foobar',
            ipv4_mgmt_address='192.168.1.1',
            ipv6_mgmt_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[
            dict(code=200), dict(code=404), dict(code=400, contents='server error'),
            dict(code=200, contents={'f5-system-slot:slot': {}}), dict(code=401, contents='auth error'),
            dict(code=404, contents='not found'), dict(code=402, contents='Payment Required')
        ])
        mm.client.patch = Mock(return_value=dict(code=400, contents='server error'))

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        res3 = mm.get_all_slots()
        self.assertDictEqual({}, res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.get_all_slots()
        self.assertIn('auth error', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('not found', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.get_slots_associated_with_partition('foobar')
        self.assertIn('Payment Required', err4.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res4 = mm.absent()
        self.assertFalse(res4)

        with self.assertRaises(F5ModuleError) as err5:
            mm.read_current_from_device = Mock(return_value=dict())
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.set_slot_config('foo', [1])
        self.assertIn('Failed to assign partition slot with', err6.exception.args[0])

        mm._set_changed_options = Mock(return_value=True)
        mm.create_on_device = Mock(return_value=True)

        self.assertTrue(mm.create())
        self.assertIn('192.168.1.1/24', mm.want.ipv4_mgmt_address)
        self.assertIn('2001:0db8:85a3:0000:0000:8a2e:0370:7334/96', mm.want.ipv6_mgmt_address)

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())
