# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_tenant
from ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager, Difference
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
            name='foo',
            image_name='BIGIP-bigip.TMOS-VEL.qcow2.zip',
            nodes=[1],
            mgmt_ip='127.0.0.1',
            mgmt_prefix=24,
            mgmt_gateway='127.0.0.254',
            mgmt_vlan=100,
            vlans=[245],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            running_state='deployed',
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'foo')
        self.assertEqual(p.image_name, 'BIGIP-bigip.TMOS-VEL.qcow2.zip')
        self.assertListEqual(p.nodes, [1])
        self.assertEqual(p.mgmt_ip, '127.0.0.1')
        self.assertEqual(p.mgmt_gateway, '127.0.0.254')
        self.assertEqual(p.mgmt_vlan, 100)
        self.assertListEqual(p.vlans, [245])
        self.assertEqual(p.cpu_cores, 2)
        self.assertEqual(p.memory, 7680)
        self.assertEqual(p.cryptos, 'enabled')
        self.assertEqual(p.running_state, 'deployed')
        self.assertEqual(p.state, 'present')

    def test_api_parameters(self):
        args = load_fixture('load_tenant_info.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.name, 'tenant1')
        self.assertEqual(p.image_name, 'BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle')
        self.assertListEqual(p.nodes, [1, 2])
        self.assertEqual(p.mgmt_ip, '10.144.140.150')
        self.assertEqual(p.mgmt_gateway, '10.144.140.254')
        self.assertEqual(p.vlans, [444])
        self.assertEqual(p.cpu_cores, 2)
        self.assertEqual(p.memory, 7680)
        self.assertEqual(p.cryptos, 'disabled')
        self.assertEqual(p.running_state, 'configured')

    def test_api_parameters_mgmt_vlan_namespaced(self):
        args = dict(
            name='tenant1',
            nodes=[1],
            image='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            **{'f5-tenant-mgmt-vlan:mgmt-vlan': 100}
        )

        p = ApiParameters(params=args)
        self.assertEqual(p.mgmt_vlan, 100)

    def test_missing_parameters(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.cpu_cores)
        self.assertIsNone(p.memory)

        p = ModuleParameters(params=dict())

        self.assertIsNone(p.vlans)
        self.assertIsNone(p.name)
        self.assertIsNone(p.mgmt_vlan)

    def test_module_parameters_invalid_mgmt_vlan(self):
        args = dict(
            mgmt_vlan=5000
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.mgmt_vlan()

        self.assertIn("Valid 'mgmt_vlan' id must be in range 0 - 4095", err.exception.args[0])

    def test_module_parameters_invalid_mgmt_ip(self):
        args = dict(
            mgmt_ip='999.999.999.999'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.mgmt_ip()

        self.assertIn('is not a valid IP address', err.exception.args[0])

    def test_module_parameters_invalid_mgmt_gateway(self):
        args = dict(
            mgmt_gateway='999.999.999.999'
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.mgmt_gateway()

        self.assertIn('is not a valid IP address', err.exception.args[0])

    def test_module_parameters_invalid_memory(self):
        args = dict(
            memory=0
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.memory()

        self.assertIn('must be in range 1 - 8388608', err.exception.args[0])

    def test_module_parameters_invalid_nodes(self):
        args = dict(
            nodes=[33]
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.nodes()

        self.assertIn('must be in range 0 - 32', err.exception.args[0])

    def test_module_parameters_invalid_vlan(self):
        args = dict(
            vlans=[4999]
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.vlans()

        self.assertIn('id must be in range 0 - 4095', err.exception.args[0])

    def test_module_parameters_name_invalid_chars(self):
        args = dict(
            name='Services&_%$'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('Invalid characters detected in name parameter', err.exception.args[0])

    def test_module_parameters_name_not_starting_with_letter(self):
        args = dict(
            name='5ervices-foo-bar'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('The name parameter must begin with a lowercase letter', err.exception.args[0])

    def test_module_parameters_name_exceed_length(self):
        args = dict(
            name='this-is-a-very-long-name-to-cause-errors-or-give-you-a-headache-just-from-looking-at-it'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        self.assertIn('The name parameter must not exceed 50 characters', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_tenant_create(self, *args):
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            virtual_disk_size=80,
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'tenant': [
            {'name': 'foo', 'config': {
                'image': 'BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle', 'nodes': [1],
                'mgmt-ip': '10.144.140.151', 'gateway': '10.144.140.254', 'vlans': [444], 'prefix-length': 24,
                'vcpu-cores-per-node': 2, 'storage': {'size': 80}, 'memory': 7680, 'cryptos': 'enabled', 'running-state': 'configured'}}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected)

    def test_tenant_create_with_mgmt_vlan_velos(self, *args):
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            mgmt_vlan=100,
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'Velos Partition'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        payload = mm.client.post.call_args[1]['data']
        self.assertEqual(payload['tenant'][0]['config']['f5-tenant-mgmt-vlan:mgmt-vlan'], 100)

    def test_tenant_create_with_mgmt_vlan_rseries_pre_v2_omitted(self, *args):
        """mgmt_vlan is omitted on rSeries when F5OS < 2.0.0."""
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            mgmt_vlan=100,
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.9.0'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        payload = mm.client.post.call_args[1]['data']
        self.assertNotIn('f5-tenant-mgmt-vlan:mgmt-vlan', payload['tenant'][0]['config'])

    def test_tenant_create_with_mgmt_vlan_rseries_v2_included(self, *args):
        """mgmt_vlan is sent on rSeries when F5OS >= 2.0.0."""
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            mgmt_vlan=100,
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        payload = mm.client.post.call_args[1]['data']
        self.assertEqual(payload['tenant'][0]['config']['f5-tenant-mgmt-vlan:mgmt-vlan'], 100)

    def test_mgmt_vlan_supported_velos(self, *args):
        set_module_args(dict(name='foo', nodes=[1], state='present'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'
        mm.client.software_version = '1.8.0'
        self.assertTrue(mm._mgmt_vlan_supported())

    def test_mgmt_vlan_supported_rseries_v2(self, *args):
        set_module_args(dict(name='foo', nodes=[1], state='present'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        self.assertTrue(mm._mgmt_vlan_supported())

    def test_mgmt_vlan_not_supported_rseries_pre_v2(self, *args):
        set_module_args(dict(name='foo', nodes=[1], state='present'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.9.0'
        self.assertFalse(mm._mgmt_vlan_supported())

    def test_tenant_create_fails(self, *args):
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value=dict(code=400, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_tenant_update(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            vlans=[444, 333],
            running_state='deployed',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.put = Mock(return_value=dict(code=204, contents={}))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertListEqual(results['vlans'], [333, 444])
        self.assertEqual(results['running_state'], 'deployed')
        self.assertEqual(mm.client.put.call_count, 2)
        self.assertEqual(mm.client.put.call_args_list[0][0][0], '/f5-tenants:tenants/tenant=foo/config/vlans')
        self.assertEqual(mm.client.put.call_args_list[1][0][0], '/f5-tenants:tenants/tenant=foo/config/running-state')
        self.assertDictEqual(mm.client.put.call_args_list[0][1], {'data': {'vlans': [333, 444]}})
        self.assertDictEqual(mm.client.put.call_args_list[1][1], {'data': {'running-state': 'deployed'}})

    def test_tenant_update_no_change(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_tenant_update_fails_error_response(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            vlans=[444, 333],
            running_state='deployed',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.put = Mock(return_value=dict(code=401, contents='unauthorized'))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to update tenant foo', err.exception.args[0])
        self.assertTrue(mm.client.put.called)

    def test_tenant_remove(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_tenant_remove_error_response(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.delete = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])
        self.assertTrue(mm.client.delete.called)

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            name='foobar',
            nodes=[1],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        assert 'Target device is a VELOS controller, aborting.' in str(err.exception)

    @patch.object(f5os_tenant, 'Connection')
    @patch.object(f5os_tenant.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            nodes=[1],
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_tenant.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_tenant, 'Connection')
    @patch.object(f5os_tenant.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            nodes=[1],
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_tenant.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            nodes=[1],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=401, contents='access denied')])

        res1 = mm.exists()
        self.assertTrue(res1)

        res2 = mm.exists()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        mm._update_changed_options = Mock(return_value=False)
        mm.read_current_from_device = Mock(return_value=dict())
        self.assertFalse(mm.update())

    def test_module_parameters_nodes_none(self):
        p = ModuleParameters(params=dict(nodes=None))
        self.assertIsNone(p.nodes)

    def test_module_parameters_mac_block_size(self):
        p = ModuleParameters(params=dict(mac_block_size=4))
        self.assertEqual(p.mac_block_size, {'f5-tenant-l2-inline:mac-block-size': 4})

    def test_difference_virtual_disk_size(self):
        want = Mock()
        want.virtual_disk_size = {'size': 100}
        have = Mock()
        have.virtual_disk_size = {'size': 50}

        diff = Difference(want, have)
        result = diff.virtual_disk_size

        self.assertEqual(result, {'virtual_disk_size': {'size': 100}})

    def test_difference_virtual_disk_size_no_change(self):
        want = Mock()
        want.virtual_disk_size = {'size': 100}
        have = Mock()
        have.virtual_disk_size = {'size': 100}

        diff = Difference(want, have)
        self.assertIsNone(diff.virtual_disk_size)

    def test_difference_virtual_disk_size_have_none(self):
        want = Mock()
        want.virtual_disk_size = {'size': 100}
        have = Mock()
        have.virtual_disk_size = None

        diff = Difference(want, have)
        self.assertEqual(diff.virtual_disk_size, {'size': 100})

    def test_difference_mac_block_size(self):
        want = Mock()
        want.mac_block_size = {'f5-tenant-l2-inline:mac-block-size': 4}
        have = Mock()
        have.mac_block_size = {'f5-tenant-l2-inline:mac-block-size': 2}

        diff = Difference(want, have)
        result = diff.mac_block_size

        self.assertEqual(result, {'mac_block_size': {'f5-tenant-l2-inline:mac-block-size': 4}})

    def test_difference_mac_block_size_have_none(self):
        want = Mock()
        want.mac_block_size = {'f5-tenant-l2-inline:mac-block-size': 4}
        have = Mock()
        have.mac_block_size = None

        diff = Difference(want, have)
        self.assertEqual(diff.mac_block_size, {'f5-tenant-l2-inline:mac-block-size': 4})

    def test_difference_mac_block_size_no_change(self):
        want = Mock()
        want.mac_block_size = {'f5-tenant-l2-inline:mac-block-size': 4}
        have = Mock()
        have.mac_block_size = {'f5-tenant-l2-inline:mac-block-size': 4}

        diff = Difference(want, have)
        self.assertIsNone(diff.mac_block_size)

    def test_announce_deprecations(self):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()

        result = {'__warnings': [{'msg': 'deprecated', 'version': '1.0'}]}
        mm._announce_deprecations(result)

        mm.client.module.deprecate.assert_called_once_with(msg='deprecated', version='1.0')

    @patch.object(f5os_tenant, 'Connection')
    @patch.object(f5os_tenant, 'F5Client')
    def test_create_check_mode(self, *args):
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.10.10.10',
            mgmt_prefix=24,
            mgmt_gateway='10.10.10.1',
            vlans=[444],
            state='present',
            _ansible_check_mode=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(f5os_tenant, 'Connection')
    @patch.object(f5os_tenant, 'F5Client')
    def test_update_check_mode(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            running_state='deployed',
            state='present',
            _ansible_check_mode=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(f5os_tenant, 'Connection')
    @patch.object(f5os_tenant, 'F5Client')
    def test_remove_check_mode(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            state='absent',
            _ansible_check_mode=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock(return_value=ApiParameters(params=dict()))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    @patch.object(f5os_tenant, 'Connection')
    @patch.object(f5os_tenant, 'F5Client')
    def test_update_running_state_configured(self, *args):
        set_module_args(dict(
            name='foo',
            nodes=[1],
            running_state='provisioned',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_tenant_create_with_max_nodes_v2(self, *args):
        """max_nodes is included in create payload on F5OS >= 2.0.0."""
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            max_nodes=2,
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        payload = mm.client.post.call_args[1]['data']
        self.assertEqual(payload['tenant'][0]['config']['max-nodes'], 2)

    def test_tenant_create_max_nodes_omitted_on_pre_v2(self, *args):
        """max_nodes is silently omitted from create payload on F5OS < 2.0.0."""
        set_module_args(dict(
            name='foo',
            image_name='BIGIP-14.1.4.1-0.0.4.ALL-VELOS.qcow2.zip.bundle',
            nodes=[1],
            mgmt_ip='10.144.140.151',
            mgmt_prefix=24,
            mgmt_gateway='10.144.140.254',
            vlans=[444],
            cpu_cores=2,
            memory=7680,
            cryptos='enabled',
            max_nodes=2,
            running_state='configured',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.8.3'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        payload = mm.client.post.call_args[1]['data']
        self.assertNotIn('max-nodes', payload['tenant'][0]['config'])

    def test_tenant_update_with_max_nodes_v2(self, *args):
        """max_nodes is sent in update payload on F5OS >= 2.0.0."""
        set_module_args(dict(
            name='foo',
            nodes=[1],
            max_nodes=2,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        put_urls = [call[0][0] for call in mm.client.put.call_args_list]
        self.assertIn('/f5-tenants:tenants/tenant=foo/config/max-nodes', put_urls)

    def test_tenant_update_max_nodes_omitted_on_pre_v2(self, *args):
        """max_nodes is silently omitted from update payload on F5OS < 2.0.0."""
        set_module_args(dict(
            name='foo',
            nodes=[1],
            max_nodes=2,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.8.3'
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        put_urls = [call[0][0] for call in mm.client.put.call_args_list]
        self.assertNotIn('/f5-tenants:tenants/tenant=foo/config/max-nodes', put_urls)

    def test_tenant_read_max_nodes_from_device_v2(self, *args):
        """max_nodes round-trips correctly when read back from a v2.0.0 device."""
        set_module_args(dict(
            name='foo',
            nodes=[1],
            max_nodes=2,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured_v2.json')))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_version_gte_2_true(self, *args):
        set_module_args(dict(name='foo', nodes=[1], state='present'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.software_version = '2.0.0'
        self.assertTrue(mm._version_gte_2())

    def test_version_gte_2_false(self, *args):
        set_module_args(dict(name='foo', nodes=[1], state='present'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.software_version = '1.8.3'
        self.assertFalse(mm._version_gte_2())

    def test_version_gte_2_exception_returns_false(self, *args):
        set_module_args(dict(name='foo', nodes=[1], state='present'))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.software_version = None
        self.assertFalse(mm._version_gte_2())
