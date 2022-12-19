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
            name='foo',
            image_name='BIGIP-bigip.TMOS-VEL.qcow2.zip',
            nodes=[1],
            mgmt_ip='127.0.0.1',
            mgmt_prefix=24,
            mgmt_gateway='127.0.0.254',
            vlans=[245],
            cpu_cores=2,
            memory=4096,
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
        self.assertListEqual(p.vlans, [245])
        self.assertEqual(p.cpu_cores, 2)
        self.assertEqual(p.memory, 4096)
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

    def test_missing_parameters(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.cpu_cores)
        self.assertIsNone(p.memory)

        p = ModuleParameters(params=dict())

        self.assertIsNone(p.vlans)
        self.assertIsNone(p.name)

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
                'vcpu-cores-per-node': 2, 'memory': 7680, 'cryptos': 'enabled', 'running-state': 'configured'}}]}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected)

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
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_tenant.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
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
