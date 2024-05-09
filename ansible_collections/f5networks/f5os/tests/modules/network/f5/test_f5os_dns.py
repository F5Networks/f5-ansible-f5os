# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_dns
from ansible_collections.f5networks.f5os.plugins.modules.f5os_dns import (
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
    def test_module_parameters_as_list(self):
        args = dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertListEqual(p.dns_servers, ["10.10.10.10", "10.10.10.11", "10.10.10.12"])
        self.assertListEqual(p.dns_domains, ["test-domain1.com", "test-domain2.com", "test-domain3.com"])

    def test_module_parameters_as_string(self):
        args = dict(
            dns_servers="10.10.10.10",
            dns_domains="test-domain1.com",
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertListEqual(p.dns_servers, ["10.10.10.10"])
        self.assertListEqual(p.dns_domains, ["test-domain1.com"])

    def test_api_parameters(self):
        args = dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='present'
        )

        p = ApiParameters(params=args)

        self.assertListEqual(p.dns_servers, ["10.10.10.10", "10.10.10.11", "10.10.10.12"])

    def test_missing_parameters(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.dns_servers)
        self.assertIsNone(p.dns_domains)

        p = ModuleParameters(params=dict())

        self.assertIsNone(p.dns_servers)
        self.assertIsNone(p.dns_domains)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_dns.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_dns.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_dns_create(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-system:dns': {'config': {'search': ['test-domain1.com',
                                                                    'test-domain2.com',
                                                                    'test-domain3.com']},
                                              'servers': {'server': [{'address': '10.10.10.10'},
                                                                     {'address': '10.10.10.11'},
                                                                     {'address': '10.10.10.12'}]}}}

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertDictEqual(mm.client.patch.call_args[1]['data'], expected)

    def test_dns_create_fails(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=400, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])
        self.assertTrue(mm.client.patch.called)

    def test_dns_update_no_change(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        # mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('load_tenant_status_configured.json')))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_dns_remove(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
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

    def test_dns_remove_error_response(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
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

    @patch.object(f5os_dns, 'Connection')
    @patch.object(f5os_dns.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='absent'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_dns.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_dns, 'Connection')
    @patch.object(f5os_dns.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            dns_servers=["10.10.10.10", "10.10.10.11", "10.10.10.12"],
            dns_domains=["test-domain1.com", "test-domain2.com", "test-domain3.com"],
            state='absent'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_dns.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            dns_servers=["10.10.10.10"],
            state="present"
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

        mm._update_changed_options = Mock(return_value=False)

        self.assertFalse(mm.update())
