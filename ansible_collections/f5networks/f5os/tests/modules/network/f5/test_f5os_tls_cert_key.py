# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_tls_cert_key
from ansible_collections.f5networks.f5os.plugins.modules.f5os_tls_cert_key import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager, F5ModuleError
)

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
    def setUp(self) -> None:
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tls_cert_key.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()

    def tearDown(self) -> None:
        self.p1.stop()

    def test_module_parameters(self):
        pass

    def test_api_parameters(self):
        args = dict()
        p = ApiParameters(args)

        self.assertIsNone(p.name)
        self.assertIsNone(p.email)
        self.assertIsNone(p.city)
        self.assertIsNone(p.province)
        self.assertIsNone(p.country)
        self.assertIsNone(p.organization)
        self.assertIsNone(p.unit)
        self.assertIsNone(p.version)
        self.assertIsNone(p.days_valid)
        self.assertIsNone(p.valid_from)
        self.assertIsNone(p.valid_until)
        self.assertIsNone(p.password)

    def test_module_parameters(self):
        args1 = dict(
            subject_alternative_name="DNS:www.example.com",
        )
        p1 = ModuleParameters(params=args1)

        self.assertEqual(p1.subject_alternative_name, "DNS:www.example.com")


class TestManager(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tls_cert_key.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tls_cert_key.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self) -> None:
        self.mock_module_helper.stop()
        self.p1.stop()
        self.p2.stop()

    def test_create_cert_key_on_velos(self, *args):
        set_module_args(dict(
            name="test_cert",
            email="name@org.com",
            city="Vegas",
            province="NV",
            country="US",
            organization="FZ",
            unit="IT",
            version=1,
            days_valid=365,
            key_size=2048,
            key_type="rsa",
            store_tls=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'

        mm.client.get = Mock(return_value={'code': 200, 'contents': {'f5-openconfig-aaa-tls:tls': {'config': {}}}})
        mm.client.post = Mock(return_value={'code': 200, 'contents': {}})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_create_cert_key_on_rseries(self, *args):
        set_module_args(dict(
            name="test_cert",
            subject_alternative_name="DNS:www.example.com",
            email="name@org.com",
            city="Vegas",
            province="NY",
            country="US",
            organization="FZ",
            unit="IT",
            version=1,
            days_valid=365,
            key_size=2048,
            key_type="rsa",
            store_tls=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm.client.get = Mock(return_value={'code': 200, 'contents': {'f5-openconfig-aaa-tls:tls': {'config': {}}}})
        mm.client.post = Mock(return_value={'code': 200, 'contents': {}})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_cert_key(self, *args):
        set_module_args(dict(
            name="test_cert",
            city="Seattle",
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        existing_cert = load_fixture('f5os_get_tls_cert.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Platform'

        mm.client.get = Mock(return_value={'code': 200, 'contents': existing_cert})
        mm.client.post = Mock(return_value={'code': 200, 'contents': {}})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_delete_cert_key(self, *args):
        set_module_args(dict(
            name="test_cert",
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Platform'

        mm.exists = Mock(side_effect=[True, False])
        mm.client.put = Mock(return_value={'code': 200, 'contents': {}})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 1)

    @patch.object(f5os_tls_cert_key, 'Connection')
    @patch.object(f5os_tls_cert_key.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_tls_cert_key.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_tls_cert_key, 'Connection')
    @patch.object(f5os_tls_cert_key.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_tls_cert_key.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            name="test_cert",
            email="name@org.com",
            city="Vegas",
            province="NV",
            country="US",
            organization="FZ",
            unit="IT",
            version=1,
            days_valid=365,
            key_size=2048,
            key_type="rsa",
            store_tls=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'

        mm.client.get = Mock(
            side_effect=[
                {'code': 404, 'contents': {}},
                {'code': 503, 'contents': 'server error'},
            ]
        )
        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as res2:
            mm.exists()
        self.assertIn("server error", res2.exception.args[0])

        mm.exists = Mock(return_value=False)
        res3 = mm.absent()
        self.assertFalse(res3)

        mm._update_changed_options = Mock(return_value=False)
        res4 = mm.should_update()
        self.assertFalse(res4)

        mm.client.get = Mock(return_value={'code': 503, 'contents': 'server error'})
        with self.assertRaises(F5ModuleError) as res5:
            mm.read_current_from_device()
        self.assertIn("server error", res5.exception.args[0])

        mm.client.put = Mock(return_value={'code': 503, 'contents': 'server error'})
        with self.assertRaises(F5ModuleError) as res6:
            mm.remove_from_device()
        self.assertIn("server error", res6.exception.args[0])

        mm.remove_from_device = Mock()
        mm.exists = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res7:
            mm.remove()
        self.assertIn("Failed to delete the resource.", res7.exception.args[0])

        mm.read_current_from_device = Mock()
        mm.should_update = Mock(return_value=False)
        res8 = mm.update()
        self.assertFalse(res8)
