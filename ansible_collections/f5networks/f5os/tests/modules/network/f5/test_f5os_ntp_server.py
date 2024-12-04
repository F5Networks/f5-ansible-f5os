# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_ntp_server
from ansible_collections.f5networks.f5os.plugins.modules.f5os_ntp_server import (
    ArgumentSpec, ModuleManager, ApiParameters
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
    def test_api_parameters(self):
        args = load_fixture('ntp_server_get.json')

        p = ApiParameters(params=args['openconfig-system:server'][0])
        self.assertEqual(p.server, '10.218.33.44')
        self.assertEqual(p.key_id, 12)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_ntp_server.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_ntp_server.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            key_id=22,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            key_id=32,
            iburst=False,
            prefer=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current_ntp})
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_no_change(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            key_id=12,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value={'code': 200, 'contents': current_ntp})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.get.call_count, 1)
        self.assertEqual(mm.client.patch.call_count, 0)
        self.assertEqual(mm.client.post.call_count, 0)

    def test_delete(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)

    @patch.object(f5os_ntp_server, 'Connection')
    @patch.object(f5os_ntp_server.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            server='1.2.3.4',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_ntp_server.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_ntp_server, 'Connection')
    @patch.object(f5os_ntp_server.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            server='1.2.3.4',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_ntp_server.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            server='1.2.3.4',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm.client.get = Mock(return_value={'code': 200})

        res1 = mm.exists()
        self.assertTrue(res1)

        mm.client.get = Mock(return_value={'code': 503, 'contents': 'service not available'})

        with self.assertRaises(F5ModuleError) as res2:
            mm.exists()
        self.assertIn('service not available', res2.exception.args[0])

        mm.client.post = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res3:
            mm.create()
        self.assertIn('service not available', res3.exception.args[0])

        mm.client.patch = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res4:
            mm.update()
        self.assertIn('service not available', res4.exception.args[0])

        mm.client.delete = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res5:
            mm.remove_from_device()
        self.assertIn('service not available', res5.exception.args[0])

        mm.client.get = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res6:
            mm.read_current_from_device()
        self.assertIn('service not available', res6.exception.args[0])

        mm.remove_from_device = Mock()
        mm.exists = Mock(return_value=True)
        with self.assertRaises(F5ModuleError) as res7:
            mm.remove()
        self.assertIn('Failed to delete the resource.', res7.exception.args[0])

        mm.exists = Mock(return_value=False)
        res8 = mm.absent()
        self.assertFalse(res8)
