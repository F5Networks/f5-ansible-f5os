# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_banner
from ansible_collections.f5networks.f5os.plugins.modules.f5os_banner import (
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
        params = {
            'login_banner': 'Unauthorized access is prohibited.',
            'motd_banner': 'Welcome to the F5OS platform.',
        }
        p = ApiParameters(params=params)
        self.assertEqual(p.login_banner, 'Unauthorized access is prohibited.')
        self.assertEqual(p.motd_banner, 'Welcome to the F5OS platform.')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_banner.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_banner.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_login_banner(self, *args):
        set_module_args(dict(
            login_banner='Unauthorized access is prohibited.',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config_empty.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['login_banner'], 'Unauthorized access is prohibited.')
        self.assertEqual(mm.client.put.call_count, 1)

    def test_create_both_banners(self, *args):
        set_module_args(dict(
            login_banner='Unauthorized access is prohibited.',
            motd_banner='Welcome to the F5OS platform.',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config_empty.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['login_banner'], 'Unauthorized access is prohibited.')
        self.assertEqual(results['motd_banner'], 'Welcome to the F5OS platform.')
        self.assertEqual(mm.client.put.call_count, 2)

    def test_update_login_banner(self, *args):
        set_module_args(dict(
            login_banner='New login banner text.',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.put = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['login_banner'], 'New login banner text.')
        self.assertEqual(mm.client.put.call_count, 1)

    def test_no_change(self, *args):
        set_module_args(dict(
            login_banner='Unauthorized access is prohibited.',
            motd_banner='Welcome to the F5OS platform.',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.put.call_count, 0)

    def test_delete_both_banners(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 2)

    def test_present_empty_login_banner_raises_error(self, *args):
        set_module_args(dict(
            login_banner='',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("cannot be an empty string", err.exception.args[0])

    def test_present_empty_motd_banner_raises_error(self, *args):
        set_module_args(dict(
            motd_banner='',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("cannot be an empty string", err.exception.args[0])

    def test_delete_login_banner_only(self, *args):
        set_module_args(dict(
            login_banner='',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})
        mm.client.delete = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)

    def test_delete_no_banners_exist(self, *args):
        set_module_args(dict(
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = load_fixture('f5os_banner_config_empty.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 200, 'contents': current})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.delete.call_count, 0)

    @patch.object(f5os_banner, 'Connection')
    @patch.object(f5os_banner.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            login_banner='Test banner',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_banner.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_banner, 'Connection')
    @patch.object(f5os_banner.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            login_banner='Test banner',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_banner.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            login_banner='Test banner',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        mm.client.get = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res1:
            mm.read_current_from_device()
        self.assertIn('service not available', res1.exception.args[0])

        mm.client.put = Mock(return_value={'code': 503, 'contents': 'service not available'})
        mm.changes = Mock()
        mm.changes.to_return = Mock(return_value={'login_banner': 'test'})
        with self.assertRaises(F5ModuleError) as res2:
            mm.update_on_device()
        self.assertIn('service not available', res2.exception.args[0])

        mm.client.put = Mock(return_value={'code': 503, 'contents': 'service not available'})
        mm.changes = Mock()
        mm.changes.to_return = Mock(return_value={'motd_banner': 'test'})
        with self.assertRaises(F5ModuleError) as res3:
            mm.update_on_device()
        self.assertIn('service not available', res3.exception.args[0])

        mm.client.delete = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res4:
            mm.remove_from_device(True, False)
        self.assertIn('service not available', res4.exception.args[0])

        mm.client.delete = Mock(return_value={'code': 503, 'contents': 'service not available'})
        with self.assertRaises(F5ModuleError) as res5:
            mm.remove_from_device(False, True)
        self.assertIn('service not available', res5.exception.args[0])
