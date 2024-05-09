# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_qkview
from ansible_collections.f5networks.f5os.plugins.modules.f5os_qkview import (
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
            filename='test',
            timeout=2,
            max_file_size=500,
            max_core_size=25,
            exclude_cores=True,
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.filename, 'test')
        self.assertEqual(p.timeout, 2)
        self.assertEqual(p.max_file_size, 500)
        self.assertEqual(p.max_core_size, 25)
        self.assertEqual(p.exclude_cores, True)
        self.assertEqual(p.state, 'present')

    def test_default_module_parameters(self):
        args = dict(
            filename='test',
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.filename, 'test')
        self.assertEqual(p.timeout, 0)
        self.assertEqual(p.max_file_size, 500)
        self.assertEqual(p.max_core_size, 25)
        self.assertEqual(p.exclude_cores, False)
        self.assertEqual(p.state, 'present')

    def test_module_parameters_invalid_max_file_size(self):
        args = dict(
            max_file_size=0
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.max_file_size()

        self.assertIn('Valid max_file_size must be in range 2 - 1000', err.exception.args[0])

    def test_module_parameters_invalid_max_core_size(self):
        args = dict(
            max_core_size=0
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.max_core_size()

        self.assertIn('Valid max_core_size must be in range 2 - 1000', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qkview.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_qkview.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_generate_qkview(self, *args):
        set_module_args(dict(
            filename='test',
            timeout=2,
            max_file_size=500,
            max_core_size=25,
            exclude_cores=True,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {
            'f5-system-diagnostics-qkview:output': {
                'result': {
                    'Busy': False,
                    'Percent': 100,
                    'Status': 'complete',
                    'Message': 'Completed collection.',
                    'Filename': 'test'
                },
                'resultint': 0
            }
        }
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=dict(load_fixture('f5os_qkview_created.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_qkview_in_progress.json'))),
            dict(code=200, contents=dict(load_fixture('f5os_qkview_status.json')))
        ])
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_generate_qkview_idempotent(self, *args):
        set_module_args(dict(
            filename='test',
            timeout=2,
            max_file_size=500,
            max_core_size=25,
            exclude_cores=True,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_generate_qkview_fails(self, *args):
        set_module_args(dict(
            filename='test',
            timeout=2,
            max_file_size=500,
            max_core_size=25,
            exclude_cores=True,
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

    def test_file_remove(self, *args):
        set_module_args(dict(
            filename='test',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)

        mm.exists = Mock(side_effect=[True, False])
        mm.read_filename_from_device = Mock(return_value="test")
        mm.client.post = Mock(return_value=dict
                              (code=200, contents=dict(load_fixture('f5os_qkview_delete.json'))
                               ))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_file_remove_idempotent(self, *args):
        set_module_args(dict(
            filename='test',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[False])

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_file_remove_fails(self, *args):
        set_module_args(dict(
            filename='test',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])
        self.assertTrue(mm.client.post.called)

    def test_read_filename_from_device(self, *args):
        set_module_args(dict(
            filename='test',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=dict(code=200, contents=dict(load_fixture('f5os_qkview_list.json'))))
        result = mm.read_filename_from_device()

        self.assertTrue(result)

    @patch.object(f5os_qkview, 'Connection')
    @patch.object(f5os_qkview.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            filename='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_qkview.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_qkview, 'Connection')
    @patch.object(f5os_qkview.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            filename='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_qkview.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            filename="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.post = Mock(side_effect=[dict(code=200, contents=dict(load_fixture('f5os_qkview_list.json'))),
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

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])
