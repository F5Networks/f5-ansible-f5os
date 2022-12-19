# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import velos_partition_image
from ansible_collections.f5networks.f5os.plugins.modules.velos_partition_image import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch, PropertyMock
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
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            remote_host='1.2.3.4',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/',
            state='present',
            timeout=600
        )

        p = ModuleParameters(params=args)

        self.assertEqual('F5OS-C-1.1.0-3198.PARTITION.iso', p.image_name)
        self.assertEqual('1.2.3.4', p.remote_host)
        self.assertEqual('admin', p.remote_user)
        self.assertEqual('admin', p.remote_password)
        self.assertEqual('/test/F5OS-C-1.1.0-3198.PARTITION.iso', p.remote_path)
        self.assertEqual('1.1.0-3198', p.iso_version)
        self.assertEqual('present', p.state)
        self.assertTupleEqual((6.0, 100), p.timeout)

    def test_module_parameter_failures(self):
        args = dict(
            image_name='1.21-3198.PARTITION.iso',
            timeout=100
        )
        p = ModuleParameters(params=args)

        self.assertIsNone(p.remote_path)

        with self.assertRaises(F5ModuleError) as err1:
            p.timeout()

        self.assertIn('Timeout value must be between 150 and 3600 seconds.', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            p.iso_version()

        self.assertIn('Could not derive iso_version from provided image_name', err2.exception.args[0])

    def test_alternative_module_parameter_choices(self):
        args = dict(
            image_name='1.21-3198.PARTITION.iso',
            iso_version='1.1.0-3198',
            remote_path='/test/1.21-3198.PARTITION.iso',
        )

        p = ModuleParameters(params=args)

        self.assertIn('1.1.0-3198', p.iso_version)
        self.assertIn('/test/1.21-3198.PARTITION.iso', p.remote_path)
        self.assertIsNone(p.remote_host)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition_image.F5Client')
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p3 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition_image.send_teem')
        self.m3 = self.p3.start()
        self.m3.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_import_image(self, *args):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            remote_host='fake.imageserver.foo.bar.com',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/',
            state='import',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        expected = {'input': [{'protocol': 'scp', 'remote-host': 'fake.imageserver.foo.bar.com',
                               'remote-file': '/test/F5OS-C-1.1.0-3198.PARTITION.iso',
                               'username': 'admin', 'password': 'admin', 'local-file': ('/var/import/staging/',),
                               'insecure': ''}]
                    }
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents=dict(
            load_fixture('start_partition_image_import.json'))))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(expected, mm.client.post.call_args[1]['data'])
        self.assertEqual('F5OS-C-1.1.0-3198.PARTITION.iso', results['image_name'])
        self.assertEqual('/test/F5OS-C-1.1.0-3198.PARTITION.iso', results['remote_path'])
        self.assertEqual('1.1.0-3198', results['iso_version'])
        self.assertEqual('Image F5OS-C-1.1.0-3198.PARTITION.iso import started.', results['message'])

    def test_import_image_failure(self, *args):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            remote_host='fake.imageserver.foo.bar.com',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/',
            state='import',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=400))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to import partition image', err.exception.args[0])

    def test_import_image_progress_check(self, *args):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        importing = dict(code=200, contents=dict(load_fixture('partition_image_import_progress.json')))
        completed = dict(code=200, contents=dict(load_fixture('partition_image_import_success.json')))

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.is_imported = Mock(side_effect=[False, False, True])
        mm.client.post = Mock(side_effect=[importing, completed])

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['message'], 'Image F5OS-C-1.1.0-3198.PARTITION.iso import successful.')
        self.assertEqual(mm.client.post.call_count, 2)

    def test_import_image_progress_check_import_fails(self, *args):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        importing = dict(code=200, contents=dict(load_fixture('partition_image_import_progress.json')))
        fail = dict(code=200, contents=dict(load_fixture('partition_image_import_fail.json')))

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.is_imported = Mock(side_effect=[False, False])
        mm.client.post = Mock(side_effect=[importing, fail])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Error uploading image: File Not Found, HTTP Error 404', err.exception.args[0])
        self.assertEqual(mm.client.post.call_count, 2)

    @patch.object(ModuleParameters, 'timeout', new_callable=PropertyMock)
    def test_import_image_progress_check_timeout(self, mock_timeout):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='present',
        ))
        mock_timeout.return_value = (1, 2)
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        importing = dict(code=200, contents=dict(load_fixture('partition_image_import_progress.json')))

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.is_imported = Mock(return_value=False)
        mm.client.post = Mock(return_value=importing)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Module timeout reached, state change is unknown', err.exception.args[0])
        self.assertEqual(mm.client.post.call_count, 2)

    def test_remove_image_success(self):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        response = dict(code=200, contents={"f5-system-image:output": {"response": "specified images removed"}})
        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.post = Mock(return_value=response)

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_remove_image_response_error(self):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        response = dict(code=400, contents=load_fixture('partition_image_remove_fail.json'))
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=response)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('unable to get response from sw mgmt API', err.exception.args[0])

    def test_remove_image_failed(self):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        response = dict(code=200, contents={"f5-system-image:output": {"response": "specified images not removed"}})
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=response)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to remove partition ISO: 1.1.0-3198 specified images not removed', err.exception.args[0])

    @patch.object(velos_partition_image, 'Connection')
    @patch.object(velos_partition_image.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            velos_partition_image.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(velos_partition_image, 'Connection')
    @patch.object(velos_partition_image.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            velos_partition_image.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            image_name='F5OS-C-1.1.0-3198.PARTITION.iso',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=200), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=201), dict(code=404), dict(code=401, contents='access denied')])

        res1 = mm.is_imported()
        self.assertTrue(res1)

        res2 = mm.is_imported()
        self.assertFalse(res2)

        with self.assertRaises(F5ModuleError) as err1:
            mm.is_imported()
        self.assertIn('server error', err1.exception.args[0])

        res3 = mm.exists()
        self.assertTrue(res3)

        res4 = mm.exists()
        self.assertFalse(res4)

        with self.assertRaises(F5ModuleError) as err2:
            mm.exists()

        self.assertIn('access denied', err2.exception.args[0])

        mm.client.post = Mock(return_value=dict(code=400, contents='server error'))

        with self.assertRaises(F5ModuleError) as err3:
            mm.check_file_transfer_status()

        self.assertIn('server error', err3.exception.args[0])

        mm.exists = Mock(side_effect=[True, True, False, True])
        mm.remove_from_device = Mock(return_value=True)

        res5 = mm.import_image()
        self.assertFalse(res5)

        res6 = mm.present()
        self.assertFalse(res6)

        res7 = mm.absent()
        self.assertFalse(res7)

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove()
        self.assertIn('Failed to delete the resource.', err4.exception.args[0])
