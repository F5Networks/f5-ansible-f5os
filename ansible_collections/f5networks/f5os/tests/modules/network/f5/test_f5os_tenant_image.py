# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_tenant_image
from ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_image import (
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
            image_name='BIGIP-bigip.ALL-VELOS.qcow2.zip',
            remote_host='1.2.3.4',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/',
            protocol='https',
            local_path='images',
            state='present',
            timeout=600
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.image_name, 'BIGIP-bigip.ALL-VELOS.qcow2.zip')
        self.assertEqual(p.remote_host, '1.2.3.4')
        self.assertEqual(p.remote_user, 'admin')
        self.assertEqual(p.remote_password, 'admin')
        self.assertEqual(p.remote_path, '/test/BIGIP-bigip.ALL-VELOS.qcow2.zip')
        self.assertEqual(p.local_path, 'images')
        self.assertEqual(p.protocol, 'https')
        self.assertEqual(p.state, 'present')
        self.assertTupleEqual(p.timeout, (6.0, 100))

    def test_module_parameter_failures(self):
        args = dict(
            timeout=100
        )
        p = ModuleParameters(params=args)

        self.assertIsNone(p.remote_path)

        with self.assertRaises(F5ModuleError) as err:
            p.timeout()

        self.assertIn('Timeout value must be between 150 and 3600 seconds.', err.exception.args[0])

    def test_alternative_module_parameter_choices(self):
        args = dict(
            image_name='BIGIP-bigip.ALL-VELOS.qcow2.zip',
            remote_path='/test/BIGIP-bigip.ALL-VELOS.qcow2.zip'
        )

        p = ModuleParameters(params=args)

        self.assertIn('/test/BIGIP-bigip.ALL-VELOS.qcow2.zip', p.remote_path)
        self.assertIsNone(p.remote_host)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_image.F5Client')
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p3 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_image.send_teem')
        self.m3 = self.p3.start()
        self.m3.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_import_image(self, *args):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            remote_host='fake.imageserver.foo.bar.com',
            remote_user='admin',
            local_path='images',
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
                               'remote-file': '/test/BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
                               'username': 'admin', 'password': 'admin', 'local-file': 'images', 'insecure': ''}]
                    }
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=200, contents=dict(load_fixture('start_image_import.json'))))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(mm.client.post.call_args[1]['data'], expected)
        self.assertEqual(results['image_name'], 'BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip')
        self.assertEqual(results['remote_path'], '/test/BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip')
        self.assertEqual(
            results['message'], 'Image BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip import started.'
        )

    def test_import_image_progress_check(self, *args):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            remote_host='fake.imageserver.foo.bar.com',
            local_path='images',
            remote_path='/test/',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )
        progress_82 = dict(code=200, contents=load_fixture('f5os_tenant_image_upload_progress.json'))
        complete = dict(code=200, contents=load_fixture('f5os_tenant_image_upload_complete.json'))
        replicated = dict(code=200, contents={"f5-tenant-images:status": "replicated"})

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[progress_82, complete, replicated])
        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertIn('import successful', results['message'])
        self.assertTrue(mm.client.get.call_count == 3)

    def test_image_imported_failed_verification(self):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            remote_host='fake.imageserver.foo.bar.com',
            local_path='images',
            remote_path='/test/',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        complete = dict(code=200, contents=load_fixture('f5os_tenant_image_upload_complete.json'))
        importing = dict(code=200, contents={"f5-tenant-images:status": "importing"})
        verifying = dict(code=200, contents={"f5-tenant-images:status": "verifying"})
        failed = dict(code=200, contents={"f5-tenant-images:status": "verification-failed"})

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(side_effect=[complete, importing, complete, verifying, complete, failed])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('failed signature verification', err.exception.args[0])
        self.assertTrue(mm.client.get.call_count == 6)

    def test_remove_image(self):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        response = dict(code=200, contents={"f5-tenant-images:output": {"result": "Successful."}})
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(side_effect=[True, False])
        mm.client.post = Mock(return_value=response)

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_image_import_failed(self):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            remote_host='fake.imageserver.foo.bar.com',
            remote_user='admin',
            remote_password='admin',
            remote_path='/test/',
            local_path='images',
            state='import',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.post = Mock(return_value=dict(code=400, contents={'operation failed'}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to import tenant image', err.exception.args[0])

    def test_remove_image_failed(self):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        response = dict(code=200, contents={"f5-tenant-images:output": {"result": "Failed."}})
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=response)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to remove tenant image', err.exception.args[0])

    def test_remove_image_failed_server_error(self):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        response = dict(code=500, contents='server error')
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.post = Mock(return_value=response)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_upload_image_failed(self):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            remote_host='fake.imageserver.foo.bar.com',
            remote_path='/test/',
            local_path='images',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture('f5os_tenant_image_upload_failed.json')))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Peer certificate cannot be authenticated with given CA certificates', err.exception.args[0])

    def test_upload_image_did_not_start(self):
        set_module_args(dict(
            image_name='foobar.iso',
            remote_host='fake.foo.bar.com',
            remote_path='/test/',
            local_path='images',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=False)
        mm.client.get = Mock(return_value=dict(
            code=200, contents=load_fixture('f5os_tenant_image_upload_complete.json'))
        )
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('File upload job not has not started', err.exception.args[0])

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.is_velos_controller = Mock(return_value=True)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Target device is a VELOS controller', err.exception.args[0])

    @patch.object(ModuleParameters, 'timeout', new_callable=PropertyMock)
    def test_import_image_progress_check_timeout(self, mock_timeout):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            remote_host='fake.imageserver.foo.bar.com',
            local_path='images',
            remote_path='/test/',
            state='present'

        ))
        mock_timeout.return_value = (1, 2)
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.is_imported = Mock(return_value=False)
        mm.is_still_uploading = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Module timeout reached, state change is unknown', err.exception.args[0])

    @patch.object(f5os_tenant_image, 'Connection')
    @patch.object(f5os_tenant_image.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            state='absent',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_tenant_image.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_tenant_image, 'Connection')
    @patch.object(f5os_tenant_image.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            image_name='BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_tenant_image.main()

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

        mm.client.get = Mock(side_effect=[dict(code=204), dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=201, contents={'f5-tenant-images:status': 'verified'}),
                                          dict(code=404), dict(code=401, contents='access denied'), dict(code=204),
                                          dict(code=500, contents='server crashed')])

        res1 = mm.is_imported()
        self.assertFalse(res1)

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

        res5 = mm.is_still_uploading()
        self.assertFalse(res5)

        with self.assertRaises(F5ModuleError) as err3:
            mm.is_still_uploading()
        self.assertIn('server crashed', err3.exception.args[0])

        mm.exists = Mock(side_effect=[True, True, False, True])
        mm.remove_from_device = Mock(return_value=True)

        res6 = mm.import_image()
        self.assertFalse(res6)

        res7 = mm.present()
        self.assertFalse(res7)

        res8 = mm.absent()
        self.assertFalse(res8)

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove()
        self.assertIn('Failed to delete the resource.', err4.exception.args[0])
