# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import pytest

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_ntp_server
from ansible_collections.f5networks.f5os.plugins.modules.f5os_ntp_server import (
    ArgumentSpec, ModuleManager, ApiParameters, _parse_version
)

from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json, AnsibleFailJson, AnsibleExitJson
)

from ansible_collections.f5networks.f5os.plugins.module_utils.client import F5Client
from ansible_collections.f5networks.f5os.plugins.modules.f5os_ntp_server import UsableChanges

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


class TestParseVersion(unittest.TestCase):
    def test_parse_version_valid(self):
        self.assertEqual(_parse_version('2.0.0'), (2, 0, 0))
        self.assertEqual(_parse_version('2.0.0-9817'), (2, 0, 0))
        self.assertEqual(_parse_version('1.8.3'), (1, 8, 3))

    def test_parse_version_invalid_returns_zero(self):
        self.assertEqual(_parse_version('not-a-version'), (0, 0, 0))
        self.assertEqual(_parse_version(''), (0, 0, 0))


class TestParameters(unittest.TestCase):
    def test_api_parameters(self):
        args = load_fixture('ntp_server_get.json')

        p = ApiParameters(params=args['openconfig-system:server'][0])
        self.assertEqual(p.server, '10.218.33.44')
        self.assertEqual(p.key_id, 12)

    def test_api_parameters_v2_fields(self):
        args = load_fixture('ntp_server_get_v2.json')

        p = ApiParameters(params=args['openconfig-system:server'][0])
        self.assertEqual(p.association_type, 'SERVER')
        self.assertEqual(p.version, 4)
        self.assertEqual(p.port, 123)

    def test_api_parameters_v2_fields_absent(self):
        args = {'address': '1.2.3.4', 'config': {'address': '1.2.3.4'}}

        p = ApiParameters(params=args)
        self.assertIsNone(p.association_type)
        self.assertIsNone(p.version)
        self.assertIsNone(p.port)


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
        current_ntp_config = load_fixture('ntp_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[{'code': 200, 'contents': current_ntp}, {'code': 200, 'contents': current_ntp_config}])
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

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
        current_ntp_config = load_fixture('ntp_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[{'code': 200, 'contents': current_ntp}, {'code': 200, 'contents': current_ntp_config}])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.get.call_count, 2)
        self.assertEqual(mm.client.patch.call_count, 0)
        self.assertEqual(mm.client.post.call_count, 0)

    def test_create_v2_fields(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            association_type='SERVER',
            version=4,
            port=123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        server_config = post_payload['server'][0]['config']
        self.assertEqual(server_config['association-type'], 'SERVER')
        self.assertEqual(server_config['version'], 4)
        self.assertEqual(server_config['port'], 123)

    def test_create_with_prefer_iburst_ntp_service_ntp_auth(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            prefer=True,
            iburst=True,
            ntp_service=True,
            ntp_authentication=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.8.3'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        server_config = post_payload['server'][0]['config']
        self.assertTrue(server_config['prefer'])
        self.assertTrue(server_config['iburst'])
        # ntp_service and ntp_authentication trigger a separate patch to /ntp/config
        patch_payload = mm.client.patch.call_args[1]['data']
        self.assertTrue(patch_payload['config']['enabled'])
        self.assertTrue(patch_payload['config']['enable-ntp-auth'])

    def test_create_pre_v2_omits_new_fields(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            association_type='SERVER',
            version=4,
            port=123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.8.3'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        server_config = post_payload['server'][0]['config']
        self.assertNotIn('association-type', server_config)
        self.assertNotIn('version', server_config)
        self.assertNotIn('port', server_config)

    def test_update_v2_fields(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            association_type='PEER',
            version=3,
            port=1123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get_v2.json')
        current_ntp_config = load_fixture('ntp_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': current_ntp},
            {'code': 200, 'contents': current_ntp_config},
        ])
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        patch_payload = mm.client.patch.call_args[1]['data']
        server_config = patch_payload['server'][0]['config']
        self.assertEqual(server_config['association-type'], 'PEER')
        self.assertEqual(server_config['version'], 3)
        self.assertEqual(server_config['port'], 1123)

    def test_update_v2_no_change(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            association_type='SERVER',
            version=4,
            port=123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get_v2.json')
        current_ntp_config = load_fixture('ntp_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': current_ntp},
            {'code': 200, 'contents': current_ntp_config},
        ])
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 0)

    def test_update_pre_v2_omits_new_fields(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            key_id=99,
            association_type='PEER',
            version=3,
            port=1123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get.json')
        current_ntp_config = load_fixture('ntp_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.8.3'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': current_ntp},
            {'code': 200, 'contents': current_ntp_config},
        ])
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        patch_payload = mm.client.patch.call_args[1]['data']
        server_config = patch_payload['server'][0]['config']
        self.assertNotIn('association-type', server_config)
        self.assertNotIn('version', server_config)
        self.assertNotIn('port', server_config)

    def test_pre_v2_new_fields_no_error(self, *args):
        """Pre-v2: specifying new fields raises no error and reports no change."""
        set_module_args(dict(
            server='10.218.33.44',
            association_type='SERVER',
            version=4,
            port=123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get.json')
        current_ntp_config = load_fixture('ntp_config.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '1.5.0'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': current_ntp},
            {'code': 200, 'contents': current_ntp_config},
        ])
        mm.client.patch = Mock(return_value={'code': 204})

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.client.patch.call_count, 0)

    def test_version_suffix_treated_as_v2(self, *args):
        """Version string '2.0.0-9817' must be treated as >= 2.0.0."""
        set_module_args(dict(
            server='10.218.33.44',
            association_type='SERVER',
            version=4,
            port=123,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.software_version = '2.0.0-9817'
        mm.client.get = Mock(return_value={'code': 404})
        mm.client.post = Mock(return_value={'code': 201})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        server_config = post_payload['server'][0]['config']
        self.assertIn('association-type', server_config)
        self.assertIn('version', server_config)
        self.assertIn('port', server_config)

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

    def test_read_current_ntp_config_api_failure(self, *args):
        set_module_args(dict(
            server='10.218.33.44',
            key_id=32,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current_ntp = load_fixture('ntp_server_get.json')

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': current_ntp},
            {'code': 503, 'contents': 'service not available'},
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('service not available', err.exception.args[0])

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


class DummyClient(F5Client):
    def __init__(self, responses=None):
        super().__init__(module=None, client=None)
        self._responses = responses or {}
        self._calls = []

    def post(self, url, data=None, **kwargs):
        self._calls.append(('post', url, data))
        return self._responses.get(url, {'code': 201, 'contents': {}})

    def patch(self, url, data=None, **kwargs):
        self._calls.append(('patch', url, data))
        return self._responses.get(url, {'code': 200, 'contents': {}})


def test_create_on_device_ntp_patch_error():
    """create_on_device raises F5ModuleError when the ntp/config PATCH fails."""
    params = {
        'server': '1.2.3.4',
        'ntp_service': True,
        'ntp_authentication': True,
    }
    responses = {
        "/openconfig-system:system/ntp/openconfig-system:servers": {'code': 201, 'contents': {}},
        '/openconfig-system:system/ntp/config': {'code': 500, 'contents': {'error': 'fail'}},
    }

    class DummyModule:
        def __init__(self, p):
            self.params = p

    mgr = ModuleManager(module=DummyModule(params))
    mgr.client = DummyClient(responses)
    mgr.changes = UsableChanges(params=params)
    with pytest.raises(F5ModuleError):
        mgr.create_on_device()


def test_version_is_v2_or_later_exception_returns_false():
    """When client.software_version raises, _version_is_v2_or_later returns False."""
    class BrokenClient:
        @property
        def software_version(self):
            raise AttributeError('no plugin')

    class DummyModule:
        def __init__(self):
            self.params = {'server': '1.2.3.4'}

    mgr = ModuleManager(module=DummyModule())
    mgr.client = BrokenClient()
    assert mgr._version_is_v2_or_later() is False


def test_update_on_device_full_coverage():
    params = {
        'server': '1.2.3.4',
        'prefer': True,
        'iburst': True,
        'ntp_service': True,
        'ntp_authentication': True,
    }
    # Simulate all patch calls succeed
    responses = {
        "/openconfig-system:system/ntp/openconfig-system:servers/server=1.2.3.4": {'code': 200, 'contents': {}},
        '/openconfig-system:system/ntp/config': {'code': 200, 'contents': {}}
    }

    class DummyModule:
        def __init__(self, params):
            self.params = params
    dummy_module = DummyModule(params)
    mgr = ModuleManager(module=dummy_module)
    mgr.client = DummyClient(responses)
    mgr.changes = UsableChanges(params=params)
    assert mgr.update_on_device() is True


def test_update_on_device_patch_error():
    params = {
        'server': '1.2.3.4',
        'prefer': True,
        'iburst': True,
        'ntp_service': True,
        'ntp_authentication': True,
    }
    # Simulate first patch call fails
    responses = {
        "/openconfig-system:system/ntp/openconfig-system:servers/server=1.2.3.4": {'code': 500, 'contents': {'error': 'fail'}},
    }

    class DummyModule:
        def __init__(self, params):
            self.params = params
    dummy_module = DummyModule(params)
    mgr = ModuleManager(module=dummy_module)
    mgr.client = DummyClient(responses)
    mgr.changes = UsableChanges(params=params)
    with pytest.raises(F5ModuleError):
        mgr.update_on_device()


def test_update_on_device_ntp_patch_error():
    params = {
        'server': '1.2.3.4',
        'prefer': True,
        'iburst': True,
        'ntp_service': True,
        'ntp_authentication': True,
    }
    # Simulate ntp config patch call fails
    responses = {
        "/openconfig-system:system/ntp/openconfig-system:servers/server=1.2.3.4": {'code': 200, 'contents': {}},
        '/openconfig-system:system/ntp/config': {'code': 500, 'contents': {'error': 'fail'}}
    }

    class DummyModule:
        def __init__(self, params):
            self.params = params
    dummy_module = DummyModule(params)
    mgr = ModuleManager(module=dummy_module)
    mgr.client = DummyClient(responses)
    mgr.changes = UsableChanges(params=params)
    with pytest.raises(F5ModuleError):
        mgr.update_on_device()
