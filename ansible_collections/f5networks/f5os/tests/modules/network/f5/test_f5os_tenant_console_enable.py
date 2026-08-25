# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import os
from unittest.mock import MagicMock, patch

from ansible.module_utils import basic
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes
import pytest

# from ansible_collections.f5networks.f5os.plugins.modules import f5os_tenant_console_enable
from ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_console_enable import (
    ApiParameters, ModuleParameters, ModuleManager, ArgumentSpec
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.plugins.modules import f5os_tenant_console_enable


fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)
    with open(path) as f:
        data = f.read()
    try:
        data = json.loads(data)
    except Exception:
        pass
    return data


def set_module_args(args):
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)
    if hasattr(basic, '_ANSIBLE_PROFILE'):
        basic._ANSIBLE_PROFILE = 'legacy'


class TestParameters:
    def test_module_parameters(self):
        args = dict(
            tenant_username='test_tenant',
            role='tenant-console',
            state='enabled'
        )
        p = ModuleParameters(params=args)
        assert p.tenant_username == 'test_tenant'
        assert p.role == 'tenant-console'
        assert p.expiry_status == 'enabled'

    def test_api_parameters(self):
        args = dict(
            username='test_tenant',
            config={
                'role': 'tenant-console',
                'expiry-status': 'enabled'
            }
        )
        p = ApiParameters(params=args)
        assert p.tenant_username == 'test_tenant'
        assert p.role == 'tenant-console'
        assert p.expiry_status == 'enabled'


class TestManager:
    def setup_module(self):
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=MagicMock(return_value=True),
                                                 fail_json=MagicMock(return_value=True))
        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)

    def test_enable_tenant_console(self, *args):
        set_module_args(dict(
            tenant_username='test_tenant',
            role='tenant-console',
            state='enabled'
        ))
        module = AnsibleModule(
            argument_spec=ArgumentSpec().argument_spec,
            supports_check_mode=True
        )
        # Mock exists method to return True
        mm = ModuleManager(module=module)
        mm.exists = MagicMock(return_value=True)

        # Mock read_current_from_device
        mm.read_current_from_device = MagicMock(return_value=ApiParameters(
            params=dict(
                username='test_tenant',
                config={
                    'role': 'tenant-console',
                    'expiry-status': 'enabled'
                }
            )
        ))
        # Mock update_on_device
        mm.update_on_device = MagicMock(return_value=True)
        results = mm.exec_module()
        assert results['changed'] is True
        # assert results['expiry_status'] == 'enabled'
        assert mm.update_on_device.called

    def test_lock_tenant_console(self, *args):
        set_module_args(dict(
            tenant_username='test_tenant',
            role='tenant-console',
            state='locked'
        ))
        module = AnsibleModule(
            argument_spec=ArgumentSpec().argument_spec,
            supports_check_mode=True
        )
        # Mock exists method to return True
        mm = ModuleManager(module=module)
        mm.exists = MagicMock(return_value=True)
        # Mock read_current_from_device
        mm.read_current_from_device = MagicMock(return_value=ApiParameters(
            params=dict(
                username='test_tenant',
                config={
                    'role': 'tenant-console',
                    'expiry-status': 'enabled'
                }
            )
        ))
        # Mock update_on_device
        mm.update_on_device = MagicMock(return_value=True)
        results = mm.exec_module()
        assert results['changed'] is True
        assert results['expiry_status'] == 'locked'
        assert mm.update_on_device.called

    def test_no_change_needed(self, *args):
        set_module_args(dict(
            tenant_username='test_tenant',
            role='tenant-console',
            state='enabled'
        ))
        module = AnsibleModule(
            argument_spec=ArgumentSpec().argument_spec,
            supports_check_mode=True
        )
        # Mock exists method to return True
        mm = ModuleManager(module=module)
        mm.exists = MagicMock(return_value=True)
        # Mock read_current_from_device - already in desired state
        mm.read_current_from_device = MagicMock(return_value=ApiParameters(
            params=dict(
                username='test_tenant',
                config={
                    'role': 'tenant-console',
                    'expiry-status': 'enabled'
                }
            )
        ))
        # Override should_update to return False
        mm.should_update = MagicMock(return_value=False)
        results = mm.exec_module()
        assert results['changed'] is False

    def test_create_tenant_console(self, *args):
        set_module_args(dict(
            tenant_username='new_tenant',
            role='tenant-console',
            state='enabled'
        ))
        module = AnsibleModule(
            argument_spec=ArgumentSpec().argument_spec,
            supports_check_mode=True
        )
        # Mock exists method to return False (tenant doesn't exist)
        mm = ModuleManager(module=module)
        mm.exists = MagicMock(return_value=False)
        # Mock create method
        mm.create = MagicMock(return_value=True)
        results = mm.exec_module()
        assert results['changed'] is True
        assert mm.create.called

    def test_error_handling(self, *args):
        set_module_args(dict(
            tenant_username='test_tenant',
            role='tenant-console',
            state='enabled'
        ))
        module = AnsibleModule(
            argument_spec=ArgumentSpec().argument_spec,
            supports_check_mode=True
        )
        # Mock exists method to raise an error
        mm = ModuleManager(module=module)
        mm.exists = MagicMock(side_effect=F5ModuleError('Test error'))
        with pytest.raises(F5ModuleError) as ex:
            mm.exec_module()

    def test_exists_true(self):
        set_module_args(dict(tenant_username='test', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=200, contents={}))
        assert mm.exists() is True

    def test_exists_false(self):
        set_module_args(dict(tenant_username='test', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=404, contents={}))
        assert mm.exists() is False

    def test_exists_error(self):
        set_module_args(dict(tenant_username='test', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=500, contents='server error'))
        with pytest.raises(F5ModuleError):
            mm.exists()

    def test_create_on_device(self):
        set_module_args(dict(tenant_username='newuser', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.patch = MagicMock(return_value=dict(code=204, contents={}))
        mm.exists = MagicMock(return_value=False)
        results = mm.exec_module()
        assert results['changed'] is True

    def test_create_with_password(self):
        set_module_args(dict(tenant_username='newuser', console_user_password='pass123', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.patch = MagicMock(return_value=dict(code=204, contents={}))
        mm.client.post = MagicMock(return_value=dict(code=204, contents={}))
        mm.exists = MagicMock(return_value=False)
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_console_enable.time.sleep'):
            results = mm.exec_module()
        assert results['changed'] is True
        mm.client.post.assert_called_once()

    def test_create_fails(self):
        set_module_args(dict(tenant_username='newuser', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.patch = MagicMock(return_value=dict(code=500, contents='error'))
        mm.exists = MagicMock(return_value=False)
        with pytest.raises(F5ModuleError):
            mm.exec_module()

    def test_update_on_device(self):
        set_module_args(dict(tenant_username='test', state='locked'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=200, contents={
            'f5-system-aaa:user': [{'username': 'test', 'config': {'role': 'tenant-console', 'expiry-status': 'enabled'}}]
        }))
        mm.client.patch = MagicMock(return_value=dict(code=204, contents={}))
        mm.exists = MagicMock(return_value=True)
        results = mm.exec_module()
        assert results['changed'] is True

    def test_update_with_password(self):
        set_module_args(dict(tenant_username='test', console_user_password='newpass', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=200, contents={
            'f5-system-aaa:user': [{'username': 'test', 'config': {'role': 'tenant-console', 'expiry-status': 'locked'}}]
        }))
        mm.client.patch = MagicMock(return_value=dict(code=204, contents={}))
        mm.client.post = MagicMock(return_value=dict(code=204, contents={}))
        mm.exists = MagicMock(return_value=True)
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_console_enable.time.sleep'):
            results = mm.exec_module()
        assert results['changed'] is True

    def test_update_password_fails(self):
        set_module_args(dict(tenant_username='test', console_user_password='newpass', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=200, contents={
            'f5-system-aaa:user': [{'username': 'test', 'config': {'role': 'tenant-console', 'expiry-status': 'locked'}}]
        }))
        mm.client.patch = MagicMock(return_value=dict(code=204, contents={}))
        mm.client.post = MagicMock(return_value=dict(code=500, contents='password error'))
        mm.exists = MagicMock(return_value=True)
        with patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_console_enable.time.sleep'):
            with pytest.raises(F5ModuleError):
                mm.exec_module()

    def test_read_current_from_device_error(self):
        set_module_args(dict(tenant_username='test', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=500, contents='read error'))
        with pytest.raises(F5ModuleError):
            mm.read_current_from_device()

    def test_update_check_mode(self):
        set_module_args(dict(tenant_username='test', state='locked', _ansible_check_mode=True))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=200, contents={
            'f5-system-aaa:user': [{'username': 'test', 'config': {'role': 'tenant-console', 'expiry-status': 'enabled'}}]
        }))
        mm.exists = MagicMock(return_value=True)
        results = mm.exec_module()
        assert results['changed'] is True

    def test_locked_not_exists(self):
        set_module_args(dict(tenant_username='test', state='locked'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.exists = MagicMock(return_value=False)
        results = mm.exec_module()
        assert results['changed'] is False

    def test_announce_deprecations(self):
        set_module_args(dict(tenant_username='test', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        result = {'__warnings': [{'msg': 'deprecated', 'version': '1.0'}]}
        mm._announce_deprecations(result)
        mm.client.module.deprecate.assert_called_once_with(msg='deprecated', version='1.0')

    @patch.object(f5os_tenant_console_enable, 'Connection')
    @patch.object(f5os_tenant_console_enable.ModuleManager, 'exec_module', MagicMock(return_value={'changed': False}))
    def test_main_success(self, *args):
        set_module_args(dict(tenant_username='test', state='enabled'))
        with pytest.raises(SystemExit) as ex:
            f5os_tenant_console_enable.main()
        assert ex.value.code == 0

    @patch.object(f5os_tenant_console_enable, 'Connection')
    @patch.object(f5os_tenant_console_enable.ModuleManager, 'exec_module',
                  MagicMock(side_effect=F5ModuleError('error')))
    def test_main_failure(self, *args):
        set_module_args(dict(tenant_username='test', state='enabled'))
        with pytest.raises(SystemExit) as ex:
            f5os_tenant_console_enable.main()
        assert ex.value.code == 1

    def test_generate_password(self):
        set_module_args(dict(tenant_username='test', state='enabled'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        pwd = mm.generate_password(16)
        assert len(pwd) == 16

    def test_create_check_mode(self):
        set_module_args(dict(tenant_username='newuser', state='enabled', _ansible_check_mode=True))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.exists = MagicMock(return_value=False)
        results = mm.exec_module()
        assert results['changed'] is True

    def test_update_on_device_patch_fails(self):
        set_module_args(dict(tenant_username='test', state='locked'))
        module = AnsibleModule(argument_spec=ArgumentSpec().argument_spec, supports_check_mode=True)
        mm = ModuleManager(module=module)
        mm.client = MagicMock()
        mm.client.get = MagicMock(return_value=dict(code=200, contents={
            'f5-system-aaa:user': [{'username': 'test', 'config': {'role': 'tenant-console', 'expiry-status': 'enabled'}}]
        }))
        mm.client.patch = MagicMock(return_value=dict(code=500, contents='update error'))
        mm.exists = MagicMock(return_value=True)
        with pytest.raises(F5ModuleError):
            mm.exec_module()
