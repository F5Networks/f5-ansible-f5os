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
