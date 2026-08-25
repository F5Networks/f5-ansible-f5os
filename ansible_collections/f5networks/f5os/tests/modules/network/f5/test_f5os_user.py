# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import pytest

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_user
from ansible_collections.f5networks.f5os.plugins.modules.f5os_user import (
    ArgumentSpec, ModuleManager, ApiParameters, ModuleParameters,
    UsableChanges, ReportableChanges, Difference
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
    def test_module_parameters_username(self):
        args = dict(
            username='testuser',
            role='operator'
        )
        p = ModuleParameters(params=args)
        assert p.username == 'testuser'

    def test_module_parameters_role(self):
        args = dict(
            username='testuser',
            role='resource-admin'
        )
        p = ModuleParameters(params=args)
        assert p.role == 'resource-admin'

    def test_module_parameters_expiry_status(self):
        args = dict(
            username='testuser',
            role='operator',
            expiry_status='2024-12-31'
        )
        p = ModuleParameters(params=args)
        assert p.expiry_status == '2024-12-31'

    def test_module_parameters_state_default(self):
        args = dict(
            username='testuser',
            role='operator'
        )
        p = ModuleParameters(params=args)
        # state is handled by Ansible's default value, not by the Parameters class
        # The actual default comes from the ArgumentSpec
        assert p.state is None  # No state was passed, so it should be None

    def test_module_parameters_state_absent(self):
        args = dict(
            username='testuser',
            role='operator',
            state='absent'
        )
        p = ModuleParameters(params=args)
        assert p.state == 'absent'

    def test_api_parameters_username(self):
        args = {
            'username': 'testuser',
            'config': {
                'role': 'operator',
                'expiry-status': 'enabled'
            }
        }
        p = ApiParameters(params=args)
        assert p.username == 'testuser'

    def test_api_parameters_role(self):
        args = {
            'username': 'testuser',
            'config': {
                'role': 'resource-admin',
                'expiry-status': 'enabled'
            }
        }
        p = ApiParameters(params=args)
        assert p.role == 'resource-admin'

    def test_api_parameters_expiry_status(self):
        args = {
            'username': 'testuser',
            'config': {
                'role': 'operator',
                'expiry-status': 'locked'
            }
        }
        p = ApiParameters(params=args)
        assert p.expiry_status == 'locked'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_user.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_create_user(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        # Override methods to force specific logic in the module
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['username'] == 'testuser'
        assert results['role'] == 'operator'

    def test_create_user_with_expiry_status(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            expiry_status='2024-12-31'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=False)
        mm.create_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['username'] == 'testuser'
        assert results['role'] == 'operator'

    def test_update_user_role(self):
        set_module_args(dict(
            username='testuser',
            role='resource-admin'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = ApiParameters(params=dict(
            username='testuser',
            config=dict(
                role='operator',
                expiry_status='enabled'
            )
        ))

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock(return_value=current)
        mm.update_on_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['role'] == 'resource-admin'

    def test_update_user_no_change(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = ApiParameters(params=dict(
            username='testuser',
            config=dict(
                role='operator',
                expiry_status='enabled'
            )
        ))

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock(return_value=current)

        results = mm.exec_module()

        assert results['changed'] is False

    def test_delete_user(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(side_effect=[True, False])
        mm.remove_from_device = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True

    def test_delete_user_not_exists(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is False

    def test_delete_user_fails(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=True)
        mm.remove_from_device = Mock(return_value=True)

        with pytest.raises(F5ModuleError) as excinfo:
            mm.exec_module()

        assert 'Failed to delete the resource' in str(excinfo.value)


class TestManagerDeviceMethods(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_user.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_exists_true(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 200, 'contents': {}}

        result = mm.exists()
        assert result is True

    def test_exists_false(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 404}

        result = mm.exists()
        assert result is False

    def test_exists_error(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 500, 'contents': 'Server Error'}

        with pytest.raises(F5ModuleError) as excinfo:
            mm.exists()

        assert 'Server Error' in str(excinfo.value)

    def test_create_on_device_basic(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post.return_value = {'code': 201}
        mm._set_changed_options()
        result = mm.create_on_device()
        assert result is True
        # Verify the payload structure
        call_args = mm.client.post.call_args
        expected_uri = "/openconfig-system:system/aaa/authentication/f5-system-aaa:users"
        expected_payload = {
            "f5-system-aaa:user": {
                "username": "testuser",
                "config": {
                    "username": "testuser",
                    "role": "operator"
                }
            }
        }
        assert call_args[0][0] == expected_uri
        assert call_args[1]['data'] == expected_payload

    def test_create_on_device_with_expiry(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            expiry_status='2024-12-31'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post.return_value = {'code': 201}
        mm._set_changed_options()

        result = mm.create_on_device()
        assert result is True

        # Verify the payload does NOT include expiry status because
        # expiry_status is not in api_attributes, so it won't be in api_params()
        call_args = mm.client.post.call_args
        payload = call_args[1]['data']
        # The expiry-status should NOT be present due to the module's implementation
        assert 'expiry-status' not in payload['f5-system-aaa:user']['config']

    def test_create_on_device_error(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.post.return_value = {'code': 400, 'contents': 'Bad Request'}
        mm._set_changed_options()

        with pytest.raises(F5ModuleError) as excinfo:
            mm.create_on_device()

        assert 'Bad Request' in str(excinfo.value)

    def test_update_on_device(self):
        set_module_args(dict(
            username='testuser',
            role='resource-admin'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.patch.return_value = {'code': 204}
        mm.changes = UsableChanges(params={'role': 'resource-admin'})

        result = mm.update_on_device()
        assert result is True

        # Verify the correct URI and payload
        call_args = mm.client.patch.call_args
        expected_uri = "/openconfig-system:system/aaa/authentication/f5-system-aaa:users/user=testuser"
        assert call_args[0][0] == expected_uri

    def test_update_on_device_error(self):
        set_module_args(dict(
            username='testuser',
            role='resource-admin'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.patch.return_value = {'code': 400, 'contents': 'Bad Request'}
        mm.changes = UsableChanges(params={'role': 'resource-admin'})

        with pytest.raises(F5ModuleError) as excinfo:
            mm.update_on_device()

        assert 'Bad Request' in str(excinfo.value)

    def test_remove_from_device(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.delete.return_value = {'code': 204}

        result = mm.remove_from_device()
        assert result is True

        # Verify the correct URI
        call_args = mm.client.delete.call_args
        expected_uri = "/openconfig-system:system/aaa/authentication/f5-system-aaa:users/user=testuser"
        assert call_args[0][0] == expected_uri

    def test_remove_from_device_error(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.delete.return_value = {'code': 400, 'contents': 'Bad Request'}

        with pytest.raises(F5ModuleError) as excinfo:
            mm.remove_from_device()

        assert 'Bad Request' in str(excinfo.value)

    def test_read_current_from_device(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mock_response = {
            'code': 200,
            'contents': {
                'f5-system-aaa:user': [{
                    'username': 'testuser',
                    'config': {
                        'role': 'operator',
                        'expiry-status': 'enabled'
                    }
                }]
            }
        }

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = mock_response

        result = mm.read_current_from_device()
        assert isinstance(result, ApiParameters)
        assert result.username == 'testuser'
        assert result.role == 'operator'

    def test_read_current_from_device_error(self):
        set_module_args(dict(
            username='testuser',
            role='operator'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.client.get.return_value = {'code': 400, 'contents': 'Bad Request'}

        with pytest.raises(F5ModuleError) as excinfo:
            mm.read_current_from_device()

        assert 'Bad Request' in str(excinfo.value)


class TestCheckMode(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_user.send_teem')
        self.m1 = self.p1.start()
        self.m1.return_value = True

    def tearDown(self):
        self.p1.stop()

    def test_create_user_check_mode(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            _ansible_check_mode=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['username'] == 'testuser'
        assert results['role'] == 'operator'

    def test_update_user_check_mode(self):
        set_module_args(dict(
            username='testuser',
            role='resource-admin',
            _ansible_check_mode=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        current = ApiParameters(params=dict(
            username='testuser',
            config=dict(
                role='operator',
                expiry_status='enabled'
            )
        ))

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock(return_value=current)

        results = mm.exec_module()

        assert results['changed'] is True
        assert results['role'] == 'resource-admin'

    def test_delete_user_check_mode(self):
        set_module_args(dict(
            username='testuser',
            role='operator',
            state='absent',
            _ansible_check_mode=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client = Mock()
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        assert results['changed'] is True


class TestDifferenceClass(unittest.TestCase):

    def test_compare_role_different(self):
        want = ModuleParameters(params={'username': 'test', 'role': 'admin'})
        have = ApiParameters(params={
            'username': 'test',
            'config': {'role': 'operator', 'expiry-status': 'enabled'}
        })
        diff = Difference(want, have)
        result = diff.compare('role')
        assert result == 'admin'

    def test_compare_role_same(self):
        want = ModuleParameters(params={'username': 'test', 'role': 'operator'})
        have = ApiParameters(params={
            'username': 'test',
            'config': {'role': 'operator', 'expiry-status': 'enabled'}
        })

        diff = Difference(want, have)
        result = diff.compare('role')
        assert result is None

    def test_compare_nonexistent_param(self):
        want = ModuleParameters(params={'username': 'test', 'role': 'admin'})
        have = ApiParameters(params={
            'username': 'test',
            'config': {'role': 'operator', 'expiry-status': 'enabled'}
        })
        diff = Difference(want, have)
        result = diff.compare('nonexistent')
        assert result is None


class TestChangesClass(unittest.TestCase):

    def test_usable_changes_to_return(self):
        changes = UsableChanges(params={'username': 'test', 'role': 'admin'})
        result = changes.to_return()
        assert 'username' in result
        assert 'role' in result
        assert result['username'] == 'test'
        assert result['role'] == 'admin'

    def test_reportable_changes_to_return(self):
        changes = ReportableChanges(params={'username': 'test', 'role': 'admin'})
        result = changes.to_return()
        assert 'username' in result
        assert 'role' in result
        assert result['username'] == 'test'
        assert result['role'] == 'admin'


class TestArgumentSpec(unittest.TestCase):

    def test_argument_spec_required_args(self):
        spec = ArgumentSpec()
        assert 'username' in spec.argument_spec
        assert 'role' in spec.argument_spec
        assert spec.argument_spec['username']['required'] is True
        assert spec.argument_spec['role']['required'] is True

    def test_argument_spec_optional_args(self):
        spec = ArgumentSpec()
        assert 'expiry_status' in spec.argument_spec
        assert 'state' in spec.argument_spec
        assert spec.argument_spec['state']['default'] == 'present'
        assert 'present' in spec.argument_spec['state']['choices']
        assert 'absent' in spec.argument_spec['state']['choices']

    def test_supports_check_mode(self):
        spec = ArgumentSpec()
        assert spec.supports_check_mode is True


class TestMain(unittest.TestCase):
    def setUp(self):
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.mock_module_helper.stop()

    @patch.object(f5os_user, 'Connection')
    @patch.object(f5os_user.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            username='testuser',
            role='operator',
        ))

        with pytest.raises(AnsibleExitJson) as result:
            f5os_user.main()

        assert result.value.args[0]['changed'] is False

    @patch.object(f5os_user, 'Connection')
    @patch.object(f5os_user.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            username='testuser',
            role='operator',
        ))

        with pytest.raises(AnsibleFailJson) as result:
            f5os_user.main()

        assert result.value.args[0]['failed']
        assert 'This module has failed' in result.value.args[0]['msg']
