# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_primarykey
from ansible_collections.f5networks.f5os.plugins.modules.f5os_primarykey import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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


class TestModuleParameters(unittest.TestCase):

    def test_module_parameters_full(self):
        args = dict(
            passphrase='test-passphrase',
            salt='test-salt',
            force_update=False,
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.passphrase, 'test-passphrase')
        self.assertEqual(p.salt, 'test-salt')

    def test_module_parameters_none_passphrase(self):
        args = dict(
            passphrase=None,
            salt='test-salt',
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertIsNone(p.passphrase)

    def test_module_parameters_none_salt(self):
        args = dict(
            passphrase='test-passphrase',
            salt=None,
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertIsNone(p.salt)

    def test_api_parameters_empty(self):
        p = ApiParameters(params=dict())

        self.assertIsNone(p.passphrase)
        self.assertIsNone(p.salt)


class TestManager(unittest.TestCase):
    """Tests for ModuleManager.

    Note: Changes, Difference, and _update_changed_options are marked
    # pragma: no cover in the module source. We still exercise them
    indirectly where possible but they are excluded from coverage metrics.
    """

    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_primarykey.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.mock_module_helper.stop()

    @patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_primarykey.time.sleep', Mock())
    def test_create_primary_key(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404))
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.post.assert_called_once()
        payload = mm.client.post.call_args[1]['data']
        self.assertEqual(payload['f5-primary-key:passphrase'], 'test-passphrase')
        self.assertEqual(payload['f5-primary-key:confirm-passphrase'], 'test-passphrase')
        self.assertEqual(payload['f5-primary-key:salt'], 'test-salt')
        self.assertEqual(payload['f5-primary-key:confirm-salt'], 'test-salt')

    @patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_primarykey.time.sleep', Mock())
    def test_create_primary_key_force_update(self, *args):
        """force_update=True triggers create even when key already exists."""
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            force_update=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        current = load_fixture('f5os_primarykey_complete.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=current))
        mm.client.post = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        mm.client.post.assert_called_once()

    def test_primary_key_already_exists_no_change(self, *args):
        """Idempotent: key exists, force_update=False → no change."""
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        current = load_fixture('f5os_primarykey_complete.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        results = mm.exec_module()

        # present() returns None when exists() is True and force_update is False
        self.assertFalse(results['changed'])

    def test_state_absent_key_exists(self, *args):
        """state=absent when key exists — remove() is a no-op (returns None)."""
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        current = load_fixture('f5os_primarykey_complete.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        results = mm.exec_module()

        # remove() is pass — returns None which is falsy
        self.assertFalse(results['changed'])

    def test_state_absent_key_does_not_exist(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_exists_returns_true(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        current = load_fixture('f5os_primarykey_complete.json')
        mm.client.get = Mock(return_value=dict(code=200, contents=current))

        self.assertTrue(mm.exists())

    def test_exists_returns_false_404(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404))

        self.assertFalse(mm.exists())

    def test_exists_returns_false_no_state_key(self, *args):
        """API returns 200 but no 'state' in response."""
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'f5-primary-key:primary-key': {}}
        ))

        self.assertFalse(mm.exists())

    def test_exists_returns_false_status_not_complete(self, *args):
        """API returns 200 with state but status is not COMPLETE."""
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents={'f5-primary-key:primary-key': {'state': {'status': 'PENDING'}}}
        ))

        self.assertFalse(mm.exists())

    def test_exists_returns_false_passphrase_and_salt_none(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # Unreachable via normal execution (ArgumentSpec has required=True for both),
        # but exercises the defensive early-return in exists().
        mm.want._values['passphrase'] = None
        mm.want._values['salt'] = None

        self.assertFalse(mm.exists())

    def test_exists_raises_on_api_error(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='internal error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exists()

        self.assertIn('internal error', err.exception.args[0])

    @patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_primarykey.time.sleep', Mock())
    def test_create_on_device_api_error(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404))
        mm.client.post = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_remove_from_device_success(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        result = mm.remove_from_device()

        self.assertTrue(result)

    def test_remove_from_device_404(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.delete = Mock(return_value=dict(code=404))

        result = mm.remove_from_device()

        self.assertFalse(result)

    def test_remove_from_device_error(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.delete = Mock(return_value=dict(code=500, contents='delete failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.remove_from_device()

        self.assertIn('delete failed', err.exception.args[0])

    @patch.object(f5os_primarykey, 'Connection')
    @patch.object(f5os_primarykey.ModuleManager, 'exec_module', Mock(return_value={'changed': True}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_primarykey.main()

        self.assertTrue(result.exception.args[0]['changed'])

    @patch.object(f5os_primarykey, 'Connection')
    @patch.object(f5os_primarykey.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            passphrase='test-passphrase',
            salt='test-salt',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_primarykey.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
