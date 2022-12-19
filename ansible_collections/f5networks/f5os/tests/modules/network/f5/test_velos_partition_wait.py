# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import paramiko

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import velos_partition_wait
from ansible_collections.f5networks.f5os.plugins.modules.velos_partition_wait import (
    Parameters, ArgumentSpec, ModuleManager
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
            name='foo2',
            delay=3,
            state='running',
            timeout=50,
            sleep=10,
            msg='We timed out during waiting for partition :-('
        )

        p = Parameters(params=args)

        self.assertEqual('foo2', p.name)
        self.assertEqual('running', p.state)
        self.assertEqual(3, p.delay)
        self.assertEqual(50, p.timeout)
        self.assertEqual(10, p.sleep)
        self.assertEqual('We timed out during waiting for partition :-(', p.msg)


class TestModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition_wait.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition_wait.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def teardown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_wait_running(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            timeout=100,
            delay=1
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        # Simulate the tenant is not present until the 3rd loop iteration at
        # which time it is present and in the configured state.
        mm.partition_exists = Mock(side_effect=[False, False, True])
        configured_state = load_fixture('load_partition_status_provisioned.json')
        mm.read_partition_from_device = Mock(return_value=configured_state)

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertTrue(mm.partition_exists.called)
        self.assertTrue(mm.read_partition_from_device.called)

    def test_wait_ssh_ready(self, *args):
        set_module_args(dict(
            name='foo',
            state='ssh-ready',
            timeout=100,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.partition_exists = Mock(side_effect=[True, True])
        deployed_state = load_fixture('load_partition_status_provisioned.json')
        mm.read_partition_from_device = Mock(return_value=deployed_state)

        # Simulate the first ssh connection attempt raises an SSHException
        # indicating ssh is not ready, followed by a second connection which
        # raises AuthenticationException, indicating ssh server is up.
        with patch.object(paramiko, 'SSHClient', autospec=True) as mock_ssh:
            mocked_client = Mock()
            attrs = {
                'connect.side_effect': [
                    paramiko.ssh_exception.SSHException,
                    paramiko.ssh_exception.AuthenticationException
                ]
            }
            mocked_client.configure_mock(**attrs)
            mock_ssh.return_value = mocked_client

            results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.partition_exists.call_count, 2)
        self.assertEqual(mocked_client.connect.call_count, 2)

    def test_wait_ssh_ready_ipv6(self, *args):
        set_module_args(dict(
            name='foo',
            state='ssh-ready',
            timeout=100,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.partition_exists = Mock(side_effect=[True, True])
        deployed_state = load_fixture('load_partition_status_provisioned_ipv6.json')
        mm.read_partition_from_device = Mock(return_value=deployed_state)

        # Simulate the first ssh connection attempt raises an SSHException
        # indicating ssh is not ready, followed by a second connection which
        # raises AuthenticationException, indicating ssh server is up.
        with patch.object(paramiko, 'SSHClient', autospec=True) as mock_ssh:
            mocked_client = Mock()
            attrs = {
                'connect.side_effect': [
                    paramiko.ssh_exception.SSHException,
                    paramiko.ssh_exception.AuthenticationException
                ]
            }
            mocked_client.configure_mock(**attrs)
            mock_ssh.return_value = mocked_client

            results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.partition_exists.call_count, 2)
        self.assertEqual(mocked_client.connect.call_count, 2)

    def test_wait_ssh_ready_no_auth_exception(self, *args):
        set_module_args(dict(
            name='foo',
            state='ssh-ready',
            timeout=100,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.partition_exists = Mock(side_effect=[True, True])
        deployed_state = load_fixture('load_partition_status_provisioned.json')
        mm.read_partition_from_device = Mock(return_value=deployed_state)

        # Simulate the first ssh connection attempt raises an SSHException
        # indicating ssh is not ready, followed by a second connection which
        # raises AuthenticationException, indicating ssh server is up.
        with patch.object(paramiko, 'SSHClient', autospec=True) as mock_ssh:
            mocked_client = Mock()
            attrs = {
                'connect.side_effect': [
                    paramiko.ssh_exception.SSHException,
                    True
                ]
            }
            mocked_client.configure_mock(**attrs)
            mock_ssh.return_value = mocked_client

            results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.partition_exists.call_count, 2)
        self.assertEqual(mocked_client.connect.call_count, 2)

    def test_timeout_elapsed(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            timeout=2
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.partition_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(AnsibleFailJson) as err:
            mm.exec_module()

        self.assertIn('Timeout waiting for desired partition state', err.exception.args[0]['msg'])

    def test_invalid_timeout(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            delay=1,
            sleep=3,
            timeout=2
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.partition_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('The combined delay and sleep should not be greater than', err.exception.args[0])

    def test_invalid_delay_timeout(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            delay=2,
            sleep=2,
            timeout=1
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.partition_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('The delay should not be greater than or equal to the timeout', err.exception.args[0])

    @patch.object(velos_partition_wait, 'Connection')
    @patch.object(velos_partition_wait.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            timeout=2
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            velos_partition_wait.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(velos_partition_wait, 'Connection')
    @patch.object(velos_partition_wait.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            timeout=2
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            velos_partition_wait.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(velos_partition_wait, 'Connection')
    @patch.object(velos_partition_wait.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_paramiko_missing(self, *args):
        set_module_args(dict(
            name='foo',
            state='running',
            timeout=2
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            velos_partition_wait.HAS_PARAMIKO = False
            velos_partition_wait.PARAMIKO_IMPORT_ERROR = ImportError('Failed to import paramiko package.')
            velos_partition_wait.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('Failed to import the required Python library (paramiko)', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='foo',
            state='running',
            timeout=100
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        self.m1.return_value.get.side_effect = [
            dict(code=404), dict(code=401, contents='access denied'),
            dict(code=202), dict(code=200, contents={'f5-system-partition:partition': ['foobar']}),
            dict(code=400, contents='server error')]

        r1 = mm.partition_is_removed()
        self.assertTrue(r1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.partition_exists()
        self.assertIn('access denied', err1.exception.args[0])

        r3 = mm.partition_exists()
        self.assertTrue(r3)

        foo1 = mm.read_partition_from_device()
        self.assertIn('foobar', foo1)

        with self.assertRaises(F5ModuleError) as err2:
            mm.read_partition_from_device()

        self.assertIn('server error', err2.exception.args[0])
