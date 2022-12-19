# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import paramiko

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_tenant_wait
from ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_wait import (
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
            name='tenant1',
            delay=3,
            state='ssh-ready',
            timeout=500,
            sleep=10,
            msg='We timed out during waiting for Tenant :-('
        )

        p = Parameters(params=args)

        self.assertEqual(p.name, 'tenant1')
        self.assertEqual(p.state, 'ssh-ready')
        self.assertEqual(p.delay, 3)
        self.assertEqual(p.timeout, 500)
        self.assertEqual(p.sleep, 10)
        self.assertEqual(p.msg, 'We timed out during waiting for Tenant :-(')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_wait.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_tenant_wait.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_wait_configured(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
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
        mm.tenant_exists = Mock(side_effect=[False, True, True])
        not_configured_state = load_fixture('load_tenant_state_configured_no_status.json')
        configured_state = load_fixture('load_tenant_state_configured.json')
        mm.read_tenant_from_device = Mock(side_effect=[not_configured_state, configured_state])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertGreaterEqual(results['elapsed'], 2)
        self.assertTrue(mm.tenant_exists.called)
        self.assertTrue(mm.read_tenant_from_device.called)

    def test_wait_provisioned(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='provisioned'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        configured_state = load_fixture('load_tenant_state_configured.json')
        provisioned_state = load_fixture('load_tenant_state_provisioned.json')
        mm.read_tenant_from_device = Mock(side_effect=[configured_state, provisioned_state])
        mm.client.platform = 'rSeries'

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.tenant_exists.call_count, 2)
        self.assertEqual(mm.read_tenant_from_device.call_count, 2)

    def test_wait_deployed(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='deployed'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        provisioned_state = load_fixture('load_tenant_state_provisioned.json')
        deployed_state = load_fixture('load_tenant_state_deployed.json')
        mm.read_tenant_from_device = Mock(side_effect=[provisioned_state, deployed_state])
        mm.client.platform = 'rSeries'

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(mm.tenant_exists.call_count, 2)
        self.assertEqual(mm.read_tenant_from_device.call_count, 2)

    def test_wait_ssh_ready(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='ssh-ready'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        deployed_state = load_fixture('load_tenant_state_deployed.json')
        mm.read_tenant_from_device = Mock(return_value=deployed_state)
        mm.client.platform = 'rSeries'

        # Simulate the first ssh connection attempt raises an SSHExecption
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
        self.assertEqual(mm.tenant_exists.call_count, 2)
        self.assertEqual(mocked_client.connect.call_count, 2)

    def test_wait_ssh_ready_no_auth_exception(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='ssh-ready'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[True, True])
        deployed_state = load_fixture('load_tenant_state_deployed.json')
        mm.read_tenant_from_device = Mock(return_value=deployed_state)
        mm.client.platform = 'rSeries'

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
        self.assertEqual(mm.tenant_exists.call_count, 2)
        self.assertEqual(mocked_client.connect.call_count, 2)

    def test_timeout_elapsed(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
            timeout=2
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.tenant_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(AnsibleFailJson) as err:
            mm.exec_module()

        self.assertIn('Timeout waiting for desired tenant state', err.exception.args[0]['msg'])

    def test_invalid_timeout(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
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
        mm.client.platform = 'rSeries'
        mm.tenant_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('The combined delay and sleep should not be greater than', err.exception.args[0])

    def test_invalid_delay_timeout(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured',
            delay=2,
            sleep=2,
            timeout=1,

        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries'
        mm.tenant_exists = Mock(side_effect=[False, False, False])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('The delay should not be greater than or equal to the timeout', err.exception.args[0])

    def test_invalid_platform_raises(self, *args):
        set_module_args(dict(
            name='defaultbip',
            state='configured'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Target device is a VELOS controller, aborting', err.exception.args[0])

    @patch.object(f5os_tenant_wait, 'Connection')
    @patch.object(f5os_tenant_wait.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foo',
            state='provisioned',
            timeout=2
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_tenant_wait.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_tenant_wait, 'Connection')
    @patch.object(f5os_tenant_wait.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foo',
            state='provisioned',
            timeout=2
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_tenant_wait.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(f5os_tenant_wait, 'Connection')
    @patch.object(f5os_tenant_wait.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_paramiko_missing(self, *args):
        set_module_args(dict(
            name='foo',
            state='provisioned',
            timeout=2
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_tenant_wait.HAS_PARAMIKO = False
            f5os_tenant_wait.PARAMIKO_IMPORT_ERROR = ImportError('Failed to import paramiko package.')
            f5os_tenant_wait.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('Failed to import the required Python library (paramiko)', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='foo',
            state='provisioned',
            timeout=100
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        self.m1.return_value.get.side_effect = [
            dict(code=404), dict(code=401, contents='access denied'),
            dict(code=202), dict(code=200, contents={'f5-tenants:tenant': ['foobar']}),
            dict(code=400, contents='server error')]

        res1 = mm.tenant_exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.tenant_exists()
        self.assertIn('access denied', err1.exception.args[0])

        r3 = mm.tenant_exists()
        self.assertTrue(r3)

        foo1 = mm.read_tenant_from_device()
        self.assertIn('foobar', foo1)

        with self.assertRaises(F5ModuleError) as err2:
            mm.read_tenant_from_device()

        self.assertIn('server error', err2.exception.args[0])
