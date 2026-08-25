# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_logging
from ansible_collections.f5networks.f5os.plugins.modules.f5os_logging import (
    ModuleParameters,
    ApiParameters,
    ArgumentSpec,
    ModuleManager,
    UsableChanges,
    ReportableChanges,
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


class TestApiParameters(unittest.TestCase):

    def test_api_parameters_servers(self):
        data = load_fixture('f5os_logging_server.json')
        params = dict(servers=data['openconfig-system:remote-server'])

        p = ApiParameters(params=params)

        self.assertIsNotNone(p.servers)
        self.assertEqual(len(p.servers), 1)
        self.assertEqual(p.servers[0]['address'], '1.2.3.4')
        self.assertEqual(p.servers[0]['port'], 514)
        self.assertEqual(p.servers[0]['protocol'], 'udp')
        self.assertEqual(len(p.servers[0]['logs']), 2)
        self.assertEqual(p.servers[0]['logs'][0]['facility'], 'local0')
        self.assertEqual(p.servers[0]['logs'][0]['severity'], 'notice')

    def test_api_parameters_servers_with_authentication(self):
        params = dict(servers=[{
            'config': {
                'host': '10.0.0.1',
                'remote-port': 6514,
                'f5-openconfig-system-logging:proto': 'tcp',
                'f5-openconfig-system-logging:authentication': {'enabled': True}
            }
        }])

        p = ApiParameters(params=params)

        self.assertEqual(p.servers[0]['address'], '10.0.0.1')
        self.assertEqual(p.servers[0]['port'], 6514)
        self.assertEqual(p.servers[0]['protocol'], 'tcp')
        self.assertTrue(p.servers[0]['authentication'])

    def test_api_parameters_servers_none(self):
        p = ApiParameters(params=dict(servers=None))
        self.assertIsNone(p.servers)

    def test_api_parameters_servers_empty(self):
        params = dict(servers=[{'config': {}}])
        p = ApiParameters(params=params)
        self.assertEqual(p.servers, [])

    def test_api_parameters_remote_forwarding(self):
        data = load_fixture('f5os_logging_host_logs.json')
        config = data['f5-openconfig-system-logging:host-logs']['config']
        params = dict(remote_forwarding=config)

        p = ApiParameters(params=params)

        self.assertIsNotNone(p.remote_forwarding)
        self.assertTrue(p.remote_forwarding['enabled'])
        self.assertEqual(len(p.remote_forwarding['logs']), 2)
        self.assertEqual(p.remote_forwarding['logs'][0]['facility'], 'local0')
        self.assertEqual(p.remote_forwarding['logs'][0]['severity'], 'informational')
        self.assertEqual(len(p.remote_forwarding['files']), 2)
        self.assertEqual(p.remote_forwarding['files'][0]['name'], 'ansible.log')

    def test_api_parameters_remote_forwarding_none(self):
        p = ApiParameters(params=dict(remote_forwarding=None))
        self.assertIsNone(p.remote_forwarding)

    def test_api_parameters_ca_bundles(self):
        data = load_fixture('f5os_logging_tls.json')
        bundles = data['f5-openconfig-system-logging:tls']['ca-bundles']['ca-bundle']
        params = dict(ca_bundles=bundles)

        p = ApiParameters(params=params)

        self.assertIsNotNone(p.ca_bundles)
        self.assertEqual(len(p.ca_bundles), 1)
        self.assertEqual(p.ca_bundles[0]['name'], 'test-bundle')

    def test_api_parameters_ca_bundles_none(self):
        p = ApiParameters(params=dict(ca_bundles=None))
        self.assertIsNone(p.ca_bundles)

    def test_api_parameters_ca_bundles_empty(self):
        params = dict(ca_bundles=[{}])
        p = ApiParameters(params=params)
        self.assertEqual(p.ca_bundles, [])

    def test_api_parameters_empty(self):
        p = ApiParameters(params=dict())
        self.assertIsNone(p.servers)
        self.assertIsNone(p.remote_forwarding)
        self.assertIsNone(p.ca_bundles)


class TestModuleParameters(unittest.TestCase):

    def test_module_parameters_servers(self):
        args = dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
                logs=[dict(facility='local0', severity='notice')],
            )],
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.servers[0]['address'], '1.2.3.4')
        self.assertEqual(p.servers[0]['port'], 514)
        self.assertEqual(p.state, 'present')

    def test_module_parameters_include_hostname(self):
        args = dict(include_hostname=True, state='present')

        p = ModuleParameters(params=args)

        self.assertTrue(p.include_hostname)

    def test_module_parameters_remote_forwarding(self):
        args = dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[dict(facility='local0', severity='informational')],
                files=[dict(name='ansible.log')],
            ),
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertTrue(p.remote_forwarding['enabled'])
        self.assertEqual(len(p.remote_forwarding['logs']), 1)
        self.assertEqual(len(p.remote_forwarding['files']), 1)

    def test_module_parameters_tls(self):
        args = dict(
            tls=dict(certificate='CERT_PEM', key='KEY_PEM'),
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.tls['certificate'], 'CERT_PEM')
        self.assertEqual(p.tls['key'], 'KEY_PEM')

    def test_module_parameters_ca_bundles(self):
        args = dict(
            ca_bundles=[dict(name='test', content='BUNDLE_PEM')],
            state='present',
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.ca_bundles[0]['name'], 'test')
        self.assertEqual(p.ca_bundles[0]['content'], 'BUNDLE_PEM')


class TestUsableChanges(unittest.TestCase):

    def test_to_return(self):
        changes = UsableChanges(params=dict(include_hostname=True))
        result = changes.to_return()
        self.assertIsInstance(result, dict)


class TestReportableChanges(unittest.TestCase):

    def test_to_return(self):
        changes = ReportableChanges(params=dict(include_hostname=True))
        result = changes.to_return()
        self.assertIsInstance(result, dict)


class TestManager(unittest.TestCase):

    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(
            AnsibleModule, exit_json=exit_json, fail_json=fail_json
        )
        self.mock_module_helper.start()
        self.p1 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.f5os_logging.F5Client'
        )
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch(
            'ansible_collections.f5networks.f5os.plugins.modules.f5os_logging.send_teem'
        )
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    # --- Create Server Tests ---

    def test_create_server(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
                logs=[dict(facility='local0', severity='notice')],
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # exists(query='all') -> server GET returns 404 -> return False (not all_exist)
        # create_on_device -> POST returns 201
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_server_with_authentication(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='10.0.0.1',
                port=6514,
                protocol='tcp',
                authentication=True,
                logs=[dict(facility='local0', severity='notice')],
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        server_conf = post_payload['remote-server'][0]['config']
        self.assertIn('f5-openconfig-system-logging:authentication', server_conf)
        self.assertTrue(server_conf['f5-openconfig-system-logging:authentication']['enabled'])

    def test_create_server_conflict_uses_put(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=409, contents='conflict'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_create_server_fails(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    # --- Update Server Tests ---

    def test_update_server(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=6514,
                protocol='tcp',
                logs=[dict(facility='local0', severity='warning')],
            )],
            state='present',
        ))

        server_data = load_fixture('f5os_logging_server.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET server -> 200
        # read_current: GET server -> 200
        mm.client.get = Mock(return_value=dict(code=200, contents=server_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_server_fails(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=6514,
                protocol='tcp',
            )],
            state='present',
        ))

        server_data = load_fixture('f5os_logging_server.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=server_data))
        mm.client.put = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    # --- Delete Server Tests ---

    def test_delete_server(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET server -> 200 (exists)
        # still_exists after remove: GET server -> 404 (deleted)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),
            dict(code=404, contents=''),
        ])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_server_not_found(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET server -> 404 (doesn't exist)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_delete_server_fails(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.delete = Mock(return_value=dict(code=500, contents='internal server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('internal server error', err.exception.args[0])

    def test_delete_still_exists_raises(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists -> True, still_exists -> True (not deleted)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete', err.exception.args[0])

    # --- Include Hostname Tests ---

    def test_create_include_hostname(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET config -> 200 (always exists for include_hostname)
        # read_current: GET config -> 200 with current data
        config_data = {'f5-openconfig-system-logging:config': {'include-hostname': False}}
        mm.client.get = Mock(return_value=dict(code=200, contents=config_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_create_include_hostname_no_change(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        config_data = {'f5-openconfig-system-logging:config': {'include-hostname': True}}
        mm.client.get = Mock(return_value=dict(code=200, contents=config_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_include_hostname_fails(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        config_data = {'f5-openconfig-system-logging:config': {'include-hostname': False}}
        mm.client.get = Mock(return_value=dict(code=200, contents=config_data))
        mm.client.put = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_delete_include_hostname(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists for include_hostname is always True (include_hostname is not None)
        # still_exists checks after delete
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # any_exists: include_hostname -> GET config
            dict(code=404, contents=''),  # still_exists: GET config -> 404
        ])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_include_hostname_fails(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.delete = Mock(return_value=dict(code=500, contents='delete failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('delete failed', err.exception.args[0])

    # --- Remote Forwarding Tests ---

    def test_create_remote_forwarding(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[
                    dict(facility='local0', severity='informational'),
                    dict(facility='authpriv', severity='notice'),
                ],
                files=[dict(name='ansible.log')],
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET host-logs -> 200 (always exists)
        # read_current: GET host-logs -> 200 with empty config
        host_logs_empty = {
            'f5-openconfig-system-logging:host-logs': {
                'config': {'remote-forwarding': {'enabled': False}}
            }
        }
        mm.client.get = Mock(return_value=dict(code=200, contents=host_logs_empty))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_create_remote_forwarding_no_change(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[
                    dict(facility='local0', severity='informational'),
                    dict(facility='authpriv', severity='notice'),
                ],
                files=[dict(name='ansible.log'), dict(name='audit/')],
            ),
            state='present',
        ))

        host_logs_data = load_fixture('f5os_logging_host_logs.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=host_logs_data))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_remote_forwarding_fails(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[dict(facility='local0', severity='notice')],
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        host_logs_empty = {
            'f5-openconfig-system-logging:host-logs': {
                'config': {'remote-forwarding': {'enabled': False}}
            }
        }
        mm.client.get = Mock(return_value=dict(code=200, contents=host_logs_empty))
        mm.client.put = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_delete_remote_forwarding(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[dict(facility='local0', severity='informational')],
            ),
            include_hostname=True,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET config (include_hostname) -> 200, GET host-logs (remote_forwarding) -> 200
        # (include_hostname makes any_exists return True at end)
        # remove_from_device: delete calls only
        # still_exists: GET config -> 404, GET host-logs -> 200
        # (no server/tls/ca returned True, returns False at end)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # any_exists - config (include_hostname)
            dict(code=200, contents={}),  # any_exists - host-logs (remote_forwarding)
            dict(code=404, contents=''),  # still_exists - config (include_hostname)
            dict(code=200, contents={}),  # still_exists - host-logs (remote_forwarding)
        ])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_delete_remote_forwarding_fails(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
            ),
            include_hostname=True,
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: config -> 200, host-logs -> 200 (include_hostname -> True at end)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # any_exists - config (include_hostname)
            dict(code=200, contents={}),  # any_exists - host-logs (remote_forwarding)
        ])
        mm.client.delete = Mock(return_value=dict(code=500, contents='delete failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('delete failed', err.exception.args[0])

    # --- TLS Tests ---

    def test_create_tls(self, *args):
        set_module_args(dict(
            tls=dict(certificate='CERT_PEM', key='KEY_PEM'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET tls -> 204 (no content, doesn't exist) -> return False (not all)
        mm.client.get = Mock(return_value=dict(code=204, contents=''))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_create_tls_fails(self, *args):
        set_module_args(dict(
            tls=dict(certificate='CERT_PEM', key='KEY_PEM'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=204, contents=''))
        mm.client.put = Mock(return_value=dict(code=500, contents='tls error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('tls error', err.exception.args[0])

    def test_update_tls(self, *args):
        set_module_args(dict(
            tls=dict(certificate='NEW_CERT', key='NEW_KEY'),
            state='present',
        ))

        tls_data = load_fixture('f5os_logging_tls.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET tls -> 200 (exists)
        # read_current: GET tls -> 200 with data
        mm.client.get = Mock(return_value=dict(code=200, contents=tls_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_tls_fails(self, *args):
        set_module_args(dict(
            tls=dict(certificate='NEW_CERT', key='NEW_KEY'),
            state='present',
        ))

        tls_data = load_fixture('f5os_logging_tls.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=tls_data))
        mm.client.put = Mock(return_value=dict(code=500, contents='update tls error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('update tls error', err.exception.args[0])

    def test_delete_tls(self, *args):
        set_module_args(dict(
            tls=dict(certificate='CERT', key='KEY'),
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET tls -> 200 (exists)
        # still_exists: GET tls -> 204 (gone)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),
            dict(code=204, contents=''),
        ])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # TLS delete calls delete for certificate and key
        self.assertEqual(mm.client.delete.call_count, 2)

    def test_delete_tls_fails(self, *args):
        set_module_args(dict(
            tls=dict(certificate='CERT', key='KEY'),
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.delete = Mock(return_value=dict(code=500, contents='tls delete failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('tls delete failed', err.exception.args[0])

    # --- CA Bundle Tests ---

    def test_create_ca_bundle(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='CA_PEM')],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET ca-bundle -> 404 (not exists) -> return False
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)

    def test_create_ca_bundle_conflict_uses_put(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='CA_PEM')],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=409, contents='conflict'))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_create_ca_bundle_fails(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='CA_PEM')],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=500, contents='ca bundle error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('ca bundle error', err.exception.args[0])

    def test_update_ca_bundle(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='NEW_CA_PEM')],
            state='present',
        ))

        tls_data = load_fixture('f5os_logging_tls.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET ca-bundle -> 200
        # read_current: GET tls -> 200
        mm.client.get = Mock(return_value=dict(code=200, contents=tls_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_ca_bundle_fails(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='NEW_CA_PEM')],
            state='present',
        ))

        tls_data = load_fixture('f5os_logging_tls.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=tls_data))
        mm.client.put = Mock(return_value=dict(code=500, contents='ca update failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('ca update failed', err.exception.args[0])

    def test_delete_ca_bundle(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='CA_PEM')],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET ca-bundle -> 200
        # still_exists: GET ca-bundle -> 404
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),
            dict(code=404, contents=''),
        ])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_ca_bundle_fails(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test-bundle', content='CA_PEM')],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        mm.client.delete = Mock(return_value=dict(code=500, contents='ca delete failed'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('ca delete failed', err.exception.args[0])

    # --- Exists Error Handling ---

    def test_exists_server_error(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='server check error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server check error', err.exception.args[0])

    def test_exists_include_hostname_error(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='config check error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('config check error', err.exception.args[0])

    def test_exists_remote_forwarding_error(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(enabled=True),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='host-logs error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('host-logs error', err.exception.args[0])

    def test_exists_tls_error(self, *args):
        set_module_args(dict(
            tls=dict(certificate='CERT', key='KEY'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='tls check error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('tls check error', err.exception.args[0])

    def test_exists_ca_bundle_error(self, *args):
        set_module_args(dict(
            ca_bundles=[dict(name='test', content='PEM')],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=500, contents='ca check error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('ca check error', err.exception.args[0])

    # --- Read Current Error Handling ---

    def test_read_current_servers_error(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist -> 200 first call, then read_current fails
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # all_exist
            dict(code=500, contents={'openconfig-system:remote-server': 'server read error'}),  # read_current
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server read error', err.exception.args[0])

    def test_read_current_include_hostname_error(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET config -> 200
        # read_current: GET config -> 500
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # all_exist
            dict(code=500, contents='config read error'),  # read_current
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('config read error', err.exception.args[0])

    def test_read_current_remote_forwarding_error(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(enabled=True),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET host-logs -> 200
        # read_current: GET host-logs -> 500
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # all_exist
            dict(code=500, contents='host-logs read error'),  # read_current
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('host-logs read error', err.exception.args[0])

    def test_read_current_tls_error(self, *args):
        set_module_args(dict(
            tls=dict(certificate='CERT', key='KEY'),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET tls -> 200
        # read_current: GET tls -> 500
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # all_exist
            dict(code=500, contents='tls read error'),  # read_current
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('tls read error', err.exception.args[0])

    # --- Check Mode Tests ---

    def test_check_mode_create(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='present',
            _ansible_check_mode=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # No post/put should be called in check mode
        mm.client.post.assert_not_called()
        mm.client.put.assert_not_called()

    def test_check_mode_update(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
            _ansible_check_mode=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        config_data = {'f5-openconfig-system-logging:config': {'include-hostname': False}}
        mm.client.get = Mock(return_value=dict(code=200, contents=config_data))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_check_mode_delete(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=514,
                protocol='udp',
            )],
            state='absent',
            _ansible_check_mode=True,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists -> 200
        mm.client.get = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    # --- Combined Parameters Tests ---

    def test_create_server_with_logs_no_auth(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='10.0.0.1',
                port=514,
                protocol='udp',
                logs=[
                    dict(facility='local0', severity='notice'),
                    dict(facility='authpriv', severity='warning'),
                ],
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=404, contents=''))
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        post_payload = mm.client.post.call_args[1]['data']
        server_conf = post_payload['remote-server'][0]
        self.assertIn('selectors', server_conf)
        self.assertEqual(len(server_conf['selectors']['selector']), 2)
        self.assertEqual(
            server_conf['selectors']['selector'][0]['facility'],
            'f5-system-logging-types:LOCAL0'
        )

    def test_create_remote_forwarding_with_files_only(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                files=[dict(name='syslog'), dict(name='boot.log')],
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        host_logs_empty = {
            'f5-openconfig-system-logging:host-logs': {
                'config': {'remote-forwarding': {'enabled': False}}
            }
        }
        mm.client.get = Mock(return_value=dict(code=200, contents=host_logs_empty))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    # --- Main Function Tests ---

    @patch.object(f5os_logging, 'Connection')
    @patch.object(f5os_logging.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))
        with self.assertRaises(AnsibleExitJson) as result:
            f5os_logging.main()
        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_logging, 'Connection')
    @patch.object(f5os_logging.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))
        with self.assertRaises(AnsibleFailJson) as result:
            f5os_logging.main()
        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    # --- Read Current from Device: Server 404 Skip ---

    def test_read_current_server_404_skipped(self, *args):
        set_module_args(dict(
            servers=[dict(
                address='9.9.9.9',
                port=514,
                protocol='udp',
            )],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # all_exist: GET server -> 200
        # read_current: GET server -> 404 (server gone - skip)
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # all_exist
            dict(code=404, contents=''),  # read_current - server not found
        ])
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    # --- Create Path Tests (covers create_on_device for remote_forwarding/include_hostname) ---

    def test_create_path_remote_forwarding_with_logs_and_files(self, *args):
        """Test create_on_device for remote_forwarding (lines 639-671)."""
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[dict(facility='local0', severity='notice')],
                files=[dict(name='syslog')],
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # Force the create path by making all_exist return False
        mm.all_exist = Mock(return_value=False)
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)
        put_payload = mm.client.put.call_args[1]['data']
        conf = put_payload['f5-openconfig-system-logging:host-logs']['config']
        self.assertTrue(conf['remote-forwarding']['enabled'])
        self.assertEqual(conf['selectors']['selector'][0]['facility'], 'openconfig-system-logging:LOCAL0')
        self.assertEqual(conf['selectors']['selector'][0]['severity'], 'NOTICE')
        self.assertEqual(conf['files']['file'][0]['name'], 'syslog')

    def test_create_path_remote_forwarding_fails(self, *args):
        set_module_args(dict(
            remote_forwarding=dict(
                enabled=True,
                logs=[dict(facility='local0', severity='notice')],
            ),
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.all_exist = Mock(return_value=False)
        mm.client.put = Mock(return_value=dict(code=500, contents='create rf error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('create rf error', err.exception.args[0])

    def test_create_path_include_hostname(self, *args):
        """Test create_on_device for include_hostname (lines 715-724)."""
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.all_exist = Mock(return_value=False)
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        put_payload = mm.client.put.call_args[1]['data']
        self.assertTrue(put_payload['f5-openconfig-system-logging:config']['include-hostname'])

    def test_create_path_include_hostname_fails(self, *args):
        set_module_args(dict(
            include_hostname=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.all_exist = Mock(return_value=False)
        mm.client.put = Mock(return_value=dict(code=500, contents='hostname create error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('hostname create error', err.exception.args[0])

    def test_update_server_with_authentication(self, *args):
        """Test update_on_device for server with authentication (lines 803-804)."""
        set_module_args(dict(
            servers=[dict(
                address='1.2.3.4',
                port=6514,
                protocol='tcp',
                authentication=True,
                logs=[dict(facility='local0', severity='warning')],
            )],
            state='present',
        ))

        server_data = load_fixture('f5os_logging_server.json')
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value=dict(code=200, contents=server_data))
        mm.client.put = Mock(return_value=dict(code=200, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        put_payload = mm.client.put.call_args[1]['data']
        server_conf = put_payload['remote-server'][0]['config']
        self.assertIn('f5-openconfig-system-logging:authentication', server_conf)
        self.assertTrue(server_conf['f5-openconfig-system-logging:authentication']['enabled'])

    def test_delete_remote_forwarding_only(self, *args):
        """Test remove_from_device for remote_forwarding (line 862)."""
        set_module_args(dict(
            remote_forwarding=dict(enabled=True),
            servers=[dict(address='1.2.3.4', port=514, protocol='udp')],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET server -> 200 (found, returns True immediately for 'any')
        # still_exists: GET server -> 404, GET host-logs -> 200
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents={}),  # any_exists - server (returns True immediately)
            dict(code=404, contents=''),  # still_exists - server
            dict(code=200, contents={}),  # still_exists - host-logs (remote_forwarding)
        ])
        mm.client.delete = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        # Should have called delete for server and host-logs
        self.assertEqual(mm.client.delete.call_count, 2)

    def test_delete_remote_forwarding_delete_fails(self, *args):
        """Test remove_from_device error for remote_forwarding delete (line 862)."""
        set_module_args(dict(
            remote_forwarding=dict(enabled=True),
            servers=[dict(address='1.2.3.4', port=514, protocol='udp')],
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        # any_exists: GET server -> 200 (returns True immediately)
        mm.client.get = Mock(return_value=dict(code=200, contents={}))
        # First delete (server) succeeds, second delete (host-logs) fails
        mm.client.delete = Mock(side_effect=[
            dict(code=204, contents={}),   # delete server - ok
            dict(code=500, contents='host-logs delete failed'),  # delete host-logs - fail
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('host-logs delete failed', err.exception.args[0])
