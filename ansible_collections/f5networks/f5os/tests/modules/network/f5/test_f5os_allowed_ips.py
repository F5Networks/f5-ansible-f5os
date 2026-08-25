# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_allowed_ips
from ansible_collections.f5networks.f5os.plugins.modules.f5os_allowed_ips import (
    ModuleParameters, ApiParameters, UsableChanges, ArgumentSpec, ModuleManager
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
    def test_module_parameters_ipv4(self):
        args = dict(
            allowed=[
                dict(
                    name='admins',
                    ipv4=dict(address='192.168.0.0', prefix=24, port=None),
                    ipv6=None,
                )
            ],
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.allowed[0]['name'], 'admins')
        self.assertEqual(p.allowed[0]['ipv4']['address'], '192.168.0.0')
        self.assertEqual(p.allowed[0]['ipv4']['prefix'], 24)

    def test_module_parameters_ipv6(self):
        args = dict(
            allowed=[
                dict(
                    name='admins_v6',
                    ipv4=None,
                    ipv6=dict(address='2001:db8::', prefix=32, port=443),
                )
            ],
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.allowed[0]['name'], 'admins_v6')
        self.assertEqual(p.allowed[0]['ipv6']['address'], '2001:db8::')
        self.assertEqual(p.allowed[0]['ipv6']['prefix'], 32)
        self.assertEqual(p.allowed[0]['ipv6']['port'], 443)

    def test_module_parameters_none(self):
        args = dict(
            allowed=None,
            state='present'
        )

        p = ModuleParameters(params=args)

        self.assertIsNone(p.allowed)

    def test_api_parameters(self):
        args = dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24))
            ]
        )

        p = ApiParameters(params=args)

        self.assertEqual(p.allowed[0]['name'], 'admins')

    def test_usable_changes_ipv4_with_port(self):
        args = dict(
            allowed=[
                dict(
                    name='snmp',
                    ipv4=dict(address='10.1.0.0', prefix=24, port=161),
                    ipv6=None,
                )
            ]
        )

        uc = UsableChanges(params=args)

        self.assertEqual(uc.allowed[0]['name'], 'snmp')
        self.assertEqual(uc.allowed[0]['config']['ipv4']['address'], '10.1.0.0')
        self.assertEqual(uc.allowed[0]['config']['ipv4']['prefix-length'], 24)
        self.assertEqual(uc.allowed[0]['config']['ipv4']['port'], 161)

    def test_usable_changes_ipv4_without_port(self):
        args = dict(
            allowed=[
                dict(
                    name='admins',
                    ipv4=dict(address='192.168.0.0', prefix=24, port=None),
                    ipv6=None,
                )
            ]
        )

        uc = UsableChanges(params=args)

        self.assertEqual(uc.allowed[0]['name'], 'admins')
        self.assertEqual(uc.allowed[0]['config']['ipv4']['address'], '192.168.0.0')
        self.assertEqual(uc.allowed[0]['config']['ipv4']['prefix-length'], 24)
        self.assertNotIn('port', uc.allowed[0]['config']['ipv4'])

    def test_usable_changes_ipv6(self):
        args = dict(
            allowed=[
                dict(
                    name='admins_v6',
                    ipv4=None,
                    ipv6=dict(address='2001:db8::', prefix=64, port=443),
                )
            ]
        )

        uc = UsableChanges(params=args)

        self.assertEqual(uc.allowed[0]['name'], 'admins_v6')
        self.assertEqual(uc.allowed[0]['config']['ipv6']['address'], '2001:db8::')
        self.assertEqual(uc.allowed[0]['config']['ipv6']['prefix-length'], 64)
        self.assertEqual(uc.allowed[0]['config']['ipv6']['port'], 443)

    def test_usable_changes_none(self):
        args = dict(allowed=None)

        uc = UsableChanges(params=args)

        self.assertIsNone(uc.allowed)


class TestManager(unittest.TestCase):
    """Tests for ModuleManager.

    Note: The module marks ``Difference`` and ``_update_changed_options`` with
    ``# pragma: no cover``, so coverage tooling will not count lines exercised
    through the update/diff path even though they are functionally tested here.
    """

    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_allowed_ips.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_allowed_ips.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_allowed_ips_ipv4(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
                dict(name='snmp', ipv4=dict(address='10.1.0.0', prefix=24, port=161)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404))
        mm.client.post = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)
        # Verify the payload structure for the first POST call
        first_call_payload = mm.client.post.call_args_list[0][1]['data']
        self.assertIn('allowed-ip', first_call_payload)
        self.assertEqual(first_call_payload['allowed-ip'][0]['name'], 'admins')
        self.assertIn('ipv4', first_call_payload['allowed-ip'][0]['config'])

    def test_create_allowed_ips_conflict_fallback_to_put(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # First call to exists (all_exist) returns False (404), create path taken
        mm.client.get = Mock(return_value=dict(code=404))
        # POST returns 409 conflict, then PUT succeeds
        mm.client.post = Mock(return_value=dict(code=409, contents={}))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.post.called)
        self.assertTrue(mm.client.put.called)

    def test_create_mixed_post_and_conflict(self, *args):
        """Test that when some entries POST successfully and others conflict, PUT fallback works."""
        set_module_args(dict(
            allowed=[
                dict(name='new_rule', ipv4=dict(address='10.0.0.0', prefix=8)),
                dict(name='existing_rule', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404))
        # First entry POSTs successfully (201), second gets 409 conflict
        mm.client.post = Mock(side_effect=[
            dict(code=201, contents={}),
            dict(code=409, contents={}),
        ])
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(mm.client.post.call_count, 2)
        self.assertEqual(mm.client.put.call_count, 1)

    def test_create_allowed_ips_fails(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=404))
        mm.client.post = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_update_allowed_ips(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.1.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # all_exist returns True (200 for all entries)
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.put.called)

    def test_update_allowed_ips_no_change(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # all_exist returns True
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertFalse(mm.client.put.called)

    def test_update_allowed_ips_fails(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.1.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_delete_allowed_ips(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # side_effect: one GET for any_exists (single allowed entry), one GET for still_exists
        mm.client.get = Mock(side_effect=[
            dict(code=200),   # any_exists checks 'admins' -> found
            dict(code=404),   # still_exists checks 'admins' -> gone
        ])
        mm.client.delete = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)

    def test_delete_allowed_ips_not_found(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # any_exists returns False (404 for all)
        mm.client.get = Mock(return_value=dict(code=404))

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_delete_allowed_ips_fails(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(code=200))
        mm.client.delete = Mock(return_value=dict(code=500, contents='server error'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_delete_failed_to_delete(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # delete returns success (204) but resource still exists on re-check,
        # simulating a race condition or backend failure
        mm.client.get = Mock(return_value=dict(code=200))
        mm.client.delete = Mock(return_value=dict(code=204))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('VELOS controller', err.exception.args[0])

    @patch.object(f5os_allowed_ips, 'Connection')
    @patch.object(f5os_allowed_ips.ModuleManager, 'exec_module', Mock(return_value={'changed': True}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_allowed_ips.main()

        self.assertTrue(result.exception.args[0]['changed'])

    @patch.object(f5os_allowed_ips, 'Connection')
    @patch.object(f5os_allowed_ips.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_allowed_ips.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        # Test exists - all_exist returns True (all 200)
        mm.client.get = Mock(return_value=dict(code=200))
        self.assertTrue(mm.all_exist())

        # Test exists - all_exist returns False (one 404)
        mm.client.get = Mock(return_value=dict(code=404))
        self.assertFalse(mm.all_exist())

        # Test exists - any_exists returns True (one 200)
        mm.client.get = Mock(return_value=dict(code=200))
        self.assertTrue(mm.any_exists())

        # Test exists - any_exists returns False (all 404)
        mm.client.get = Mock(return_value=dict(code=404))
        self.assertFalse(mm.any_exists())

        # Test exists - raises on error
        mm.client.get = Mock(return_value=dict(code=500, contents='server error'))
        with self.assertRaises(F5ModuleError) as err:
            mm.exists(query='any')
        self.assertIn('server error', err.exception.args[0])

        # Test read_current_from_device
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        result = mm.read_current_from_device()
        self.assertIsInstance(result, ApiParameters)

        # Note: The module extracts response['contents']['f5-allowed-ips:allowed-ips']
        # BEFORE checking the status code, so the mock must include that key even
        # in error responses. A response missing the key would raise KeyError
        # rather than F5ModuleError — this is a known module quirk.
        mm.client.get = Mock(return_value=dict(
            code=500,
            contents={'f5-allowed-ips:allowed-ips': {}, 'error': 'server error'}
        ))
        with self.assertRaises(F5ModuleError):
            mm.read_current_from_device()

        # Test update returns False when no changes
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm._update_changed_options = Mock(return_value=False)
        self.assertFalse(mm.update())

        # Test remove raises when still_exists
        mm.remove_from_device = Mock(return_value=True)
        mm.client.get = Mock(return_value=dict(code=200))
        with self.assertRaises(F5ModuleError) as err:
            mm.remove()
        self.assertIn('Failed to delete the resource.', err.exception.args[0])

    def test_update_ip_version_mismatch(self, *args):
        """Test that a change is detected when the IP version differs."""
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv6=dict(address='2001:db8::', prefix=32)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # all_exist returns True
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        # IP version changed from ipv4 to ipv6 so update should trigger
        self.assertTrue(results['changed'])

    def test_update_port_added(self, *args):
        """Test that adding a port to an existing entry triggers a change."""
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=24, port=8443)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_update_address_changed(self, *args):
        """Test that changing the address triggers a change."""
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='10.0.0.0', prefix=24)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_update_prefix_changed(self, *args):
        """Test that changing the prefix triggers a change."""
        set_module_args(dict(
            allowed=[
                dict(name='admins', ipv4=dict(address='192.168.0.0', prefix=16)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_update_port_changed(self, *args):
        """Test that changing the port triggers a change."""
        set_module_args(dict(
            allowed=[
                dict(name='snmp', ipv4=dict(address='10.1.0.0', prefix=24, port=162)),
            ],
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value=dict(
            code=200,
            contents=load_fixture('f5os_allowed_ips.json')
        ))
        mm.client.put = Mock(return_value=dict(code=204, contents={}))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
