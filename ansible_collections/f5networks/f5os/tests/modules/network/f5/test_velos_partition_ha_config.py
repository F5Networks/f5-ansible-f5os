from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule


from ansible_collections.f5networks.f5os.plugins.modules.velos_partition_ha_config import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import (
    Mock, patch
)
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json
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
    def test_module_parameters_prefer_node_and_auto_failback(self):
        args = dict(
            prefer_node='prefer-1',
            auto_failback={'enabled': True, 'failback_delay': 45},
            state='present'
        )
        p = ModuleParameters(params=args)
        self.assertEqual(p.prefer_node, 'prefer-1')
        self.assertEqual(p.auto_failback, {'enabled': True, 'failback_delay': 45})


class TestApiParameters(unittest.TestCase):
    def test_api_parameters_basic(self):
        args = dict(
            prefer_node='prefer-1',
            auto_failback={'enabled': True, 'failback_delay': 45},
            state='present'
        )
        p = ApiParameters(params=args)
        self.assertEqual(p.prefer_node, 'prefer-1')
        self.assertEqual(p.auto_failback, {'enabled': True, 'failback_delay': 45})
        self.assertEqual(p.state, 'present')

    def test_api_parameters_missing_values(self):
        args = dict()
        p = ApiParameters(params=args)
        self.assertIsNone(p.prefer_node)
        self.assertIsNone(p.auto_failback)
        self.assertIsNone(p.state)

    def test_api_parameters_partial(self):
        args = dict(prefer_node='prefer-2')
        p = ApiParameters(params=args)
        self.assertEqual(p.prefer_node, 'prefer-2')
        self.assertIsNone(p.auto_failback)
        self.assertIsNone(p.state)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        # Patch F5Client for velos_partition_ha_config
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.velos_partition_ha_config.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.mock_module_helper.stop()

    def test_partition_ha_create(self):
        set_module_args(dict(
            prefer_node='prefer-1',
            auto_failback={'enabled': True, 'failback_delay': 60},
            state='present'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'VELOS'
        # Patch .get and .patch to return dicts with required keys
        mm.client.put = Mock(return_value={'code': 201, 'contents': {}})
        mm.client.get = Mock(return_value={
            'code': 200,
            'contents': {
                'f5-system-redundancy:config': {
                    'mode': 'prefer-1',
                    'auto-failback': {'enabled': True, 'failback-delay': 60}
                }
            }
        })
        mm.want = Mock()
        mm.want.prefer_node = 'prefer-1'
        mm.want.auto_failback = {'enabled': True, 'failback_delay': 60}
        mm.want.state = 'present'
        mm.have = Mock()
        mm.have.prefer_node = None
        mm.have.auto_failback = None
        mm.have.state = None
        mm._announce_deprecations = Mock()
        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(results['prefer_node'], 'prefer-1')
        self.assertEqual(results['auto_failback'], {'enabled': True, 'failback_delay': 60})

    def test_partition_ha_no_change(self):
        set_module_args(dict(
            prefer_node='prefer-2',
            auto_failback={'enabled': False, 'failback_delay': 30},
            state='present'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'VELOS'
        mm.client.put = Mock(return_value={'code': 200, 'contents': {}})
        mm.client.get = Mock(return_value={
            'code': 200,
            'contents': {
                'f5-system-redundancy:config': {
                    'mode': 'prefer-2',
                    'auto-failback': {'enabled': False, 'failback-delay': 30}
                }
            }
        })
        mm.want = Mock()
        mm.want.prefer_node = 'prefer-2'
        mm.want.auto_failback = {'enabled': False, 'failback_delay': 30}
        mm.want.state = 'present'
        mm.have = Mock()
        mm.have.prefer_node = 'prefer-2'
        mm.have.auto_failback = {'enabled': False, 'failback_delay': 30}
        mm.have.state = 'present'
        mm._announce_deprecations = Mock()
        results = mm.exec_module()
        self.assertFalse(results['changed'])
        # self.assertEqual(results['prefer_node'], 'prefer-2')
        # self.assertEqual(results['auto_failback'], {'enabled': False, 'failback_delay': 30})

    def test_changes_to_return_returns_expected_dict(self):
        from ansible_collections.f5networks.f5os.plugins.modules.velos_partition_ha_config import UsableChanges
        changes = UsableChanges(params={
            'prefer_node': 'node2',
            'auto_failback': {'enabled': False, 'failback_delay': 30},
            'state': 'present'
        })
        result = changes.to_return()
        self.assertEqual(result['prefer_node'], 'node2')
        self.assertEqual(result['auto_failback'], {'enabled': False, 'failback_delay': 30})

    def test_present_check_mode(self):
        set_module_args(dict(
            prefer_node='prefer-1',
            auto_failback={'enabled': True, 'failback_delay': 60},
            state='present',
            _ansible_check_mode=True
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'VELOS'
        mm.client.put = Mock(return_value=dict(code=201, contents={}))
        mm.client.get = Mock(return_value={})
        mm.want = Mock()
        mm.want.prefer_node = 'prefer-1'
        mm.want.auto_failback = {'enabled': True, 'failback_delay': 60}
        mm.want.state = 'present'
        mm.have = Mock()
        mm.have.prefer_node = None
        mm.have.auto_failback = None
        mm.have.state = None
        mm._announce_deprecations = Mock()
        module.check_mode = True
        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(results['prefer_node'], 'prefer-1')
        self.assertEqual(results['auto_failback'], {'enabled': True, 'failback_delay': 60})

    def test_present_error_on_update(self):
        set_module_args(dict(
            prefer_node='prefer-1',
            auto_failback={'enabled': True, 'failback_delay': 60},
            state='present'
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'VELOS'
        mm.client.put = Mock(side_effect=F5ModuleError('update failed'))
        mm.client.get = Mock(return_value={
            'code': 200,
            'contents': {
                'f5-system-redundancy:config': {
                    'mode': 'prefer-1',
                    'auto-failback': {'enabled': True, 'failback-delay': 60}
                }
            }
        })
        mm.want = Mock()
        mm.want.prefer_node = 'prefer-1'
        mm.want.auto_failback = {'enabled': True, 'failback_delay': 60}
        mm.want.state = 'present'
        mm.have = Mock()
        mm.have.prefer_node = None
        mm.have.auto_failback = None
        mm.have.state = None
        mm._announce_deprecations = Mock()
        with self.assertRaises(F5ModuleError):
            mm.exec_module()
