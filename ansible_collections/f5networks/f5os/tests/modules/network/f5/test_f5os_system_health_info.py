# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules import f5os_system_health_info
from ansible_collections.f5networks.f5os.plugins.modules.f5os_system_health_info import (
    ArgumentSpec, ModuleManager
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


_MODULE_PATH = 'ansible_collections.f5networks.f5os.plugins.modules.f5os_system_health_info'


def _fixture_response(name):
    """Build a successful API response dict from a fixture file."""
    return dict(code=200, contents=dict(load_fixture(name)))


def _error_response(code=500, contents='server error'):
    """Build an error API response dict."""
    return dict(code=code, contents=contents)


# Standard fixture responses reused across tests
_HEALTH_OK = 'f5os_system_health.json'
_COMPONENTS_OK = 'f5os_platform_components.json'
_ALERTS_OK = 'f5os_system_alerts.json'
_ALERTS_EMPTY = 'f5os_system_alerts_empty.json'
_HEALTH_FILTERED = 'f5os_system_health_filtered.json'


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch(f'{_MODULE_PATH}.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch(f'{_MODULE_PATH}.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def _build_manager(self, args=None, platform='rSeries Platform'):
        """Create and return a ModuleManager with common setup."""
        set_module_args(args or dict())
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = platform
        return mm

    def _standard_get_responses(self, health=_HEALTH_OK, include_alerts=True):
        """Build the standard ordered GET responses: health, components, [alerts]."""
        responses = [
            _fixture_response(health),
            _fixture_response(_COMPONENTS_OK),
        ]
        if include_alerts:
            responses.append(_fixture_response(_ALERTS_OK))
        return responses

    def test_collect_all_health(self, *args):
        mm = self._build_manager()
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=True))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 5)
        self.assertEqual(len(results['health_summary']), 5)
        self.assertEqual(len(results['platform_components']), 8)
        self.assertEqual(len(results['alerts']), 2)
        self.assertEqual(results['alerts'][0]['severity'], 'CRITICAL')
        self.assertEqual(results['alerts'][1]['severity'], 'WARNING')

    def test_collect_health_no_alerts(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 5)
        self.assertNotIn('alerts', results)

    def test_filter_cpu(self, *args):
        mm = self._build_manager(args=dict(component_filter=['cpu'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        self.assertEqual(results['components'][0]['name'], 'CPU')

    def test_filter_power(self, *args):
        mm = self._build_manager(args=dict(component_filter=['power'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        self.assertEqual(results['components'][0]['name'], 'Power Supply')

    def test_filter_multiple(self, *args):
        mm = self._build_manager(args=dict(component_filter=['cpu', 'memory'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 2)
        names = [c['name'] for c in results['components']]
        self.assertIn('CPU', names)
        self.assertIn('Memory', names)

    def test_filter_no_match(self, *args):
        mm = self._build_manager(args=dict(component_filter=['storage'], include_alerts=False))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_FILTERED),
            _fixture_response(_COMPONENTS_OK),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 0)
        self.assertEqual(len(results['health_summary']), 0)

    def test_health_204_empty(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(return_value=dict(code=204))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 0)
        self.assertEqual(len(results['health_summary']), 0)
        self.assertEqual(len(results['platform_components']), 0)

    def test_alerts_204_empty(self, *args):
        mm = self._build_manager(args=dict(include_alerts=True))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_OK),
            _fixture_response(_COMPONENTS_OK),
            dict(code=204),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['alerts']), 0)

    def test_alerts_empty_body(self, *args):
        mm = self._build_manager(args=dict(include_alerts=True))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_OK),
            _fixture_response(_COMPONENTS_OK),
            _fixture_response(_ALERTS_EMPTY),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['alerts']), 0)

    def test_platform_components_204(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_OK),
            dict(code=204),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['platform_components']), 0)

    def test_platform_components_api_error(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_OK),
            _error_response(contents='components error'),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('components error', err.exception.args[0])

    def test_platform_components_parsed(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        psu = next(c for c in results['platform_components'] if c['name'] == 'PSU-1')
        self.assertEqual(psu['type'], 'POWER_SUPPLY')
        self.assertEqual(psu['oper_status'], 'ACTIVE')
        self.assertEqual(psu['description'], 'Power Supply Unit 1')

    def test_health_api_error(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(return_value=_error_response())

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])

    def test_alerts_api_error(self, *args):
        mm = self._build_manager(args=dict(include_alerts=True))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_OK),
            _fixture_response(_COMPONENTS_OK),
            _error_response(contents='alerts error'),
        ])

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('alerts error', err.exception.args[0])

    def test_velos_controller_raises(self, *args):
        mm = self._build_manager(platform='Velos Controller')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('VELOS controller', err.exception.args[0])

    def test_velos_partition_allowed(self, *args):
        mm = self._build_manager(args=dict(include_alerts=False), platform='Velos Partition')
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 5)

    def test_check_mode(self, *args):
        mm = self._build_manager(args=dict(_ansible_check_mode=True, include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 5)

    def test_component_attributes_parsed(self, *args):
        mm = self._build_manager(args=dict(component_filter=['cpu'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        cpu = results['components'][0]
        self.assertEqual(cpu['key'], 'appliance/hardware/cpu')
        self.assertEqual(len(cpu['attributes']), 1)
        attr = cpu['attributes'][0]
        self.assertEqual(attr['name'], 'cpu:core:temperature')
        self.assertEqual(attr['value'], '42')
        self.assertEqual(attr['updated_at'], '2024-01-15T10:00:00Z')

    def test_summary_matches_components(self, *args):
        mm = self._build_manager(args=dict(component_filter=['cpu', 'temperature'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertEqual(len(results['health_summary']), len(results['components']))
        for summary, comp in zip(results['health_summary'], results['components']):
            self.assertEqual(summary['name'], comp['name'])
            self.assertEqual(summary['health'], comp['health'])
            self.assertNotIn('attributes', summary)

    def test_filter_temperature(self, *args):
        mm = self._build_manager(args=dict(component_filter=['temperature'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        self.assertEqual(results['components'][0]['name'], 'Temperature')

    def test_filter_storage(self, *args):
        mm = self._build_manager(args=dict(component_filter=['storage'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        self.assertEqual(results['components'][0]['name'], 'Storage')

    def test_filter_memory(self, *args):
        mm = self._build_manager(args=dict(component_filter=['memory'], include_alerts=False))
        mm.client.get = Mock(side_effect=self._standard_get_responses(include_alerts=False))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        self.assertEqual(results['components'][0]['name'], 'Memory')

    def test_filter_with_alerts(self, *args):
        mm = self._build_manager(args=dict(component_filter=['cpu'], include_alerts=True))
        mm.client.get = Mock(side_effect=[
            _fixture_response(_HEALTH_OK),
            _fixture_response(_COMPONENTS_OK),
            _fixture_response(_ALERTS_OK),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        self.assertEqual(results['components'][0]['name'], 'CPU')
        self.assertEqual(len(results['alerts']), 2)

    def test_parse_partial_component_data(self, *args):
        """Test components with missing state or attributes keys."""
        partial_data = {
            "f5-system-health:health": {
                "components": {
                    "component": [
                        {
                            "name": "appliance",
                            "hardware": [
                                {
                                    "key": "appliance/hardware/unknown",
                                    "state": {},
                                    "attributes": {}
                                }
                            ]
                        }
                    ]
                }
            }
        }
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=partial_data),
            _fixture_response(_COMPONENTS_OK),
        ])

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(len(results['components']), 1)
        comp = results['components'][0]
        self.assertEqual(comp['name'], '')
        self.assertEqual(comp['health'], '')
        self.assertEqual(comp['attributes'], [])

    def test_parse_multiple_outer_components(self, *args):
        """Test health data with multiple top-level component entries."""
        multi_data = {
            "f5-system-health:health": {
                "components": {
                    "component": [
                        {
                            "name": "appliance",
                            "hardware": [
                                {
                                    "key": "appliance/hardware/cpu",
                                    "state": {"name": "CPU", "health": "ok", "severity": "info"},
                                    "attributes": {"attribute": []}
                                }
                            ]
                        },
                        {
                            "name": "chassis",
                            "hardware": [
                                {
                                    "key": "chassis/hardware/psu",
                                    "state": {"name": "PSU", "health": "ok", "severity": "info"},
                                    "attributes": {"attribute": []}
                                }
                            ]
                        }
                    ]
                }
            }
        }
        mm = self._build_manager(args=dict(include_alerts=False))
        mm.client.get = Mock(side_effect=[
            dict(code=200, contents=multi_data),
            _fixture_response(_COMPONENTS_OK),
        ])

        results = mm.exec_module()

        self.assertEqual(len(results['components']), 2)
        names = [c['name'] for c in results['components']]
        self.assertIn('CPU', names)
        self.assertIn('PSU', names)

    @patch.object(f5os_system_health_info, 'Connection')
    @patch.object(f5os_system_health_info.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict())

        with self.assertRaises(AnsibleExitJson) as result:
            f5os_system_health_info.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(f5os_system_health_info, 'Connection')
    @patch.object(f5os_system_health_info.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.')))
    def test_main_function_failed(self, *args):
        set_module_args(dict())

        with self.assertRaises(AnsibleFailJson) as result:
            f5os_system_health_info.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])
