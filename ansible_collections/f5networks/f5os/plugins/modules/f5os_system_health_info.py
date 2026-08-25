#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_system_health_info
short_description: Collect system health information from F5OS devices
description:
  - Collects system health information from F5OS devices including hardware component
    status, active alerts, and overall health summary.
  - Supports filtering by component type to retrieve specific hardware health data.
  - This module is read-only and does not make any changes to the device.
version_added: "1.23.0"
options:
  component_filter:
    description:
      - Filter health data by one or more component types.
      - When not specified, all component health data is returned.
      - Component types are matched against the hardware key in the health response
        (e.g., C(cpu) matches keys containing C(cpu), C(power) matches keys containing C(psu)).
    type: list
    elements: str
    choices:
      - power
      - cpu
      - temperature
      - memory
      - storage
  include_alerts:
    description:
      - When C(true), include active alerts from the device in the response.
    type: bool
    default: true
author:
  - F5 Networks (@f5networks)
notes:
  - This module is supported on F5OS rSeries platforms and VELOS partitions.
  - It is not supported on VELOS controllers.
  - This module is read-only and supports C(check_mode) natively (no changes are made).
'''

EXAMPLES = r'''
- name: Collect all system health information with alerts
  f5networks.f5os.f5os_system_health_info:

- name: Collect only CPU and temperature health
  f5networks.f5os.f5os_system_health_info:
    component_filter:
      - cpu
      - temperature
    include_alerts: false

- name: Collect power supply health with alerts
  f5networks.f5os.f5os_system_health_info:
    component_filter:
      - power
    include_alerts: true

- name: Collect memory and storage health
  f5networks.f5os.f5os_system_health_info:
    component_filter:
      - memory
      - storage
'''

RETURN = r'''
health_summary:
  description: Overall health summary for each hardware component category.
  returned: always
  type: list
  elements: dict
  sample:
    - name: CPU
      health: ok
      severity: info
      key: appliance/hardware/cpu
components:
  description: Detailed health data for hardware components including attributes.
  returned: always
  type: list
  elements: dict
  sample:
    - name: CPU
      health: ok
      severity: info
      key: appliance/hardware/cpu
      attributes:
        - name: "cpu:core:temperature"
          description: "CPU core temperature (C)"
          health: ok
          severity: info
          value: "42"
          updated_at: "2024-01-15T10:00:00Z"
platform_components:
  description: Hardware platform components including PSU, CPU, sensors, LCD, TPM.
  returned: always
  type: list
  elements: dict
  sample:
    - name: PSU-1
      type: POWER_SUPPLY
      description: "Power Supply Unit 1"
      oper_status: ACTIVE
alerts:
  description: List of active alerts on the device.
  returned: when I(include_alerts) is C(true)
  type: list
  elements: dict
  sample:
    - source: appliance
      resource: /system/health
      severity: CRITICAL
      description: "PSU 2 is not present"
      timestamp: "2024-01-15T09:30:00Z"
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)

from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError
)

# Aliases for filter names that differ from hardware key substrings
_FILTER_ALIASES = {
    'power': 'psu',
}


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def _safe_get(self, uri):
        """GET a URI, return None on 204, raise on error."""
        response = self.client.get(uri)
        if response['code'] == 204:
            return None
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']

    def exec_module(self):
        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
        start = datetime.datetime.now().isoformat()
        result = dict(changed=False)

        health_data = self._get_health()
        components = self._parse_components(health_data)

        if self.module.params.get('component_filter'):
            components = self._filter_components(components)

        result['health_summary'] = self._build_summary(components)
        result['components'] = components
        result['platform_components'] = self._get_platform_components()

        if self.module.params.get('include_alerts'):
            result['alerts'] = self._get_alerts()

        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def _get_health(self):
        data = self._safe_get("/openconfig-system:system/f5-system-health:health")
        return data if data is not None else {}

    def _get_platform_components(self):
        data = self._safe_get("/openconfig-platform:components")
        if data is None:
            return []
        raw_components = data.get(
            'openconfig-platform:components', {}
        ).get('component', [])
        result = []
        for comp in raw_components:
            state = comp.get('state', {})
            result.append(dict(
                name=comp.get('name', ''),
                type=state.get('type', ''),
                description=state.get('description', ''),
                oper_status=state.get('oper-status', ''),
            ))
        return result

    def _get_alerts(self):
        data = self._safe_get("/f5-alert:alert")
        if data is None:
            return []
        alerts_data = data.get('f5-alert:alert', {})
        raw_alerts = alerts_data.get('alert', [])
        result = []
        for alert in raw_alerts:
            result.append(dict(
                source=alert.get('source', ''),
                resource=alert.get('resource', ''),
                severity=alert.get('severity', ''),
                description=alert.get('description', ''),
                timestamp=alert.get('timestamp', ''),
            ))
        return result

    def _parse_components(self, health_data):
        components = []
        health_root = health_data.get('f5-system-health:health', {})
        component_list = health_root.get('components', {}).get('component', [])

        for component in component_list:
            hardware_list = component.get('hardware', [])
            for hw in hardware_list:
                state = hw.get('state', {})
                attrs_raw = hw.get('attributes', {}).get('attribute', [])
                attributes = []
                for attr in attrs_raw:
                    attributes.append(dict(
                        name=attr.get('name', ''),
                        description=attr.get('description', ''),
                        health=attr.get('health', ''),
                        severity=attr.get('severity', ''),
                        value=attr.get('value', ''),
                        updated_at=attr.get('updatedAt', ''),
                    ))
                components.append(dict(
                    name=state.get('name', ''),
                    health=state.get('health', ''),
                    severity=state.get('severity', ''),
                    key=hw.get('key', ''),
                    attributes=attributes,
                ))
        return components

    def _filter_components(self, components):
        filters = self.module.params['component_filter']
        match_keys = {_FILTER_ALIASES.get(f, f) for f in filters}

        result = []
        for comp in components:
            key = comp.get('key', '').lower()
            if any(mk in key for mk in match_keys):
                result.append(comp)
        return result

    def _build_summary(self, components):
        summary = []
        for comp in components:
            summary.append(dict(
                name=comp['name'],
                health=comp['health'],
                severity=comp['severity'],
                key=comp['key'],
            ))
        return summary


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            component_filter=dict(
                type='list',
                elements='str',
                choices=['power', 'cpu', 'temperature', 'memory', 'storage'],
            ),
            include_alerts=dict(
                type='bool',
                default=True,
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
