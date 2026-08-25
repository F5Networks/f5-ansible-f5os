#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_appliance_mode
short_description: Manage F5OS appliance mode on rSeries and VELOS partition devices
description:
  - Enable or disable F5OS appliance mode on rSeries platforms and VELOS partitions
    via the F5OS RESTCONF API.
  - Appliance mode restricts shell access and certain administrative functions,
    providing an additional layer of security for the F5OS platform layer.
  - This module is not supported on VELOS controllers.
version_added: "1.23.0"
options:
  enabled:
    description:
      - Whether appliance mode should be enabled or disabled.
      - When C(true), appliance mode is enabled, restricting shell access.
      - When C(false), appliance mode is disabled, allowing full administrative access.
    type: bool
    required: true
  state:
    description:
      - The desired state of the appliance mode configuration.
      - Only C(present) is supported. Use the C(enabled) parameter to toggle appliance mode on or off.
    type: str
    choices:
      - present
    default: present
author:
  - F5 Networks (@f5networks)
notes:
  - This module is supported on F5OS rSeries platforms and VELOS partitions.
  - It is not supported on VELOS controllers.
  - This module uses the PUT method to set appliance mode, matching the F5OS RESTCONF API specification.
  - Enabling appliance mode disables root shell access on the device. Ensure you have an alternate
    management path before enabling this on a production system.
'''

EXAMPLES = r'''
- name: Enable appliance mode
  f5networks.f5os.f5os_appliance_mode:
    enabled: true
    state: present

- name: Disable appliance mode
  f5networks.f5os.f5os_appliance_mode:
    enabled: false
    state: present
'''

RETURN = r'''
enabled:
  description: The appliance mode state after the operation.
  returned: changed
  type: bool
  sample: true
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    returnables = [
        'enabled',
    ]

    updatables = [
        'enabled',
    ]


class ApiParameters(Parameters):
    @property
    def enabled(self):
        config = self._values.get('f5-security-appliance-mode:appliance-mode', {})
        if not config:
            return None
        return config.get('enabled')


class ModuleParameters(Parameters):
    pass


class Changes(Parameters):  # pragma: no cover
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class Difference(object):  # pragma: no cover
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):  # pragma: no cover
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        return self.update()

    def update(self):
        self.have = self.read_current_from_device()
        if not self._update_changed_options():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/f5-security-appliance-mode:appliance-mode"
        response = self.client.get(uri)
        if response['code'] == 404:
            return ApiParameters(params={})
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents'])

    def update_on_device(self):
        uri = "/openconfig-system:system/f5-security-appliance-mode:appliance-mode"
        payload = {
            "f5-security-appliance-mode:appliance-mode": {
                "enabled": self.want.enabled,
            }
        }
        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            enabled=dict(
                type='bool',
                required=True,
            ),
            state=dict(
                default='present',
                choices=['present'],
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
