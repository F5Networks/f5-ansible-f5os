#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_partition_ha_config
short_description: Managing high availability for the VELOS partition
description:
  - Configure redundancy mode of a F5OS partition
  - This module allows setting a specific controller as active in an HA pair.
  - Manually trigger a failover of the partition controllers
version_added: "1.19.0"
options:
  prefer_node:
    description:
      - Specifies which controller mode should be active.
      - When set to C(prefer-1), controller 1 will be set as active.
      - When set to C(prefer-2), controller 2 will be set as active.
      - When set to C(active-controller), the active controller will be set based on the current active controller.
      - When set to C(auto), the system will automatically determine the active controller.
    type: str
    choices:
      - prefer-1
      - prefer-2
      - active-controller
      - auto
    required: True
  auto_failback:
    description:
      - Dictionary to configure auto-failback behavior for the partition.
      - When B(enabled), the system will automatically fail back to the preferred controller after a failover event.
      - If the partition C(prefer_mode) remains as C(auto), you do not have to B(enable) the C(auto_failback).
      - The C(failback_delay) specifies the number of seconds to wait before failback occurs.
    type: dict
    suboptions:
      enabled:
        description:
          - Whether auto-failback is enabled.
        type: bool
        default: false
      failback_delay:
        description:
          - Number of seconds to wait before performing auto-failback.
        type: int
        default: 30
  state:
    description:
      - When C(present), ensures the specified controller is active.
      - When C(absent), This module does not support removing the active controller setting.
    type: str
    choices:
      - present
    default: present
notes:
  - This module is supported only for F5OS VELOS partitions.
  - The C(absent) state is not applicable for this module as it does not support removing the active controller setting.
author:
  - Ravinder Reddy (@chnthalapalli)
'''

EXAMPLES = r'''
- name: Set controller 1 as active
  velos_partition_ha_config:
    prefer_node: prefer-1
    state: present

- name: Set controller 2 as active
  velos_partition_ha_config:
    prefer_node: prefer-2
    state: present

- name: Set controller to auto mode
  velos_partition_ha_config:
    prefer_node: auto
    state: present

- name: Set controller 1 as active with auto-failback enabled
  velos_partition_ha_config:
    prefer_node: prefer-1
    auto_failback:
      enabled: true
      failback_delay: 60
    state: present
'''

RETURN = r'''
prefer_node:
  description: The prefer_node that was set as active.
  returned: changed
  type: str
  sample: "prefer-1"
auto_failback:
  description: The auto_failback configuration that was set.
  returned: changed
  type: dict
  sample: {"enabled": true, "failback_delay": 60}
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {
    }

    api_attributes = [
        'prefer_node',
        'auto_failback',
    ]

    returnables = [
        'prefer_node',
        'auto_failback',
    ]

    updatables = [
        'prefer_node',
        'auto_failback',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def prefer_node(self):
        return self._values['prefer_node']

    @property
    def auto_failback(self):
        return self._values.get('auto_failback')


class Changes(Parameters):
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


class Difference(object):
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
        self.changes = UsableChanges()
        self.have = ApiParameters()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):  # pragma: no cover
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
        changed = False
        result = dict()
        state = self.want.state
        if state == "present":
            changed = self.present()
        elif state == "absent":
            pass
        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def present(self):
        if self.exists():
            return False
        else:
            return self.create()

    def exists(self):
        # uri = "/openconfig-system:system/f5-system-redundancy:redundancy/f5-system-redundancy:config/f5-system-redundancy:mode"
        uri = "/openconfig-system:system/f5-system-redundancy:redundancy/f5-system-redundancy:config"
        response = self.client.get(uri)
        # raise F5ModuleError(f'response: {response['contents']}')
        # openconfig-system:system/f5-system-redundancy:redundancy/config

        # {"f5-system-redundancy:config":{"mode":"prefer-1","auto-failback":{"enabled":false,"failback-delay":30}}}
        # {"f5-system-redundancy:config":{"mode":"prefer-2","auto-failback":{"enabled":false,"failback-delay":30}}}
        # {"f5-system-redundancy:config":{"mode":"auto","auto-failback":{"enabled":false,"failback-delay":30}}}
        # {"f5-system-redundancy:config":{"mode":"active-controller","auto-failback":{"enabled":false,"failback-delay":30}}}

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        if response['contents']['f5-system-redundancy:config']['mode'] != self.want.prefer_node:
            return False
        if self.want.auto_failback is not None and isinstance(self.want.auto_failback, dict):
            if 'auto-failback' in response['contents']['f5-system-redundancy:config']:
                auto_failback = response['contents']['f5-system-redundancy:config']['auto-failback']
                if auto_failback.get('enabled') != self.want.auto_failback.get('enabled') or auto_failback.get('failback-delay') != self.want.auto_failback.get('failback_delay'):  # noqa: E501
                    return False
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def update_on_device(self):
        # uri = "/openconfig-system:system/f5-system-redundancy:redundancy/f5-system-redundancy:config/f5-system-redundancy:mode"
        uri = "/openconfig-system:system/f5-system-redundancy:redundancy/f5-system-redundancy:config"

        # payload = {
        #     "f5-system-redundancy:mode": self.want.prefer_node
        # }
        payload = {
            "f5-system-redundancy:config": {
                "mode": self.want.prefer_node,
                "auto-failback": {
                    "enabled": self.want.auto_failback.get('enabled', False),
                    "failback-delay": self.want.auto_failback.get('failback_delay', 30)
                }
            }
        }

        response = self.client.put(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            prefer_node=dict(type='str', required=True, choices=['active-controller', 'prefer-1', 'prefer-2', 'auto']),
            auto_failback=dict(
                type='dict',
                options=dict(
                    enabled=dict(type='bool', default=False),
                    failback_delay=dict(type='int', default=30)
                )
            ),
            state=dict(
                default='present',
                choices=['present']
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
