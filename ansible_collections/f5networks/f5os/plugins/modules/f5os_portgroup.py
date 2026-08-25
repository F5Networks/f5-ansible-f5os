#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_portgroup
short_description: Manage port group configuration on F5 rSeries devices
description:
  - Manage port group configuration on F5 rSeries devices via the F5OS RESTCONF API.
  - This module allows configuring the port group mode (e.g., 4x25G, 2x50G, 1x100G) for
    network interfaces on rSeries platforms.
  - This module is only supported on rSeries platforms and will fail on VELOS systems.
version_added: "1.23.0"
options:
  name:
    description:
      - The name of the port group to configure.
      - This is typically in the format C(portgroup_name), for example C(1/1) or C(1/2).
    type: str
    required: true
  mode:
    description:
      - The mode to set for the port group.
      - Defines how the physical port is split or configured.
      - Common values include C(MODE_4x25G), C(MODE_2x50G), C(MODE_1x100G),
        C(MODE_4x10G), C(MODE_1x40G), and C(MODE_2x100G).
    type: str
  state:
    description:
      - The desired state of the port group configuration.
      - When C(present), ensures the port group is configured with the specified mode.
      - When C(absent), deletes the port group configuration, resetting it to the device default.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - F5 Networks (@f5networks)
notes:
  - This module is supported only on F5OS rSeries platforms. It is not supported on VELOS.
  - Port group names and supported modes are device-specific and depend on the hardware model.
'''

EXAMPLES = r'''
- name: Configure port group 1/1 in 4x25G mode
  f5networks.f5os.f5os_portgroup:
    name: "1/1"
    mode: "MODE_4x25G"
    state: present

- name: Configure port group 1/2 in 1x100G mode
  f5networks.f5os.f5os_portgroup:
    name: "1/2"
    mode: "MODE_1x100G"
    state: present

- name: Configure port group in 2x50G mode
  f5networks.f5os.f5os_portgroup:
    name: "1/1"
    mode: "MODE_2x50G"
    state: present

- name: Reset port group 1/1 to device default
  f5networks.f5os.f5os_portgroup:
    name: "1/1"
    state: absent
'''

RETURN = r'''
mode:
  description: The configured mode of the port group.
  returned: changed
  type: str
  sample: "MODE_4x25G"
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

    api_attributes = [
        'mode',
    ]

    returnables = [
        'mode',
    ]

    updatables = [
        'mode',
    ]


class ApiParameters(Parameters):
    pass


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

    @property
    def _portgroup_uri(self):
        name_encoded = self.want.name.replace('/', '%2F')
        return (
            "/openconfig-platform:components/component=platform"
            "/port/f5-platform-port:portgroups"
            "/portgroup={0}".format(name_encoded)
        )

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
        if self.client.platform != 'rSeries Platform':
            raise F5ModuleError(
                "Target device is not an rSeries platform. "
                "The f5os_portgroup module is only supported on rSeries devices."
            )
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            raise F5ModuleError(
                "Port group '{0}' does not exist on the device. "
                "Port groups are hardware-defined and cannot be created.".format(self.want.name)
            )

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def exists(self):
        response = self.client.get(self._portgroup_uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update(self):
        self.have = self.read_current_from_device()
        if not self._update_changed_options():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def read_current_from_device(self):
        response = self.client.get(self._portgroup_uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        contents = response['contents']
        portgroups = contents.get('f5-platform-port:portgroup', [])
        pg = portgroups[0] if portgroups else {}
        config = pg.get('config', {})
        params = dict(
            name=config.get('name'),
            mode=config.get('mode'),
        )
        return ApiParameters(params=params)

    def update_on_device(self):
        uri = self._portgroup_uri + '/config'
        payload = {
            "f5-platform-port:config": {
                "name": self.want.name,
                "mode": self.changes.mode,
            }
        }
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        response = self.client.delete(self._portgroup_uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            mode=dict(),
            state=dict(
                default='present',
                choices=['present', 'absent'],
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['mode']],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
