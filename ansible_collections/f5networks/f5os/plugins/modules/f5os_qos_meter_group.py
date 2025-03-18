#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_qos_meter_group
short_description: Manage QoS meter groups on F5OS
description:
  - Manage QoS meter groups on F5OS.
version_added: 1.0.0
options:
  name:
    description:
      - Specifies the name of the meter group.
    type: str
    required: True
  interfaces:
    description:
      - Specifies the interfaces to associate with the meter group.
    type: list
    elements: str
  meters:
    description:
      - Specifies the list of traffic priorities and weights that together make a meter.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Specifies the name of the traffic priority.
        type: str
        required: true
      weight:
        description:
          - Specifies the weight to associate with the traffic priority.
        type: int
        required: true
  state:
    description:
      - If C(present), this option creates qkview file on specified remote host.
      - If C(absent), this option deletes qkview file on the device (if it exists).
      - When deleting a traffic priority make sure it is not the default for any QoS.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Rohit Upadhyay (@urohit011)
'''

EXAMPLES = r'''
- name: Create QoS meter group
  f5os_qos_meter_group:
    name: test_meter
    meters:
      - name: tp1
        weight: 2
      - name: tp2
        weight: 3
    interfaces:
      - "1.0"
      - "lag-prod"

- name: Remove QoS meter group
  f5os_qos_meter_group:
    name: test_meter
    state: absent
'''

RETURN = r'''
name:
  description: The name of the meter group.
  returned: changed
  type: str
  sample: meter_group_1
interfaces:
  description: List of interfaces that associate with the meter group.
  returned: changed
  type: list
  sample: ["1.0", "2.0"]
meters:
  description: List of traffic priorities and their weights.
  returned: changed
  type: list
  sample: [{"name": "traffic_priority_1", weight: 2}]
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        "name",
        "interfaces",
        "meters",
    ]

    returnables = [
        "name",
        "interfaces",
        "meters",
    ]

    updatables = [
        "interfaces",
        "meters",
    ]


class ApiParameters(Parameters):
    @property
    def interfaces(self):
        if self._values['interfaces'] is None:
            return None

        result = []
        for item in self._values['interfaces']:
            if item['meter-group'] == self._values['name']:
                result.append(item)

        return result

    @property
    def meters(self):
        if self._values['meters'] is None:
            return None

        if 'traffic-priority' in self._values['meters'] and self._values['meters']['traffic-priority']:
            return self._values['meters']


class ModuleParameters(Parameters):
    @property
    def interfaces(self):
        if self._values.get('interfaces') is None:
            return None

        result = []

        for intf in self._values["interfaces"]:
            result.append(
                {
                    "name": intf,
                    "meter-group": self._values["name"]
                }
            )

        return result

    @property
    def meters(self):
        if self._values.get('meters') is None:
            return None

        result = {"traffic-priority": self._values["meters"]}
        return result


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:  # pragma: no cover
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
        except AttributeError:  # pragma: no cover
            return attr1

    @property
    def meters(self):
        want = self.want.meters
        have = self.have.meters

        if want != have:
            return {'meters': want}


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

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:  # pragma: no cover
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:  # pragma: no cover
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
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
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        name = self.want.name
        uri = f"/f5-qos:qos/meter-setting/config/meter-groups/meter-group={name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def patch_interfaces(self, interfaces):
        payload = {
            'f5-qos:interfaces': {
                'interface': interfaces
            }
        }

        uri = "/f5-qos:qos/meter-setting/config/interfaces"

        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()

        interfaces = None
        if "interfaces" in params:
            interfaces = params.pop("interfaces")

        payload = {
            'f5-qos:meter-group': [params]
        }
        uri = "/f5-qos:qos/meter-setting/config/meter-groups"

        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if interfaces:
            self.patch_interfaces(interfaces)

        return True

    def _update_interfaces(self):
        have = self.have.interfaces
        want = self.want.interfaces

        remove_interfaces = []

        for intf1 in have:
            remove = True
            for intf2 in want:
                if intf1 == intf2:
                    remove = False
                    break
            if remove:
                remove_interfaces.append(intf1)

        if remove_interfaces:
            self._remove_qos_interfaces(remove_interfaces)

    def update_on_device(self):
        params = self.changes.api_params()
        name = self.want.name
        params["name"] = name
        interfaces = None

        if "interfaces" in params:
            interfaces = params.pop("interfaces")

        payload = {
            'f5-qos:meter-group': [params]
        }
        uri = f"/f5-qos:qos/meter-setting/config/meter-groups/meter-group={name}"
        response = self.client.put(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        self._update_interfaces()
        if interfaces:
            self.patch_interfaces(interfaces)

        return True

    def _remove_qos_interfaces(self, interfaces):
        name = self.want.name
        interfaces = [i for i in interfaces if i["meter-group"] == name]

        for interface in interfaces:
            intf = interface["name"]
            uri = f"/f5-qos:qos/meter-setting/config/interfaces/interface={intf}"
            response = self.client.delete(uri)

            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        interfaces = self._read_current_qos_interfaces()
        self._remove_qos_interfaces(interfaces)

        name = self.want.name
        uri = f"/f5-qos:qos/meter-setting/config/meter-groups/meter-group={name}"
        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def _read_current_qos_interfaces(self):
        uri = "/f5-qos:qos/meter-setting/config/interfaces/interface"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']['f5-qos:interface']

    def read_current_from_device(self):
        name = self.want.name
        uri = f"/f5-qos:qos/meter-setting/config/meter-groups/meter-group={name}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        params = None
        if response['contents']["f5-qos:meter-group"]:
            params = response['contents']["f5-qos:meter-group"][0]

        interfaces = self._read_current_qos_interfaces()

        params.update({"interfaces": interfaces})

        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            meters=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(
                        type='str',
                        required=True,
                    ),
                    weight=dict(
                        type='int',
                        required=True
                    ),
                ),
            ),
            interfaces=dict(
                type='list',
                elements='str',
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            )
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
