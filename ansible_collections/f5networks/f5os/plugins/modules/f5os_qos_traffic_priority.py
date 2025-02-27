#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_qos_traffic_priority
short_description: Manage QoS Traffic Priorities on F5OS
description:
  - Manage QoS Traffic Priorities on F5OS.
version_added: 1.15.0
options:
  name:
    description:
      - Specifies the name of the traffic priority.
    type: str
  qos_status:
    description:
      - Specifies the status of the QoS.
    type: str
    choices:
      - disable
      - 802.1p
      - dscp
  default_qos:
    description:
      - Specifies the QoS for which the specified traffic priority will act as the default one.
    type: str
    choices:
      - 802.1p
      - dscp
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
- name: Create traffic priority on Velos
  f5os_qos_traffic_priority:
    name: test_traffic_priority
    default_qos: "802.1p"
    qos_status: "802.1p"

- name: Delete traffic priority on Velos
  f5os_qos_traffic_priority:
    name: test_traffic_priority
    state: absent
'''

RETURN = r'''
name:
  description: The name of the traffic priority.
  returned: changed
  type: str
  sample: test_tf
default_qos:
  description: The QoS for which the traffic priority is default for.
  returned: changed
  type: str
  sample: 802.1p
qos_status:
  description: The status of the QoS.
  returned: changed
  type: str
  sample: 802.1
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
        "default_qos",
        "qos_status",
    ]

    returnables = [
        "name",
        "default_qos",
        "qos_status",
    ]

    updatables = [
        "default_qos",
        "qos_status",
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def qos_status(self):
        if self._values.get("qos_status") is None:
            return None
        if self._values["qos_status"] == "disable":
            return "QoS-disabled"
        if self._values["qos_status"] == "802.1p":
            return "8021P-enabled"
        if self._values["qos_status"] == "dscp":
            return "DSCP-enabled"

    @property
    def default_qos(self):
        if self._values.get("default_qos") is None:
            return None
        if self._values["default_qos"] == "802.1p":
            return "mapping-8021p"
        if self._values["default_qos"] == "dscp":
            return "mapping-DSCP"


class Changes(Parameters):
    def to_return(self):  # pragma: no cover
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
        except AttributeError:  # pragma: no cover
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

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
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

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
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
        uri = f"/f5-qos:qos/global-setting/config/traffic-priorities/traffic-priority={self.want.name}"

        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_traffic_priority_on_device(self, params):
        uri = "/f5-qos:qos/global-setting/config/traffic-priorities"
        payload = {"f5-qos:traffic-priority": [{"name": params["name"]}]}

        response = self.client.post(uri, payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def make_default_traffic_priority_for_qos(self, params):
        qos_type = params["default_qos"]

        uri = f"/f5-qos:qos/global-setting/config/{qos_type}"
        k = f"f5-qos:{qos_type}"
        payload = {k: {"default-traffic-priority": self.want.name}}

        response = self.client.patch(uri, payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def change_qos_status(self, params):
        uri = "/f5-qos:qos/global-setting/config/status"

        payload = {"f5-qos:status": params["qos_status"]}

        response = self.client.put(uri, payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def create_on_device(self):
        params = self.changes.api_params()

        if "name" in params:
            self.create_traffic_priority_on_device(params)

        if "default_qos" in params:
            self.make_default_traffic_priority_for_qos(params)

        if "qos_status" in params:
            self.change_qos_status(params)

        return True

    def update_on_device(self):
        params = self.changes.api_params()

        if "default_qos" in params:
            self.make_default_traffic_priority_for_qos(params)

        if "qos_status" in params:
            self.change_qos_status(params)

        return True

    def remove_from_device(self):
        uri = f"/f5-qos:qos/global-setting/config/traffic-priorities/traffic-priority={self.want.name}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_traffic_priority_qos(self):
        uri_8021p = "/f5-qos:qos/global-setting/config/mapping-8021p/default-traffic-priority"

        response = self.client.get(uri_8021p)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        default = response['contents']['f5-qos:default-traffic-priority']
        if default == self.want.name:
            return "mapping-8021p"

        uri_dscp = "/f5-qos:qos/global-setting/config/mapping-DSCP/default-traffic-priority"
        response = self.client.get(uri_dscp)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        default = response['contents']['f5-qos:default-traffic-priority']
        if default == self.want.name:
            return "mapping-DSCP"

    def read_current_qos_status(self):
        if self.want.qos_status:
            uri = "/f5-qos:qos/global-setting/config/status"
            response = self.client.get(uri)

            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

            return response['contents']['f5-qos:status']

    def read_current_from_device(self):
        existing = dict()
        qos_status = None
        default_qos = None

        if self.want.default_qos:
            default_qos = self.read_current_traffic_priority_qos()
            existing['default_qos'] = default_qos

        if self.want.qos_status:
            qos_status = self.read_current_qos_status()
            existing['qos_status'] = qos_status

        return ApiParameters(params=existing)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            qos_status=dict(
                type="str",
                choices=["disable", "802.1p", "dscp"]
            ),
            name=dict(type="str"),
            default_qos=dict(
                type="str",
                choices=["802.1p", "dscp"]
            ),
            state=dict(
                default="present",
                choices=["present", "absent"]
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)

        self.required_one_of = [
            ["qos_status", "name"]
        ]
        self.required_if = [
            ["state", "absent", ["name"]]
        ]
        self.required_if = [
            ["default_qos", "802.1p", ["name"]],
            ["default_qos", "dscp", ["name"]]
        ]


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
