#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_qos_mapping
short_description: Manage QoS Mappings on F5OS
description:
  - Manage QoS Mappings on F5OS.
version_added: 1.16.0
options:
  mapping_type:
    description:
      - Specifies the type of the standard that is to be mapped to the traffic priority.
    type: str
    choices:
      - dscp
      - 802.1p
    required: True
  traffic_priority:
    description:
      - Specify one of the existing traffic priorities.
    type: str
    required: True
  mapping_values:
    description:
      - A list of values where where every element is either an individual value or two numerical values
        separated by a C(-) denoting a range.
      - Valid values for C(802.1p) are 0-7, inclusive.
      - Valid values for C(dscp) are 0-63, inclusive.
    type: list
    elements: str
  state:
    description:
      - If C(present), creates the specified object if it does not exist, or updates the existing object.
      - If C(absent), deletes the object if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Rohit Upadhyay (@urohit011)
'''

EXAMPLES = r'''
- name: Create QoS 8021p mapping
  f5os_qos_mapping:
    mapping_type: "802.1p"
    traffic_priority: "test_tp"
    mapping_values:
      - "2-3"
      - "5"

- name: Create QoS dscp mapping
  f5os_qos_mapping:
    mapping_type: "dscp"
    traffic_priority: "test_tp"
    mapping_values:
      - "33-34"
      - "37"

- name: Remove QoS dscp mapping
  f5os_qos_mapping:
    mapping_type: "dscp"
    traffic_priority: "test_tp"
    state: absent
'''

RETURN = r'''
mapping_type:
  description: Specifies the type of the standard that is to be mapped to the traffic priority.
  returned: changed
  type: str
  sample: dscp
traffic_priority:
  description: Specify one of the existing traffic priorities.
  returned: changed
  type: str
  sample: test_tp
mapping_values:
  description: A list of values where where every element is either an individual value or two numerical values.
  returned: changed
  type: list
  sample: ["30-40", "41"]
'''

import datetime
import re

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
        "name": "traffic_priority",
        "value": "mapping_values",
    }

    api_attributes = [
        "name",
        "value",
    ]

    returnables = [
        # "mapping_type",
        "mapping_values",
        # "traffic_priority",
    ]

    updatables = [
        "mapping_values"
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    def _validate_range(self, a, b=None):
        mapping_type = self._values["mapping_type"]
        start, end = (0, 63) if mapping_type == "dscp" else (0, 7)

        if (a and b and start <= a < b <= end) or (start <= a <= end):
            return True

        raise F5ModuleError(
            f"for the mapping type {mapping_type}, the mapping values must be between {start} and {end}"
        )

    @property
    def mapping_values(self):
        values = self._values["mapping_values"]
        num_range = r"^\d+\-\d+$"

        res = set()

        for i in values:
            if re.match(num_range, i):
                a, b = map(int, i.split("-"))
                self._validate_range(a, b)
                res.update(range(a, b + 1))

            elif str(i).isdigit():
                self._validate_range(int(i))
                res.add(int(i))

            else:
                raise F5ModuleError(
                    "Invalid mapping value: {0}".format(i)
                )

        return sorted(list(res))

    @property
    def mapping_type(self):
        if self._values["mapping_type"] == "dscp":
            return "mapping-DSCP"
        elif self._values["mapping_type"] == "802.1p":
            return "mapping-8021p"


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
        mapping_type = self.want.mapping_type
        traffic_priority = self.want.traffic_priority

        uri = f"/f5-qos:qos/global-setting/config/{mapping_type}/traffic-priority={traffic_priority}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        if "value" not in params:
            raise F5ModuleError(
                "The parameter 'mapping_values' is required"
            )

        mapping_type = self.want.mapping_type
        traffic_priority = self.want.traffic_priority

        params.update({"name": traffic_priority})
        payload = {"traffic-priority": [params]}

        uri = f"/f5-qos:qos/global-setting/config/{mapping_type}"

        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()

        if "value" not in params:
            raise F5ModuleError(
                "The parameter 'mapping_values' is required"
            )

        mapping_type = self.want.mapping_type
        traffic_priority = self.want.traffic_priority

        params.update({"name": traffic_priority})
        payload = {"traffic-priority": [params]}

        uri = f"/f5-qos:qos/global-setting/config/{mapping_type}/traffic-priority={traffic_priority}"

        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        mapping_type = self.want.mapping_type
        traffic_priority = self.want.traffic_priority

        uri = f"/f5-qos:qos/global-setting/config/{mapping_type}/traffic-priority={traffic_priority}"
        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        mapping_type = self.want.mapping_type
        traffic_priority = self.want.traffic_priority

        uri = f"/f5-qos:qos/global-setting/config/{mapping_type}/traffic-priority={traffic_priority}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        params = response['contents']['f5-qos:traffic-priority'][0]

        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            mapping_type=dict(
                type="str",
                required=True,
                choices=["dscp", "802.1p"],
            ),
            traffic_priority=dict(
                type="str",
                required=True,
            ),
            mapping_values=dict(
                type="list",
                elements="str",
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
