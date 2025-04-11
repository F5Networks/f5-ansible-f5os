#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_controller_management_interfaces
short_description: Manage DHCP, IPv4 and IPv6 on F5OS devices
description:
  - Manage DHCP, IPv4, IPv6
  - IPv4 contains System Controller 1, System Controller 2, Floating, Prefix length, Gateway
  - IPv6 contains System Controller 1, System Controller 2, Floating, Prefix length, Gateway
version_added: 1.16.0
options:
  dhcp:
    description:
      - This specifies Configuration of DHCP. DHCP is supported only on static interfaces
    type: bool
    required: true
  ipv4:
    description: This specifies Configuration of IPv4
    type: dict
    suboptions:
        system_controller_1:
            description: Specifies the System Controller 1 IPv4. The IPv4 address for the System Controller 1.
            type: str
            default: "0.0.0.0"
        system_controller_2:
            description: Specifies the System Controller 2 IPv4. The IPv4 address for the System Controller 2.
            type: str
            default: "0.0.0.0"
        floating:
            description: Specifies the Floating IPv4.
            type: str
            default: "0.0.0.0"
        prefix_length:
            description: Specifies the Prefix length of IPv4. The length of the subnet prefix (leaf).
            type: int
            default: 0
        gateway:
            description: Specifies the Gateway for IPv4. The default gateway for the subnet (leaf).
            type: str
            default: "0.0.0.0"
  ipv6:
    description: This specifies Configuration of IPv6
    type: dict
    suboptions:
        system_controller_1:
            description: Specifies the System Controller 1 IPv6. The IPv6 address for the System Controller 1.
            type: str
            default: "::"
        system_controller_2:
            description: Specifies the System Controller 2 IPv6. The IPv6 address for the System Controller 2.
            type: str
            default: "::"
        floating:
            description: Specifies the Floating IPv6
            type: str
            default: "::"
        prefix_length:
            description: Specifies the Prefix length of IPv6. The length of the subnet prefix (leaf).
            type: int
            default: 0
        gateway:
            description: Specifies the Gateway for IPv6. The default gateway for the subnet (leaf).
            type: str
            default: "::"
  state:
    description:
      - If C(present), Configurations are posted on F5OS.
    type: str
    choices:
      - present
    default: present
notes:
  - Delete is not supported for this module.

author:
  - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''
- name: Manage DHCP, IPv4 and IPv6 on F5OS devices
  velos_controller_management_interfaces:
    dhcp: true
    ipv4:
      system_controller_1: 10.1.1.1
      system_controller_2: 10.1.1.2
      floating: 10.1.1.3
      prefix_length: 24
      gateway: 10.1.1.1
    ipv6:
      system_controller_1: 2001:db8:1::1
      system_controller_2: 2001:db8:1::2
      floating: 2001:db8:1::3
      prefix_length: 64
      gateway: 2001:db8:1::1
    state: present
'''

RETURN = r'''
dhcp:
  description: This specifies Configuration of DHCP. DHCP is supported only on static interfaces (leaf)
  returned: changed
  type: bool
ipv4:
  description: This specifies Configuration of IPv4
  returned: changed
  type: complex
  contains:
    system_controller_1:
      description: Specifies the System Controller 1 IPv4. The IPv4 address for the System Controller 1.
      returned: changed
      type: str
    system_controller_2:
      description: Specifies the System Controller 2 IPv4. The IPv4 address for the System Controller 2.
      returned: changed
      type: str
    floating:
      description: Specifies the Floating IPv4.
      returned: changed
      type: str
    prefix_length:
      description: Specifies the Prefix length of IPv4. The length of the subnet prefix (leaf).
      returned: changed
      type: int
    gateway:
      description: Specifies the Gateway for IPv4. The default gateway for the subnet (leaf).
      returned: changed
      type: str
ipv6:
  description: This specifies Configuration of IPv6
  returned: changed
  type: complex
  contains:
    system_controller_1:
      description: Specifies the System Controller 1 IPv6. The IPv6 address for the System Controller 1.
      returned: changed
      type: str
    system_controller_2:
      description: Specifies the System Controller 2 IPv6. The IPv6 address for the System Controller 2.
      returned: changed
      type: str
    floating:
      description: Specifies the Floating IPv6.
      returned: changed
      type: str
    prefix_length:
      description: Specifies the Prefix length of IPv6. The length of the subnet prefix (leaf).
      returned: changed
      type: int
    gateway:
      description: Specifies the Gateway for IPv6. The default gateway for the subnet (leaf).
      returned: changed
      type: str
'''

import datetime

from ansible.module_utils.basic import (
    AnsibleModule
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = [
        "dhcp",
        "ipv4",
        "ipv6"
    ]

    returnables = [
        "dhcp",
        "ipv4",
        "ipv6"
    ]

    updatables = [
        "dhcp",
        "ipv4",
        "ipv6"
    ]


class ApiParameters(Parameters):

    @property
    def dhcp(self):
        try:
            return self._values['config']['dhcp-enabled']
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def ipv4(self):
        try:
            result = {}
            result['system_controller_1'] = self._values['config']['ipv4']['controller-1']['address']
            result['system_controller_2'] = self._values['config']['ipv4']['controller-2']['address']
            result['floating'] = self._values['config']['ipv4']['floating']['address']
            result['prefix_length'] = self._values['config']['ipv4']['prefix-length']
            result['gateway'] = self._values['config']['ipv4']['gateway']
            return result
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def ipv6(self):
        try:
            result = {}
            result['system_controller_1'] = self._values['config']['ipv6']['controller-1']['address']
            result['system_controller_2'] = self._values['config']['ipv6']['controller-2']['address']
            result['floating'] = self._values['config']['ipv6']['floating']['address']
            result['prefix_length'] = self._values['config']['ipv6']['prefix-length']
            result['gateway'] = self._values['config']['ipv6']['gateway']
            return result
        except (TypeError, ValueError, KeyError):
            return None


class ModuleParameters(Parameters):
    @property
    def dhcp(self):
        if not self._values['dhcp']:
            return False
        return True

    @property
    def ipv4(self):
        if self._values['ipv4'] is None:
            result = {}
            result['system_controller_1'] = "0.0.0.0"
            result['system_controller_2'] = "0.0.0.0"
            result['floating'] = "0.0.0.0"
            result['prefix_length'] = 0
            result['gateway'] = "0.0.0.0"
            return result
        return self._values['ipv4']

    @property
    def ipv6(self):
        if self._values['ipv6'] is None:
            result = {}
            result['system_controller_1'] = "::"
            result['system_controller_2'] = "::"
            result['floating'] = "::"
            result['prefix_length'] = 0
            result['gateway'] = "::"
            return result
        return self._values['ipv6']


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
            return result  # pragma: no cover
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

    def _set_changed_options(self):  # pragma: no cover
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
                    changed.update(change)  # pragma: no cover
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
        # elif state == "absent":
        #     changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        return self.update()

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
        self.create_on_device()
        return True

    def create_on_device(self):
        params = {}
        params["f5-mgmt-ip:mgmt-ip"] = {}
        params["f5-mgmt-ip:mgmt-ip"]["config"] = {}
        params["f5-mgmt-ip:mgmt-ip"]["config"]["dhcp-enabled"] = self.want.dhcp

        if self.want.ipv4 is not None:
            ipv4 = {
                "controller-1": {
                    "address": self.want.ipv4["system_controller_1"]
                },
                "controller-2": {
                    "address": self.want.ipv4["system_controller_2"]
                },
                "floating": {
                    "address": self.want.ipv4["floating"]
                },
                "prefix-length": self.want.ipv4["prefix_length"],
                "gateway": self.want.ipv4["gateway"]
            }

            params["f5-mgmt-ip:mgmt-ip"]["config"]["ipv4"] = ipv4

        if self.want.ipv6 is not None:
            ipv6 = {
                "controller-1": {
                    "address": self.want.ipv6["system_controller_1"]
                },
                "controller-2": {
                    "address": self.want.ipv6["system_controller_2"]
                },
                "floating": {
                    "address": self.want.ipv6["floating"]
                },
                "prefix-length": self.want.ipv6["prefix_length"],
                "gateway": self.want.ipv6["gateway"]
            }

            params["f5-mgmt-ip:mgmt-ip"]["config"]["ipv6"] = ipv6

        uri = "/openconfig-system:system/f5-mgmt-ip:mgmt-ip"

        response = self.client.patch(uri, data=params)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/f5-mgmt-ip:mgmt-ip"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return_object = response['contents']['f5-mgmt-ip:mgmt-ip']

        return ApiParameters(params=return_object)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            dhcp=dict(required=True, type="bool"),
            ipv4=dict(
                type="dict",
                options=dict(
                    system_controller_1=dict(
                        type="str",
                        default="0.0.0.0"
                    ),
                    system_controller_2=dict(
                        type="str",
                        default="0.0.0.0"
                    ),
                    floating=dict(
                        type="str",
                        default="0.0.0.0"
                    ),
                    prefix_length=dict(
                        type="int",
                        default=0
                    ),
                    gateway=dict(
                        type="str",
                        default="0.0.0.0"
                    ),
                )
            ),
            ipv6=dict(
                type="dict",
                options=dict(
                    system_controller_1=dict(
                        type="str",
                        default="::"
                    ),
                    system_controller_2=dict(
                        type="str",
                        default="::"
                    ),
                    floating=dict(
                        type="str",
                        default="::"
                    ),
                    prefix_length=dict(
                        type="int",
                        default=0
                    ),
                    gateway=dict(
                        type="str",
                        default="::"
                    ),
                )
            ),
            state=dict(
                default="present",
                choices=["present"]
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)

        self.required_if = []

        self.mutually_exclusive = []


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
