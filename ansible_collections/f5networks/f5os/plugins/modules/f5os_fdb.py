#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_fdb
short_description: Manage Layer 2 forwarding database (FDB) entry in the system
description:
  - Manage Layer 2 forwarding database (FDB) entry in the F5OS based systems like VELOS partitions or rSeries platforms.
version_added: "1.15.0"
options:
  mac_address:
    description:
      - Hex list representation of the Layer 2 MAC address.
      - The format must be exactly 6 octets in the format B(xx:xx:xx:xx:xx:xx)
    type: str
    required: True
  vlan_id:
    description:
      - The ID of the VLAN that is associated with the mac-address for the FDB object
      - Valid value range is from C(0) to C(4095).
    required: True
    type: int
  interface:
    description:
      - The interface on which the MAC address is learned/Static Mapped for the FDB object
    required: True
    type: str
  tag_type:
    description:
      - The manner in which the FDB will interpret the VLAN value during lookup processing
    choices:
      - tag_type_vid
      - tag_type_vlan_tag
      - tag_type_vni
      - tag_type_s_tag_c_tag
    type: str
  state:
    description:
      - The Layer 2 forwarding database (FDB) state.
      - If C(present), creates Layer 2 forwarding database (FDB) if it does not exist, or updates the existing Layer 2 forwarding database (FDB).
      - If C(absent), deletes the Layer 2 forwarding database (FDB) if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - This module will not execute on VELOS controller.
author:
  - Ravinder Reddy Chinthalapalli (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Create Layer 2 forwarding database (FDB) entry in the system
  f5os_fdb:
    mac_address: 11:22:33:44:55:66
    vlan_id: 1234
    interface: 1.0
    state: present

- name: Update Layer 2 forwarding database (FDB) entry in the system
  f5os_fdb:
    mac_address: 11:22:33:44:55:66
    vlan_id: 1234
    interface: 1.0
    state: present

- name: Layer 2 forwarding database (FDB) entry in the system
  f5os_fdb:
    mac_address: 11:22:33:44:55:66
    vlan_id: 1234
    interface: 1.0
    state: absent
'''

RETURN = r'''
mac_address:
  description: The name of the VLAN.
  returned: changed
  type: str
  sample: xx:xx:xx:xx:xx:xx
interface:
  description: The interface for the FDB object
  returned: changed
  type: str
  sample: 1.0
vlan_id:
  description: The ID of the VLAN.
  returned: changed
  type: int
  sample: 1234
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
    api_map = {
        'mac-address': 'mac_address',
        'vlan': 'vlan_id',
        'interface': 'interface',
        'tag-type': 'tag_type'
    }
    api_attributes = [
        'mac-address',
        'interface',
        'vlan',
        'tag-type'
    ]
    returnables = [
        'mac_address',
        'interface',
        'vlan_id',
        'tag_type',
    ]

    updatables = [
        'mac_address',
        'interface',
        'vlan_id',
        'tag_type',
    ]


class ApiParameters(Parameters):

    @property
    def interface(self):
        if self._values['interface'] is None:
            return None
        return self._values['interface']['interface-ref']['config']['interface']


class ModuleParameters(Parameters):
    @property
    def vlan_id(self):
        result = self._values['vlan_id']
        if result < 0 or result > 4095:
            raise F5ModuleError(
                "Valid 'vlan_id' must be in range 0 - 4095."
            )
        return result

    @property
    def mac_address(self):
        if self._values['mac_address'] is None:
            return None
        return self._values['mac_address']

    @property
    def interface(self):
        if self._values['interface'] is None:
            return None
        return self._values['interface']

    @property
    def tag_type(self):
        if self._values['tag_type'] is None:
            return "tag_type_vid"
        return self._values['tag_type']


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
        # if self.client.platform == 'Velos Controller':
        #     raise F5ModuleError("Target device is a VELOS controller, aborting.")
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
        self.create_on_device()
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
        uri = f"/f5-l2fdb:fdb/mac-table/entries/entry={self.want.mac_address},{self.want.vlan_id},{self.want.tag_type}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        interface_dict = {
            'interface-ref': {
                'config': {'interface': self.want.interface}
            }
        }
        uri = "/f5-l2fdb:fdb"
        params = {'f5-l2fdb:fdb': {'mac-table': {'entries': {'entry': [{'mac-address': self.want.mac_address,
                                                                        'tag-type': self.want.tag_type,
                                                                        'interface': interface_dict,
                                                                        'vlan': self.want.vlan_id}
                                                                        ]}}}}  # noqa: E124
        response = self.client.patch(uri, data=params)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        uri = f"/f5-l2fdb:fdb/mac-table/entries/entry={self.want.mac_address},{self.want.vlan_id},{self.want.tag_type}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/f5-l2fdb:fdb/mac-table/entries/entry={self.want.mac_address},{self.want.vlan_id},{self.want.tag_type}"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents']['f5-l2fdb:entry'][0])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            mac_address=dict(
                required=True,
                type="str",
            ),
            interface=dict(
                required=True,
                type="str",
            ),
            tag_type=dict(
                type="str",
                choices=['tag_type_vid', 'tag_type_vlan_tag', 'tag_type_s_tag_c_tag', 'tag_type_vni']
            ),
            vlan_id=dict(
                required=True,
                type="int",
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
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
