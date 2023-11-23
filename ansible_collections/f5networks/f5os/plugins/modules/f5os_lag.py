#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_lag
short_description: Manage LAG interfaces on F5OS based systems
description:
  - Manage LAG interfaces on F5OS systems like VELOS partitions or rSeries platforms.
version_added: "1.0.0"
options:
  name:
    description:
      - Name of the interface to configure.
    type: str
    required: true
  trunk_vlans:
    description:
      - Configures multiple VLAN IDs to associate with the Link Aggregation Group.
      - The C(trunk_vlans) parameter is used for tagged traffic.
      - The order of these VLANs is ignored, the module orders the VLANs automatically.
    type: list
    elements: int
  native_vlan:
    description:
      - Configures the VLAN ID to associate with the Link Aggregation Group.
      - The C(native_vlans) parameter is used for untagged traffic.
    type: int
  lag_type:
    description:
      - The LAG type of the interface to be created.
      - Parameter is required when creating new LAG interface.
    type: str
    choices:
      - lacp
      - static
  config_members:
    description:
      - "Configures the list of interfaces to be grouped for the Link Aggregation Group (LAG)."
      - "For VELOS partitions blade/port interface format is required e.g. 1/1.0"
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
notes:
  - This module will not execute on VELOS controller.
author:
  - Ravinder Reddy (@chinthalapalli)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Creating VLAN444
  f5os_vlan:
    name: vlan-444
    vlan_id: 444

- name: Creating VLAN555
  f5os_vlan:
    name: vlan-555
    vlan_id: 555

- name: Attach Trunk-vlans to LAG to interface
  f5os_lag:
    name: "Arista"
    lag_type: "lacp"
    trunk_vlans: [444]
    state: present

- name: Modify Vlans to LAG interface
  f5os_lag:
    name: "Arista"
    trunk_vlans: [444, 555]
    state: present

- name: Add interfaces to LAG on Velos Partition
  f5os_lag:
    name: "Arista"
    config_members:
      - "1/1.0"
    state: present

- name: Add interfaces to LAG on rSeries Platform
  f5os_lag:
    name: "Arista"
    config_members:
      - "1.0"
    state: present

- name: Delete LAG interface
  f5os_lag:
    name: "Arista"
    trunk_vlans: [444, 555]
    state: absent
'''

RETURN = r'''
name:
  description: Name of the partition LAG interface to configure
  returned: changed
  type: str
  sample: new_name
trunk_vlans:
  description: Trunk VLANs to attach to LAG interface
  returned: changed
  type: list
  sample: [444,555]
native_vlan:
  description: Native VLAN to attach to LAG interface
  returned: changed
  type: int
  sample: 222
lag_type:
  description: The LAG type of the interface to be created.
  returned: changed
  type: str
  sample: static
config_members:
  description: The list of interfaces to be grouped for the Link Aggregation Group
  returned: changed
  type: list
  sample: ["1.0", "2.0"]
'''
import datetime
import re

from urllib.parse import quote

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ansible_collections.f5networks.f5os.plugins.module_utils.compare import cmp_simple_list


class Parameters(AnsibleF5Parameters):
    api_map = {
        'type': 'interface_type'
    }

    api_attributes = []

    returnables = [
        'name',
        'native_vlan',
        'trunk_vlans',
        'interface_type',
        'config_members',
        'lag_type'
    ]

    updatables = [
        'native_vlan',
        'trunk_vlans',
        'config_members',
    ]


class ApiParameters(Parameters):
    @property
    def interface_type(self):
        # Remove the 'iana-if-type:' prefix returned from the API.
        return re.sub(r'^{0}'.format(re.escape('iana-if-type:')), '', self._values['config']['type'])

    @property
    def trunk_vlans(self):
        aggregate = self._values['openconfig-if-aggregate:aggregation']
        if aggregate is None:
            return None
        if 'openconfig-vlan:switched-vlan' not in aggregate:
            return None
        return aggregate['openconfig-vlan:switched-vlan']['config'].get('trunk-vlans', None)

    @property
    def native_vlan(self):
        aggregate = self._values['openconfig-if-aggregate:aggregation']
        if aggregate is None:
            return None
        if 'openconfig-vlan:switched-vlan' not in aggregate:
            return None
        return aggregate['openconfig-vlan:switched-vlan']['config'].get('native-vlan', None)

    @property
    def lag_type(self):
        if self._values['openconfig-if-aggregate:aggregation'] is None:
            return None
        return self._values['openconfig-if-aggregate:aggregation']['config'].get('lag-type', None)


class ModuleParameters(Parameters):
    @staticmethod
    def _validate_vlan_ids(vlan):
        if 0 > vlan or vlan > 4095:
            raise F5ModuleError(
                "Valid 'vlan_id' must be in range 0 - 4095."
            )

    @property
    def native_vlan(self):
        if self._values['native_vlan'] is None:
            return None
        self._validate_vlan_ids(self._values['native_vlan'])
        return self._values['native_vlan']

    @property
    def trunk_vlans(self):
        if self._values['trunk_vlans'] is None:
            return None
        vlans = self._values['trunk_vlans']
        for vlan in vlans:
            self._validate_vlan_ids(vlan)
        vlans.sort()
        return vlans

    @property
    def interface_type(self):
        return "{0}{1}".format('iana-if-type:', 'ieee8023adLag')

    @property
    def config_members(self):
        # Format: blade/port, or 1/1.0
        if self._values['config_members'] is None:
            return None
        interface_format = re.compile(r'(?P<blade>\d+)\/(?P<port>\d+\.\d+)')
        intf_members = self._values['config_members']
        if len(intf_members) > 0:
            for intf in intf_members:
                match = interface_format.match(intf)
                if match is None and self.client.platform == 'Velos Partition':
                    raise F5ModuleError(
                        "Valid interface name must be formatted 'blade/port'. e.g. '1/1.0'"
                    )
        return intf_members

    @property
    def lag_type(self):
        if self._values['lag_type'] is None:
            return None
        return self._values['lag_type'].upper()


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
    returnables = [
        'name',
        'native_vlan',
        'trunk_vlans',
        'config_members',
        'lag_type'
    ]


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
    def trunk_vlans(self):
        return cmp_simple_list(self.want.trunk_vlans, self.have.trunk_vlans)

    @property
    def config_members(self):
        return cmp_simple_list(self.want.config_members, self.have.config_members)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params, client=self.client)
        self.have = ApiParameters()
        self.changes = UsableChanges()

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
        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
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
        if self.want.lag_type is None:
            raise F5ModuleError("The parameter lag_type must not be empty when creating new LAG interface.")
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    @staticmethod
    def _populate_vlans(params, intf):
        if params.get('trunk_vlans', None):
            trunk_vlan = {
                "trunk-vlans": params['trunk_vlans'],
            }
            intf['openconfig-if-aggregate:aggregation']['openconfig-vlan:switched-vlan'] = dict(config=trunk_vlan)
        if params.get('native_vlan', None):
            native_vlan = {
                "native-vlan": params['native_vlan'],
            }
            if 'config' in intf['openconfig-if-aggregate:aggregation']['openconfig-vlan:switched-vlan']:
                intf['openconfig-if-aggregate:aggregation']['openconfig-vlan:switched-vlan']['config'].update(
                    native_vlan
                )
            else:
                intf['openconfig-if-aggregate:aggregation']['openconfig-vlan:switched-vlan'] = dict(
                    config=native_vlan)
        return intf

# TODO: replace the below blob and above helper function with json template at some point
    def create_on_device(self):
        params = self.changes.to_return()
        interface = {
            "name": params['name'],
            "config": {
                "name": params['name'],
                "type": params['interface_type'],
                "enabled": True,
            },
            "openconfig-if-aggregate:aggregation": {
                "config": {
                    "lag-type": params['lag_type'],
                    "f5-if-aggregate:distribution-hash": "src-dst-ipport",
                },
            }
        }
        payload = {
            'openconfig-interfaces:interfaces': {
                'interface': [self._populate_vlans(params, interface)]
            }
        }

        uri = "/"
        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        if params.get('config_members', None):
            for intf in params.get('config_members'):
                self._configure_member(intf)
        return True

    def update_on_device(self):
        params = self.changes.to_return()
        vlans = dict()
        if params.get('trunk_vlans', None):
            vlans['trunk-vlans'] = params['trunk_vlans']
        if params.get('native_vlan', None):
            vlans['native-vlan'] = params['native_vlan']
        if vlans:
            uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}" \
                  f"/openconfig-if-aggregate:aggregation/openconfig-vlan:switched-vlan"
            payload = {"openconfig-vlan:switched-vlan": {"config": vlans}}
            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
        if params.get('config_members', None):
            intf_to_add = set(self.want.config_members) - set(self.have.config_members)
            intf_to_delete = set(self.have.config_members) - set(self.want.config_members)
            for intf in intf_to_add:
                self._configure_member(intf)
            for intf in intf_to_delete:
                self._delete_member(intf)
        return True

    def remove_from_device(self):
        self.have = self.read_current_from_device()
        if self.have.config_members is not None:
            for intf in self.have.config_members:
                self._delete_member(intf)
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        intf_list = []
        for intf in self._get_interfaces():
            if self._is_lag_member(intf):
                intf_list.append(intf)

        config = dict(response['contents']['openconfig-interfaces:interface'][0])
        config.update(config_members=intf_list)
        return ApiParameters(params=config)

    def _encode_interface(self, intfname):
        """
        Helper method -- Encode interface name (/ -> %2F).
        :return interface_encoded: str
        """
        return quote(intfname, safe='')

    def _get_interfaces(self):
        uri = "/openconfig-interfaces:interfaces"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        intf_list = []
        for intdict in response['contents']['openconfig-interfaces:interfaces']['interface']:
            if intdict['config']['type'] == 'iana-if-type:ethernetCsmacd':
                intf_list.append(intdict['name'])
        return intf_list

    def _configure_member(self, intf):
        uri = "/"
        payload = {
            'openconfig-interfaces:interfaces': {
                'interface': [
                    {
                        'name': intf,
                        'config': {
                            'name': intf
                        },
                        'openconfig-if-ethernet:ethernet': {
                            'config': {
                                'openconfig-if-aggregate:aggregate-id': self.want.name
                            }
                        }
                    }
                ]
            }
        }
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def _delete_member(self, intf):
        interface_encoded = self._encode_interface(intf)
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/config/openconfig-if-aggregate:aggregate-id"

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def _is_lag_member(self, intf):
        interface_encoded = self._encode_interface(intf)
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/config/openconfig-if-aggregate:aggregate-id"
        response = self.client.get(uri)
        if response['code'] == 204:
            return False
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        if response['contents']['openconfig-if-aggregate:aggregate-id'] == self.want.name:
            return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            trunk_vlans=dict(
                type='list',
                elements='int',
            ),
            config_members=dict(
                type='list',
                elements='str',
            ),
            native_vlan=dict(
                type="int",
            ),
            lag_type=dict(
                choices=['lacp', 'static']
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
