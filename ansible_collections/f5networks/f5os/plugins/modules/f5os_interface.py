#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_interface
short_description: Manage network interfaces on F5OS based systems
description:
  - Manage network interfaces on F5OS systems like VELOS partitions or rSeries platforms.
version_added: "1.0.0"
options:
  name:
    description:
      - Name of the interface to configure.
      - "For VELOS partitions blade/port format is required e.g. 1/1.0"
    type: str
    required: true
  trunk_vlans:
    description:
      - Configures multiple VLAN IDs to associate with the interface.
      - The C(trunk_vlans) parameter is used for tagged traffic.
      - VLANs should not be assigned to interfaces if Link Aggregation Groups. In that case, VLANs should be added to
        the the LAG configuration with C(f5os_lag) module instead.
      - The order of these VLANs is ignored, the module orders the VLANs automatically.
    type: list
    elements: int
  native_vlan:
    description:
      - Configures the VLAN ID to associate with the interface.
      - The C(native_vlans) parameter is used for untagged traffic.
    type: int
  enabled:
    description:
      - "Configures the interface state as Enabled if C(True) or Disabled id C(False)."
      - "Configures the Operational Status as UP if C(True) or DOWN id C(False)."
    type: bool
    version_added: "1.15.0"
  description:
    description:
      - "Configures the description of Interface"
    type: str
    version_added: "1.15.0"
  forward_error_correction:
    description:
      - "Configures the forward error correction on Interface"
    type: str
    version_added: "1.15.0"
    choices:
      - auto
      - enabled
      - disabled
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
  - MTU, Interface Type are not editable.
author:
  - Ravinder Reddy (@chinthalapalli)
  - Wojciech Wypior (@wojtek0806)
  - Prateek Ramani (@ramani)
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

- name: Attach Vlans to interface on Velos Partition
  f5os_interface:
    name: "2/1.0"
    trunk_vlans: [444]
    state: present

- name: Modify Vlans to interface on Velos Partition
  f5os_interface:
    name: "2/1.0"
    trunk_vlans: [444, 555]
    state: present

- name: Delete vlans on interface on Velos Partition
  f5os_interface:
    name: "1.0"
    trunk_vlans: [444, 555]
    state: absent

- name: Attach Vlans to interface on rSeries Platform
  f5os_interface:
    name: "1.0"
    trunk_vlans: [444]
    state: present

- name: Modify Vlans to interface on rSeries Platform
  f5os_interface:
    name: "1.0"
    trunk_vlans: [444, 555]
    state: present

- name: Delete vlans on interface on rSeries Platform
  f5os_interface:
    name: "1.0"
    trunk_vlans: [444, 555]
    state: absent
'''

RETURN = r'''
name:
  description: Name of the partition interface to configure.
  returned: changed
  type: str
  sample: 1.0
trunk_vlans:
  description: Trunk VLANs to attach to the interface
  returned: changed
  type: list
  sample: [444,555]
native_vlan:
  description: Native VLAN to attach to the interface
  returned: changed
  type: int
  sample: 222
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
        'interface_type',
        'trunk_vlans',
        'enabled',
        'description',
        'forward_error_correction'
    ]

    updatables = [
        'name',
        'native_vlan',
        'trunk_vlans',
        'enabled',
        'description',
        'forward_error_correction'
    ]


class ApiParameters(Parameters):
    @property
    def interface_type(self):
        # Remove the 'iana-if-type:' prefix returned from the API.
        return re.sub(r'^{0}'.format(re.escape('iana-if-type:')), '', self._values['config']['type'])

    @property
    def trunk_vlans(self):
        interface = self._values['openconfig-if-ethernet:ethernet']
        if interface is None:
            return None
        if 'openconfig-vlan:switched-vlan' not in interface:
            return None
        return interface['openconfig-vlan:switched-vlan']['config'].get('trunk-vlans', None)

    @property
    def native_vlan(self):
        interface = self._values['openconfig-if-ethernet:ethernet']
        if interface is None:
            return None
        if 'openconfig-vlan:switched-vlan' not in interface:
            return None
        return interface['openconfig-vlan:switched-vlan']['config'].get('native-vlan', None)

    @property
    def enabled(self):
        return self._values['config']['enabled']

    @property
    def description(self):
        if 'description' not in self._values['config']:
            return None
        return self._values['config']['description']

    @property
    def forward_error_correction(self):
        if 'f5-interface:forward-error-correction' not in self._values['config']:
            return None
        return self._values['config']['f5-interface:forward-error-correction']


class ModuleParameters(Parameters):
    @staticmethod
    def _validate_vlan_ids(vlan):
        if 0 > vlan or vlan > 4095:
            raise F5ModuleError(
                "Valid 'vlan_id' must be in range 0 - 4095."
            )

    @property
    def name(self):
        interface_format = re.compile(r'(?P<blade>\d+)\/(?P<port>\d+\.\d+)')
        match = interface_format.match(self._values['name'])
        if match is None and self.client.platform == 'Velos Partition':
            raise F5ModuleError(
                "Valid interface name must be formatted 'blade/port'. e.g. '1/1.0'"
            )

        return self._values['name']

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
        'trunk_vlans'
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
    def enabled(self):
        if self.want.enabled == self.have.enabled:
            return None
        else:
            return self.want.enabled


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params, client=self.client)
        self.changes = UsableChanges()
        self.have = ApiParameters()

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
            raise F5ModuleError(
                "Interface {0} does not exist. This module can only update existing interfaces".format(
                    self.want.name
                )
            )

    def absent(self):
        if self.exists() and self._vlans_exist_on_interface():
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
        self.have = self.read_current_from_device()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        return True

    def exists(self):
        interface_encoded = self._encode_interface_name()
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        params = self.changes.to_return()
        interface_encoded = self._encode_interface_name()

        payload = {}
        if 'enabled' in params or params.get('description') or params.get('forward_error_correction'):
            uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}"

            config = dict()
            if 'enabled' in params:
                config['enabled'] = params['enabled']
            if params.get('description'):
                config['description'] = params['description']
            if params.get('forward_error_correction'):
                config['f5-interface:forward-error-correction'] = params['forward_error_correction']

            payload = {'interface': []}
            payload['interface'].append({"config": config})

            response = self.client.patch(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

        vlans = dict()
        if params.get('trunk_vlans', None):
            vlans['trunk-vlans'] = params['trunk_vlans']
        if params.get('native_vlan', None):
            vlans['native-vlan'] = params['native_vlan']
        if vlans:
            uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
                  f"/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan"
            payload = {"openconfig-vlan:switched-vlan": {"config": vlans}}
            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        self.remove_vlans()
        return True

    def _remove_trunk_vlans(self, vlan):
        interface_encoded = self._encode_interface_name()
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/openconfig-vlan:switched-vlan/openconfig-vlan:config/openconfig-vlan:trunk-vlans={vlan}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def _remove_native_vlan(self):
        interface_encoded = self._encode_interface_name()
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/openconfig-vlan:switched-vlan/openconfig-vlan:config/openconfig-vlan:native-vlan"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        interface_encoded = self._encode_interface_name()
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents']['openconfig-interfaces:interface'][0])

    def _encode_interface_name(self):
        """
        Helper method -- Encode interface name (/ -> %2F).
        Use this method after confirming interface is
            valid using self.verify(interface: str)
        :return interface_encoded: str
        """
        return quote(self.want.name, safe='')

    def remove_vlans(self):
        if self.have.trunk_vlans is not None:
            for vlan in self.have.trunk_vlans:
                self._remove_trunk_vlans(vlan)
        if self.have.native_vlan is not None:
            self._remove_native_vlan()
        return True

    def _vlans_exist_on_interface(self):
        interface_encoded = self._encode_interface_name()
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/openconfig-vlan:switched-vlan"
        response = self.client.get(uri)
        if response['code'] in [200, 201, 202]:
            return True
        if response['code'] == 204:
            return False
        raise F5ModuleError(response['contents'])


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
            native_vlan=dict(
                type="int",
            ),
            description=dict(),
            enabled=dict(
                type="bool",
            ),
            forward_error_correction=dict(
                choices=['auto', 'enabled', 'disabled']
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
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
