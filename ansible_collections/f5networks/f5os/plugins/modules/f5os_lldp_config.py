#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_lldp_config
short_description: Manage LLDP config
description:
  - Manages LLDP config.
version_added: "1.8.0"
options:
  enabled:
    description:
      - Specifies whether to enable LLDP or not.
    type: bool
    default: false
  system_name:
    description:
      - Name of the System.
    type: str
    default: ""
  system_description:
    description:
      - Description of the System.
    type: str
    default: ""
  tx_interval:
    description:
      - Interval (in seconds) at which LLDP packets are sent to neighbors.
      - This parameter value should lie between 0-65535.
    type: int
    default: 30
  tx_hold:
    description:
      - This parameter value should lie between 0-65535.
    type: int
    default: 4
  reinitiate_delay:
    description:
      - Specify the minimum time interval, in seconds, an LLDP port waits before re-initializing an LLDP transmission.
      - This parameter value should lie between 0-65535.
    type: int
    default: 2
  tx_delay:
    description:
      - Specify the minimum time delay, in seconds, between successive LLDP frame transmissions.
      - This parameter value should lie between 0-65535.
    type: int
    default: 2
  max_neighbors_per_port:
    description:
      - Specify the maximum number of LLDP neighbors for which LLDP data is retained.
    type: int
    default: 10
  interfaces:
    description: Specifies interfaces for which we want to enable LLDP.
    type: dict
    suboptions:
      name:
        description:
          - Specifies Interface to configure.
        type: str
      enabled:
        description:
          - Specify whether interface is enabled or not.
        type: bool
        default: false
      tlv_advertisement_state:
        description:
            - LLDP enables a network device to advertise information about itself to other devices on the network.
            - It enables network devices to receive information from neighboring devices.
        type: str
        choices:
          - rxonly
          - txrx
          - txonly
          - none
      tlv_map:
        description:
            - For TLV Map, select the TLV device information that you want to transmit and/or receive.
            - Such as chassis ID, MAC Phy configuration, management address, MFS (maximum frame size), port description, port ID, and power MDI.
        type: str
        default : chassis-id, port-id, ttl
  state:
    description:
      - If C(present), this option creates LLDP configuration on specified remote host.
      - If C(absent), this option disables LLDP configuration on the device (if it exists).
    type: str
    choices:
      - present
      - absent
    default: present


author:
  - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''
- name: Enable LLDP
  f5os_lldp_config:
    enabled: true
    system_name: test
    system_description: test description
    tx_interval: 30
    tx_hold: 4
    reinitiate_delay: 2
    tx_delay: 2
    max_neighbors_per_port: 13
    interfaces:
      name: 1.0
      enable: true
      tlv_advertisement_state: rxonly
      tlv_map: chassis-id port-id ttl system-name
'''
RETURN = r'''

enabled:
  description: Specifies whether to enable LLDP or not.
  returned: changed
  type: bool
  sample: true
system_name:
  description: Name of the System.
  returned: changed
  type: str
  sample: test
system_description:
  description: Description of the System.
  returned: changed
  type: str
  sample: test description
tx_interval:
  description: Interval (in seconds) at which LLDP packets are sent to neighbors.
  returned: changed
  type: int
  sample: 30
tx_hold:
  description: This parameter value should lie between 0-65535.
  returned: changed
  type: int
  sample: 4
reinitiate_delay:
  description: Specify the minimum time interval, in seconds, an LLDP port waits before re-initializing an LLDP transmission.
  returned: changed
  type: int
  sample: 2
tx_delay:
  description: Specify the minimum time delay, in seconds, between successive LLDP frame transmissions.
  returned: changed
  type: int
  sample: 2
max_neighbors_per_port:
  description: Specify the maximum number of LLDP neighbors for which LLDP data is retained.
  returned: changed
  type: int
  sample: 2
'''


import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
    }

    api_attributes = [
    ]

    returnables = [
        'enabled',
        'system_name',
        'system_description',
        'tx_interval',
        'tx_hold',
        'reinitiate_delay',
        'tx_delay',
        'max_neighbors_per_port',
        'tlv_advertisement_state',
        'tlv_map'
    ]

    updatables = [
        'enabled',
        'system_name',
        'system_description',
        'tx_interval',
        'tx_hold',
        'reinitiate_delay',
        'tx_delay',
        'max_neighbors_per_port',
        'interfaces'
    ]


class ApiParameters(Parameters):

    @property
    def enabled(self):
        try:
            return bool(self._values['config']['enabled'])
        except (TypeError, ValueError):
            return None

    @property
    def system_name(self):
        try:
            return str(self._values['config']['system-name'])
        except (TypeError, ValueError):
            return None

    @property
    def system_description(self):
        try:
            return str(self._values['config']['system-description'])
        except (TypeError, ValueError):
            return None

    @property
    def tx_interval(self):
        try:
            return int(self._values['config']['f5-lldp:tx-interval'])
        except (TypeError, ValueError):
            return None

    @property
    def tx_hold(self):
        try:
            return int(self._values['config']['f5-lldp:tx-hold'])
        except (TypeError, ValueError):
            return None

    @property
    def reinitiate_delay(self):
        try:
            return int(self._values['config']['f5-lldp:reinit-delay'])
        except (TypeError, ValueError):
            return None

    @property
    def tx_delay(self):
        try:
            return int(self._values['config']['f5-lldp:tx-delay'])
        except (TypeError, ValueError):
            return None

    @property
    def max_neighbors_per_port(self):
        try:
            return int(self._values['config']['f5-lldp:max-neighbors-per-port'])
        except (TypeError, ValueError):
            return None

    @property
    def interfaces(self):
        try:
            return self._values['interfaces']['interface']
        except (TypeError, ValueError):
            return None


class ModuleParameters(Parameters):

    def _validate_max_size(self, size, param):
        if 0 > size or size > 65535:
            raise F5ModuleError(
                "Valid " + param + " must be in range 0 - 65535."
            )

    @property
    def enabled(self):
        if self._values['enabled'] is None:
            return False
        return self._values['enabled']

    @property
    def system_name(self):
        if self._values['system_name'] is None:
            return ''
        return self._values['system_name']

    @property
    def system_description(self):
        if self._values['system_description'] is None:
            return ''
        return self._values['system_description']

    @property
    def tx_interval(self):
        if self._values['tx_interval'] is None:
            return 30
        self._validate_max_size(self._values['tx_interval'], "tx_interval")
        return self._values['tx_interval']

    @property
    def tx_hold(self):
        if self._values['tx_hold'] is None:
            return 4

        self._validate_max_size(self._values['tx_hold'], "tx_hold")
        return self._values['tx_hold']

    @property
    def reinitiate_delay(self):
        if self._values['reinitiate_delay'] is None:
            return 2

        self._validate_max_size(self._values['reinitiate_delay'], "reinitiate_delay")
        return self._values['reinitiate_delay']

    @property
    def tx_delay(self):
        if self._values['tx_delay'] is None:
            return 2

        self._validate_max_size(self._values['tx_delay'], "tx_delay")
        return self._values['tx_delay']

    @property
    def max_neighbors_per_port(self):
        if self._values['max_neighbors_per_port'] is None:
            return 10

        self._validate_max_size(self._values['max_neighbors_per_port'], "max_neighbors_per_port")
        return self._values['max_neighbors_per_port']


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
    returnables = [
        'enabled',
        'system_name',
        'system_description',
        'tx_interval',
        'tx_hold',
        'reinitiate_delay',
        'tx_delay',
        'max_neighbors_per_port',
        'tlv_advertisement_state',
        'tlv_map'
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
    def interfaces(self):
        if self.want.interfaces is not None:
            if self.have.interfaces is not None:
                for interface in self.have.interfaces:
                    if interface['name'] == self.want.interfaces['name']:
                        changes = {}
                        if interface['config']['enabled'] != self.want.interfaces['enabled']:
                            changes['enabled'] = self.want.interfaces['enabled']
                        if interface['config']['f5-lldp:tlv-advertisement-state'] != self.want.interfaces['tlv_advertisement_state']:
                            changes['tlv_advertisement_state'] = self.want.interfaces['tlv_advertisement_state']
                        if interface['config']['f5-lldp:tlvmap'] != self.want.interfaces['tlv_map']:
                            changes['tlv_map'] = self.want.interfaces['tlv_map']
                        return changes
                return self.want.interfaces
            else:
                return self.want.interfaces
        return None


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params, client=self.client)
        self.changes = UsableChanges()
        self.have = ApiParameters()

    def _set_changed_options(self):

        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

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
        return self.create()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        payload = {
            'openconfig-lldp:lldp': {
                'config': {
                    'enabled': self.want.enabled,
                    'system-name': self.want.system_name,
                    'system-description': self.want.system_description,
                    'f5-lldp:tx-interval': self.want.tx_interval,
                    'f5-lldp:tx-hold': self.want.tx_hold,
                    'f5-lldp:reinit-delay': self.want.reinitiate_delay,
                    'f5-lldp:tx-delay': self.want.tx_delay,
                    'f5-lldp:max-neighbors-per-port': self.want.max_neighbors_per_port
                }
            }
        }
        # Posting LLDP Config

        uri = "/openconfig-lldp:lldp"
        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        tobeCreated = True
        if self.want.interfaces is not None:
            self.have = self.read_current_from_device()

            if self.have.interfaces is None:
                tobeCreated = True
            else:
                for interface in self.have.interfaces:
                    if interface['name'] == self.want.interfaces['name']:
                        tobeCreated = False
                        break
            if tobeCreated:
                interfaces = {
                    "openconfig-lldp:interface": [
                        {
                            'name': self.want.interfaces['name'],
                            'config': {
                                'name': self.want.interfaces['name'],
                                'enabled': self.want.interfaces['enabled'],
                                "f5-lldp:tlv-advertisement-state": self.want.interfaces['tlv_advertisement_state'],
                                "f5-lldp:tlvmap": self.want.interfaces['tlv_map']
                            }
                        }
                    ]
                }

                # Posting Interfaces
                uri = '/openconfig-lldp:lldp/interfaces'
                response = self.client.post(uri, data=interfaces)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])
            else:
                interfaces = {
                    'openconfig-lldp:config': {
                        "enabled": self.want.interfaces['enabled'],
                        "f5-lldp:tlv-advertisement-state": self.want.interfaces['tlv_advertisement_state'],
                        "f5-lldp:tlvmap": self.want.interfaces['tlv_map']
                    }
                }

                # Patching Interfaces
                uri = f"/openconfig-lldp:lldp/interfaces/interface={self.want.interfaces['name'].replace('/', '%2F')}/config"
                response = self.client.patch(uri, data=interfaces)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

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

    def update_on_device(self):
        self.create_on_device()

    def read_current_from_device(self):
        uri = "/openconfig-lldp:lldp"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents']['openconfig-lldp:lldp'])

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        return True

    def remove_from_device(self):
        self.have = self.read_current_from_device()
        uri = "/openconfig-lldp:lldp/interfaces/interface="
        if self.have.interfaces is not None:
            for interface in self.have.interfaces:
                name = interface['name']
                name = name.replace('/', '%2F')
                deleteUrl = uri + name
                response = self.client.delete(deleteUrl)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        payload = {
            'openconfig-lldp:lldp': {
                'config': {
                    'enabled': False,
                    'system-name': '',
                    'system-description': '',
                    'f5-lldp:tx-interval': 30,
                    'f5-lldp:tx-hold': 4,
                    'f5-lldp:reinit-delay': 2,
                    'f5-lldp:tx-delay': 2,
                    'f5-lldp:max-neighbors-per-port': 10
                }
            }
        }

        uri = "/openconfig-lldp:lldp"
        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        return True

    def exists(self):
        uri = "/openconfig-lldp:lldp"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        config = response['contents']['openconfig-lldp:lldp']['config']
        if 'system-name' in config:
            if config['system-name'] is None:
                return False
            if self.want.system_name == config['system-name']:
                return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            enabled=dict(
                type="bool",
                default=False
            ),
            system_name=dict(
                type="str",
                default=""
            ),
            system_description=dict(
                type="str",
                default=""
            ),
            tx_interval=dict(
                type="int",
                default=30
            ),
            tx_hold=dict(
                type="int",
                default=4
            ),
            reinitiate_delay=dict(
                type="int",
                default=2
            ),
            max_neighbors_per_port=dict(
                type="int",
                default=10
            ),
            tx_delay=dict(
                type="int",
                default=2
            ),
            interfaces=dict(
                type="dict",
                options=dict(
                    name=dict(
                        type="str"
                    ),
                    enabled=dict(
                        type="bool",
                        default=False
                    ),
                    tlv_advertisement_state=dict(
                        type="str",
                        choices=['rxonly', 'txrx', 'txonly', 'none']
                    ),
                    tlv_map=dict(
                        type="str",
                        default="chassis-id, port-id, ttl"
                    )
                )
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
