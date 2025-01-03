#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_stp_config
short_description: Manage STP config
description:
  - Manages STP config.
version_added: "1.8.0"
options:
  mode:
    description:
      - Specifies the mode of the spanning tree protocol.
      - The default value is STP.
    type: str
    default: stp
    choices:
      - stp
      - rstp
      - mstp
    version_added: "1.14.0"
  hello_time:
    description:
      - Specifies the time interval, in seconds, that the rSeries system transmits spanning tree information to adjacent bridges in the network.
      - The default value is 2.
    type: int
    default: 2
  max_age:
    description:
      - Specifies the length of time, in seconds, that spanning tree information received from other bridges is considered valid.
      - The default value is 20, and the valid range is from 6 to 40.
    type: int
    default: 20
  forwarding_delay:
    description:
      - Specifies the amount of time, in seconds, that the system blocks an interface from forwarding network traffic.
      - The default value is 15, and the valid range is from 4 to 30.
      - This has no effect when running in RSTP or MSTP unless using an added legacy STP bridge.
    type: int
    default: 15
  hold_count:
    description:
      - Specifies the maximum number of spanning tree frames (BPDUs) that the system can transmit on a port within the Hello Time interval.
      - This ensures that spanning tree frames do not overload the network. The default value is 6, and the valid range is from 1 to 10.
    type: int
    default: 6
  bridge_priority:
    description:
      - Specifies the bridge in the spanning tree with the lowest relative priority becomes the root bridge.
      - The default value is 32768. The valid range is from 0 to 61440 in multiples of 4096.
    type: int
    default: 32768
  mstp_instances:
    version_added: "1.14.0"
    description:
      - Specifies the MSTP instances to configure.
    type: list
    elements: dict
    suboptions:
      instance_id:
        description:
          - Specifies the mstp instance ID.
        type: int
      vlans:
        description:
          - Specifies the VLANs to include in the mstp instance.
        type: list
        elements: int
      bridge_priority:
        description:
          - Specifies the bridge priority for the mstp instance.
        type: int
      interface:
        description:
        - Specifies the interface associated with the mstp instance.
        type: dict
        suboptions:
          name:
            description:
              - Specifies the interface name.
            type: str
          cost:
            description:
              - Used to calculate the cost of sending spanning tree traffic through the interface to an adjacent bridge or spanning tree region.
            type: int
          port_priority:
            description:
              - Used as the port identifier together with the slot/port numbers.
            type: int
          edge_port:
            description:
              - Specifies whether the interface is an edge port.
              - When enabled, indicates the interface or LAG is an edge port that does not receive any BPDU frames.
            type: str
            choices:
              - EDGE_AUTO
              - EDGE_ENABLE
              - EDGE_DISABLE
          link_type:
            description:
              - Specifies the type of optimization.
              - P2P Optimizes for point-to-point spanning tree links (connects two spanning tree bridges only).
              - Note that P2P is the only valid STP link type for a LAG.
              - SHARED Optimizes for shared spanning tree links (connecting two or more spanning tree bridges).
            type: str
            choices:
              - P2P
              - SHARED
  interfaces:
    description: Specifies interfaces for which we want to enable STP.
    type: dict
    suboptions:
      name:
        description:
          - Specifies Interface to configure.
        type: str
      cost:
        description:
          - Used to calculate the cost of sending spanning tree traffic through the interface to an adjacent bridge or spanning tree region.
          - The default value is 0, and the valid range is from 1 (lowest) to 200,000,000 (highest).
        type: int
        default: 1
      port_priority:
        description:
            - Used as the port identifier together with the slot/port numbers.
            - The default value is 128 (when an interface is selected), and the valid range is from 0 (highest) to 240 (lowest) in multiples of 16.
        type: int
        default: 128
      edge_port:
        description:
            - Needed only for RSTP or MSTP.
            - When enabled, indicates the interface or LAG is an edge port that does not receive any BPDU frames.
            - Set to EDGE_AUTO, EDGE_ENABLE, or EDGE_DISABLE.
            - Enabling EDGE-ENABLE, if interface later receives BPDUs, the system disables the setting automatically, as only non-edge interfaces receive BPDUs.
        type: str
        default: EDGE_AUTO
        choices:
          - EDGE_AUTO
          - EDGE_ENABLE
          - EDGE_DISABLE
      link_type:
        description:
            - Specifies the type of optimization.
            - P2P Optimizes for point-to-point spanning tree links (connects two spanning tree bridges only).
            - Note that P2P is the only valid STP link type for a LAG.
            - SHARED Optimizes for shared spanning tree links (connecting two or more spanning tree bridges).
            - The default value is P2P.
        type: str
        default: P2P
        choices:
          - P2P
          - SHARED
  state:
    description:
      - If C(present), this option creates STP configuration on specified remote host.
      - If C(absent), this option disables STP configuration with default settings on the device.
    type: str
    choices:
      - present
      - absent
    default: present


author:
  - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''
- name: Enable STP
  f5os_stp_config:
    hello_time: 1
    max_age: 6
    forwarding_delay: 15
    hold_count: 6
    bridge_priority: 32768
    interfaces:
      name: 1.0
      cost: 1
      port_priority: 128
      edge_port: EDGE_AUTO
      link_type: P2P
'''
RETURN = r'''

hello_time:
  description: Specifies the time interval, in seconds, that the rSeries system transmits spanning tree information.
  returned: changed
  type: int
  sample: 1
max_age:
  description: Specifies the length of time, in seconds, that spanning tree information received from other bridges is considered valid.
  returned: changed
  type: int
  sample: 6
forwarding_delay:
  description: Specifies the amount of time, in seconds, that the system blocks an interface from forwarding network traffic.
  returned: changed
  type: int
  sample: 15
hold_count:
  description: Specifies the maximum number of spanning tree frames (BPDUs) that the system can transmit on a port.
  returned: changed
  type: int
  sample: 6
bridge_priority:
  description: Specifies the bridge in the spanning tree with the lowest relative priority becomes the root bridge.
  returned: changed
  type: int
  sample: 32768
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
        'mstp_instances'
    ]

    returnables = [
        'hello_time',
        'max_age',
        'forwarding_delay',
        'hold_count',
        'bridge_priority',
        'interfaces',
        'mstp_instances'
    ]

    updatables = [
        'hello_time',
        'max_age',
        'forwarding_delay',
        'hold_count',
        'bridge_priority',
        'interfaces',
        'mstp_instances'
    ]


class ApiParameters(Parameters):

    @property
    def mstp_instances(self):
        return self._values['mstp-instances']

    @property
    def hello_time(self):
        try:
            return int(self._values['hello-time'])
        except (TypeError, ValueError):
            return None

    @property
    def max_age(self):
        try:
            return int(self._values['max-age'])
        except (TypeError, ValueError):
            return None

    @property
    def forwarding_delay(self):
        try:
            return int(self._values['forwarding-delay'])
        except (TypeError, ValueError):
            return None

    @property
    def hold_count(self):
        try:
            return int(self._values['hold-count'])
        except (TypeError, ValueError):
            return None

    @property
    def bridge_priority(self):
        try:
            return int(self._values['bridge-priority'])
        except (TypeError, ValueError):
            return None

    @property
    def interfaces(self):
        try:
            return self._values['interfaces']
        except (TypeError, ValueError):
            return None


class ModuleParameters(Parameters):

    @property
    def hello_time(self):
        if self._values['hello_time'] is None:
            return 2
        if 1 > self._values['hello_time'] or self._values['hello_time'] > 10:
            raise F5ModuleError(
                "Valid hello_time must be in range 0 - 10."
            )
        return self._values['hello_time']

    @property
    def max_age(self):
        if self._values['max_age'] is None:
            return 20
        if 6 > self._values['max_age'] or self._values['hello_time'] > 40:
            raise F5ModuleError(
                "Valid max_age must be in range 6 - 40."
            )
        return self._values['max_age']

    @property
    def forwarding_delay(self):
        if self._values['forwarding_delay'] is None:
            return 15
        if 4 > self._values['forwarding_delay'] or self._values['forwarding_delay'] > 30:
            raise F5ModuleError(
                "Valid forwarding_delay must be in range 4 - 30."
            )
        return self._values['forwarding_delay']

    @property
    def hold_count(self):
        if self._values['hold_count'] is None:
            return 6
        if 1 > self._values['hold_count'] or self._values['hold_count'] > 10:
            raise F5ModuleError(
                "Valid hold_count must be in range 1 - 10."
            )
        return self._values['hold_count']

    @property
    def bridge_priority(self):
        if self._values['mode'] == 'mstp':
            return None
        if self._values['bridge_priority'] is None:
            return 32768
        if 0 > self._values['bridge_priority'] or self._values['bridge_priority'] > 61440 or self._values['bridge_priority'] % 4096 != 0:
            raise F5ModuleError(
                "Valid bridge_priority must be in range 0-61440 and a multiple of 4096."
            )
        return self._values['bridge_priority']

    @property
    def mstp_instances(self):
        mst_instances = {'mst-instance': []}
        instances = self._values["mstp_instances"]
        if instances is None:
            return None

        for instance in instances:
            instance_id = instance['instance_id']
            vlans = instance['vlans']
            bridge_priority = instance['bridge_priority']
            interface = instance.get('interface')

            mst_instance = {
                "mst-id": instance_id,
                "config": {
                    "mst-id": instance_id,
                    "bridge-priority": bridge_priority,
                    "vlan": vlans
                }
            }

            if interface is not None:
                mst_instance['interfaces'] = {
                    "interface": []
                }

                interface_payload = {
                    "name": interface['name'],
                    "config": {
                        "name": interface['name'],
                        "cost": interface['cost'],
                        "port-priority": interface['port_priority'],
                        "edge-port": interface['edge_port'],
                        "link-type": interface['link_type']
                    }
                }

                mst_instance['interfaces']['interface'].append(interface_payload)

            mst_instances['mst-instance'].append(mst_instance)

            return mst_instances

    @property
    def interfaces(self):
        if self._values['interfaces'] is not None:
            interface = {}
            interface['cost'] = 1
            interface['port_priority'] = 128
            interface['edge_port'] = 'EDGE-ENABLE'
            interface['link_type'] = 'P2P'
            interface['name'] = self._values['interfaces']['name']
            if 'cost' in self._values['interfaces']:
                interface['cost'] = self._values['interfaces']['cost']

            if 'port_priority' in self._values['interfaces']:
                if (0 > self._values['interfaces']['port_priority'] or
                        self._values['interfaces']['port_priority'] > 240 or self._values['interfaces']['port_priority'] % 16 != 0):
                    raise F5ModuleError("Valid port_priority must be in range 0-240 and a multiple of 16.")
                interface['port_priority'] = self._values['interfaces']['port_priority']

            if 'edge_port' in self._values['interfaces']:
                interface['edge_port'] = self._values['interfaces']['edge_port']

            if 'link_type' in self._values['interfaces']:
                interface['link_type'] = self._values['interfaces']['link_type']

            return interface
        else:
            return None


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
        'hello_time',
        'max_age',
        'forwarding_delay',
        'hold_count',
        'bridge_priority',
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
    def mstp_instances(self):
        want = self.want.mstp_instances
        have = self.have.mstp_instances

        if want is not None:
            if have is not None:
                if want != have:
                    return {"mstp_instances": want}
            else:
                return {"mstp_instances": want}

    @property
    def interfaces(self):
        if self.want.interfaces is not None:
            if self.have.interfaces is not None:
                for interface in self.have.interfaces:
                    if interface['name'] == self.want.interfaces['name']:
                        changes = {}
                        if self.want.interfaces['edge_port'] not in interface['config']['edge-port']:
                            changes['edge_port'] = self.want.interfaces['edge_port']
                        if interface['config']['link-type'] != self.want.interfaces['link_type']:
                            changes['link_type'] = self.want.interfaces['link_type']
                        if interface['config']['cost'] != self.want.interfaces['cost']:
                            changes['cost'] = self.want.interfaces['cost']
                        if interface['config']['port-priority'] != self.want.interfaces['port_priority']:
                            changes['port_priority'] = self.want.interfaces['port_priority']

                        return changes
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

    def enable_stp_protocol(self):
        mode = self.want.mode
        payload = {}

        if mode in ['rstp', 'mstp']:
            payload['enabled-protocol'] = [f"openconfig-spanning-tree-types:{mode.upper()}"]
        else:
            payload['enabled-protocol'] = [f"f5-openconfig-spanning-tree-types:{mode.upper()}"]

        # Posting Global Config

        uri = "/openconfig-spanning-tree:stp/global/config"
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def patch_stp_config(self):
        mode = self.want.mode

        if mode in ['rstp', 'mstp']:
            uri = f"/openconfig-spanning-tree:stp/{mode}/config"
        else:
            uri = "/openconfig-spanning-tree:stp/f5-openconfig-spanning-tree:stp/config"

        if mode in ['rstp', 'mstp']:
            config_key = "openconfig-spanning-tree:config"
        else:
            config_key = "f5-openconfig-spanning-tree:config"

        cfg = {
            "hello-time": self.want.hello_time,
            "max-age": self.want.max_age,
            "forwarding-delay": self.want.forwarding_delay,
            "hold-count": self.want.hold_count,
            "bridge-priority": self.want.bridge_priority
        }

        payload = {
            config_key: {k: v for k, v in cfg.items() if v is not None}
        }

        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def post_stp_interface(self):
        # Posting Interfaces - cost , port-priority
        mode = self.want.mode
        if mode in ['rstp']:
            config_key = "openconfig-spanning-tree:interface"
        else:
            config_key = "f5-openconfig-spanning-tree:interface"

        interfaces = {
            config_key: [
                {
                    'name': self.want.interfaces['name'],
                    'config': {
                        'name': self.want.interfaces['name'],
                        'cost': self.want.interfaces['cost'],
                        "port-priority": self.want.interfaces['port_priority'],
                    }
                }
            ]
        }

        if mode in ['rstp']:
            uri = f"/openconfig-spanning-tree:stp/{mode}/interfaces"
        else:
            uri = '/openconfig-spanning-tree:stp/f5-openconfig-spanning-tree:stp/interfaces'

        response = self.client.post(uri, data=interfaces)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        # Posting Interfaces - edge-port , link-type
        interfaces = {
            "interface": [
                {
                    "name": self.want.interfaces['name'],
                    "config": {
                        "name": self.want.interfaces['name'],
                        "edge-port": "openconfig-spanning-tree-types:" + self.want.interfaces['edge_port'],
                        "link-type": self.want.interfaces['link_type']
                    }
                }
            ]
        }
        uri = '/openconfig-spanning-tree:stp/interfaces'
        response = self.client.post(uri, data=interfaces)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def patch_stp_interface(self):
        mode = self.want.mode
        interface_name = self.want.interfaces['name'].replace('/', '%2F')

        if mode in ['rstp', 'mstp']:
            config_key = "openconfig-spanning-tree:interface"
        else:
            config_key = "f5-openconfig-spanning-tree:config"

        interfaces = {
            config_key: {
                'name': self.want.interfaces['name'],
                'cost': self.want.interfaces['cost'],
                "port-priority": self.want.interfaces['port_priority'],
            }
        }

        uri = '/openconfig-spanning-tree:stp/f5-openconfig-spanning-tree:stp/interfaces/f5-openconfig-spanning-tree:interface=' + interface_name + '/config'
        response = self.client.patch(uri, data=interfaces)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        interfaces = {
            "openconfig-spanning-tree:config": {
                "name": self.want.interfaces['name'],
                "edge-port": self.want.interfaces['edge_port'],
                "link-type": self.want.interfaces['link_type'],
            }
        }

        uri = '/openconfig-spanning-tree:stp/interfaces/interface=' + interface_name + '/config'

        response = self.client.patch(uri, data=interfaces)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def create_mstp_on_device(self):
        uri = "/openconfig-spanning-tree:stp/mstp/openconfig-spanning-tree:mst-instances"
        mst_instances = self.want.mstp_instances
        interfaces = {"interface": []}

        for instance in mst_instances['mst-instance']:
            interface = instance.get('interfaces')

            if interface is not None:
                for i in interface['interface']:
                    interfaces['interface'].append({
                        "name": i["config"]["name"],
                        "config": {
                            "name": i["config"]["name"],
                            "edge-port": "openconfig-spanning-tree-types:" + i["config"]["edge-port"],
                            "link-type": i["config"]['link-type'],
                        }
                    })
                    del i["config"]["edge-port"]
                    del i["config"]["link-type"]

        response = self.client.post(uri, data=mst_instances)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        if interfaces['interface']:
            uri = '/openconfig-spanning-tree:stp/interfaces'
            response = self.client.post(uri, data=interfaces)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

    def create_on_device(self):

        self.enable_stp_protocol()

        self.patch_stp_config()

        if self.want.mode == 'mstp':
            self.create_mstp_on_device()
            return True

        if self.want.interfaces is not None:
            self.have = self.read_current_from_device()
            existing_interfaces = []
            if self.have.interfaces is not None:
                for interface in self.have.interfaces:
                    existing_interfaces.append(interface['name'])
            if self.want.interfaces not in existing_interfaces:
                self.post_stp_interface()

            else:
                self.patch_stp_interface()

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

    def update_mstp_instances(self, params):
        payload = {"mst-instances": params["mstp_instances"]}
        uri = "/openconfig-spanning-tree:stp/mstp/openconfig-spanning-tree:mst-instances"
        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def update_mstp_interfaces(self, params):
        uri = '/openconfig-spanning-tree:stp/interfaces'
        response = self.client.patch(uri, data=params)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def update_mstp_on_device(self):
        params = self.changes.api_params()

        if "mstp_instances" in params:
            interfaces = {"interface": []}

            for instance in params["mstp_instances"]["mst-instance"]:
                interface = instance.get('interfaces')
                if interface is not None:
                    for i in interface['interface']:
                        interfaces['interface'].append({
                            "name": i["config"]["name"],
                            "config": {
                                "name": i["config"]["name"],
                                "edge-port": "openconfig-spanning-tree-types:" + i["config"]["edge-port"],
                                "link-type": i["config"]['link-type'],
                            }
                        })
                        del i["config"]["edge-port"]
                        del i["config"]["link-type"]

            self.update_mstp_instances(params)
            self.update_mstp_interfaces({"interfaces": interfaces})

    def update_on_device(self):
        self.patch_stp_config()

        if self.want.mode == 'mstp':
            self.update_mstp_on_device()
            return True

        if self.want.interfaces is not None:
            self.have = self.read_current_from_device()
            existing_interfaces = []
            if self.have.interfaces is not None:
                for interface in self.have.interfaces:
                    existing_interfaces.append(interface['name'])
            if self.want.interfaces['name'] not in existing_interfaces:
                self.post_stp_interface()
            else:
                self.patch_stp_interface()

        return True

    def read_current_mstp(self):
        uri = "/openconfig-spanning-tree:stp"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        mstp_obj = response['contents']['openconfig-spanning-tree:stp']['mstp']
        del mstp_obj['state']
        mstp_instance_interface = dict()
        interfaces = response['contents']['openconfig-spanning-tree:stp'].get('interfaces')

        for inst in mstp_obj['mst-instances']['mst-instance']:
            del inst['state']
            if 'interfaces' in inst:
                if 'interface' in inst['interfaces']:
                    for intf in inst['interfaces']['interface']:
                        del intf['state']
                        name = intf['name']
                        mstp_instance_interface[name] = intf

        if interfaces is not None:
            if 'interface' in interfaces:
                for intf in interfaces['interface']:
                    name = intf['name']
                    if name in mstp_instance_interface:
                        i = mstp_instance_interface[name]
                        i["config"]["edge-port"] = intf['config']['edge-port'].split(":")[1]
                        i["config"]["link-type"] = intf['config']['link-type']

        stp_cfg = mstp_obj["config"]
        mst_inst = mstp_obj["mst-instances"]
        del mstp_obj["config"]
        del mstp_obj["mst-instances"]
        mstp_obj.update(stp_cfg)
        mstp_obj["mstp-instances"] = mst_inst

        return ApiParameters(params=mstp_obj)

    def read_current_from_device(self):
        mode = self.want.mode

        if mode == 'mstp':
            return self.read_current_mstp()

        if mode == 'rstp':
            uri = "/openconfig-spanning-tree:stp"
        else:
            uri = "/openconfig-spanning-tree:stp/f5-openconfig-spanning-tree:stp/config"

        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if mode in ['rstp', 'mstp']:
            stp = response['contents']['openconfig-spanning-tree:stp']['rstp']['config']
        else:
            stp = response['contents']['f5-openconfig-spanning-tree:config']

        if mode in ['rstp']:
            uri = "/openconfig-spanning-tree:stp"
            response = self.client.get(uri)

            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
            rstp_obj = response['contents']['openconfig-spanning-tree:stp']['rstp']
            if 'interfaces' in rstp_obj:
                if 'interface' in rstp_obj['interfaces']:
                    stp['interfaces'] = rstp_obj['interfaces']['interface']

            if 'interfaces' in stp:
                for interface in stp['interfaces']:
                    name = interface['name']
                    name = name.replace('/', '%2F')
                    uri = '/openconfig-spanning-tree:stp/interfaces/interface=' + name + '/config'
                    response = self.client.get(uri)
                    if response['code'] not in [200, 201, 202]:
                        raise F5ModuleError(response['contents'])

                    interface['config']['edge-port'] = response['contents']['openconfig-spanning-tree:config']['edge-port']
                    interface['config']['link-type'] = response['contents']['openconfig-spanning-tree:config']['link-type']
        else:
            uri = "/openconfig-spanning-tree:stp/interfaces"
            response = self.client.get(uri)

            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

            if 'openconfig-spanning-tree:interfaces' in response['contents']:
                stp['interfaces'] = response['contents']['openconfig-spanning-tree:interfaces']['interface']

            if 'interfaces' in stp:
                for interface in stp['interfaces']:
                    name = interface['name']
                    name = name.replace('/', '%2F')
                    uri = '/openconfig-spanning-tree:stp/f5-openconfig-spanning-tree:stp/interfaces/interface=' + name + '/config'
                    response = self.client.get(uri)
                    if response['code'] not in [200, 201, 202]:
                        raise F5ModuleError(response['contents'])

                    interface['config']['cost'] = response['contents']['f5-openconfig-spanning-tree:config']['cost']
                    interface['config']['port-priority'] = response['contents']['f5-openconfig-spanning-tree:config']['port-priority']

        return ApiParameters(params=stp)

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        return True

    def remove_from_device(self):
        uri = "/openconfig-spanning-tree:stp/global/config"
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        uri = "/openconfig-spanning-tree:stp/interfaces"
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        return True

    def exists(self):
        uri = "/openconfig-spanning-tree:stp"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        config = response['contents']['openconfig-spanning-tree:stp']

        mode = self.want.mode
        if mode in ['rstp', 'mstp']:
            config_str = f'openconfig-spanning-tree-types:{mode.upper()}'
        else:
            config_str = f'f5-openconfig-spanning-tree-types:{mode.upper()}'

        if 'global' in config and config_str in config['global']['config']['enabled-protocol']:
            return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            mode=dict(
                type="str",
                default='stp',
                choices=['stp', 'rstp', 'mstp']
            ),
            hello_time=dict(
                type="int",
                default=2
            ),
            max_age=dict(
                type="int",
                default=20
            ),
            forwarding_delay=dict(
                type="int",
                default=15
            ),
            hold_count=dict(
                type="int",
                default=6
            ),
            bridge_priority=dict(
                type="int",
                default=32768
            ),
            mstp_instances=dict(
                type="list",
                elements="dict",
                options=dict(
                    instance_id=dict(type="int"),
                    vlans=dict(type="list", elements="int"),
                    bridge_priority=dict(type="int"),
                    interface=dict(
                        type="dict",
                        options=dict(
                            name=dict(type="str"),
                            cost=dict(type="int"),
                            port_priority=dict(type="int"),
                            edge_port=dict(
                                type="str",
                                choices=["EDGE_AUTO", "EDGE_ENABLE", "EDGE_DISABLE"]
                            ),
                            link_type=dict(
                                type="str",
                                choices=["P2P", "SHARED"]
                            )
                        )
                    )
                )
            ),
            interfaces=dict(
                type="dict",
                options=dict(
                    name=dict(
                        type="str"
                    ),
                    cost=dict(
                        type="int",
                        default=1
                    ),
                    port_priority=dict(
                        type="int",
                        default=128
                    ),
                    edge_port=dict(
                        type="str",
                        default="EDGE_AUTO",
                        choices=["EDGE_AUTO", "EDGE_ENABLE", "EDGE_DISABLE"]
                    ),
                    link_type=dict(
                        type="str",
                        choices=["P2P", "SHARED"],
                        default="P2P"
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

        self.required_if = [
            ['mode', 'mstp', ['mstp_instances']]
        ]
        self.mutually_exclusive = [
            ['interfaces', 'mstp_instances'],
            ['bridge_priority', 'mstp_instances']
        ]


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
