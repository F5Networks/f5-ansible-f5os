#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_device_info
short_description: Collect information from F5OS devices
description:
  - Collect information from F5OS devices.
version_added: "1.0.0"
options:
  gather_subset:
    description:
      - When supplied, this argument restricts the information returned to a given subset.
      - You can specify a list of values to include a larger subset.
      - Values can also be used with an initial C(!) to specify that a specific subset
        should not be collected.
    type: list
    elements: str
    required: True
    choices:
      - all
      - interfaces
      - vlans
      - controller-images
      - partition-images
      - tenant-images
      - system-info
      - "!all"
      - "!interfaces"
      - "!vlans"
      - "!controller-images"
      - "!partition-images"
      - "!tenant-images"
      - "!system-info"
    aliases: ['include']
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- hosts: all
  collections:
    - f5networks.f5os
  connection: httpapi

  vars:
    ansible_host: "lb.mydomain.com"
    ansible_user: "admin"
    ansible_httpapi_password: "secret"
    ansible_network_os: f5networks.f5os.f5os
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Collect interface and vlan information on F5OS device
      f5os_device_info:
        gather_subset:
          - interfaces
          - vlans

    - name: Collect all F5OS device information
      f5os_device_info:
        gather_subset:
          - all

    - name: Collect all F5OS device information except system-info
      f5os_device_info:
        gather_subset:
          - all
          - "!system-info"
'''
RETURN = r'''
interfaces:
  description: Information about interfaces on the platform.
  returned: When C(interfaces) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Name of the interface as designated on the F5OS device.
      returned: queried
      type: str
      sample: 1.1
    enabled:
      description:
        - Indicates if the interface is enabled.
      returned: queried
      type: bool
      sample: yes
    l3_counters:
      description:
        - Packets interface counters.
      returned: queried
      type: dict
      sample: hash/dictionary of values
    loopback_mode:
      description:
        - Indicates if the interface is set in loopback mode.
      returned: queried
      type: bool
      sample: no
    admin_status:
      description:
        - Returns the interface admin status as set by the user.
      returned: queried
      type: str
      sample: DOWN
    operational_status:
      description:
        - Returns the interface operational status.
      returned: queried
      type: str
      sample: UP
    port_speed:
      description:
        - Returns the set port speed of the interface.
      returned: queried
      type: str
      sample: 25G
    mac_address:
      description:
        - Returns the mac address of the interface.
      returned: queried
      type: str
      sample: 00:94:a1:69:4f:02
    l2_counters:
      description: Frames interface counters.
      returned: queried
      type: dict
      sample: hash/dictionary of values
  sample: hash/dictionary of values
vlans:
  description: Information about vlans on the platform.
  returned: When C(vlans) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Name of the vlan
      returned: queried
      type: str
      sample: vlan-444
    vlan_id:
      description:
        - Vlan tag as configured on device.
      returned: queried
      type: int
      sample: 444
  sample: hash/dictionary of values
velos_controller_images:
  description: Information about F5OS controller ISO images uploaded on the VELOS controller.
  returned: When C(controller-images) is specified in C(gather_subset).
  type: complex
  contains:
    version:
      description:
        - Version of the uploaded ISO file.
      returned: queried
      type: str
      sample: 1.2.1-10781
    service:
      description:
        - Version of service component in the uploaded ISO file.
      returned: queried
      type: str
      sample: 1.2.1-10781
    os:
      description:
        - Version of OS component in the uploaded ISO file.
      returned: queried
      type: str
      sample: 1.2.1-10781
  sample: hash/dictionary of values
velos_partition_images:
  description: Information about F5OS partition ISO images uploaded on the VELOS controller.
  returned: When C(partition-images) is specified in C(gather_subset).
  type: complex
  contains:
    version:
      description:
        - Version of the uploaded F5OS ISO file.
      returned: queried
      type: str
      sample: 1.2.1-10781
    service:
      description:
        - Version of service component in the uploaded F5OS ISO file.
      returned: queried
      type: str
      sample: 1.2.1-10781
    os:
      description:
        - Version of OS component in the uploaded F5OS ISO file.
      returned: queried
      type: str
      sample: 1.2.1-10781
  sample: hash/dictionary of values
tenant_images:
  description: Information about tenant images uploaded on the F5OS platform.
  returned: When C(tenant-images) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Name of the uploaded ISO file.
      returned: queried
      type: str
      sample: BIGIP-15.1.5-0.0.10.ALL-F5OS.qcow2.zip.bundle
    in_use:
      description:
        - Indicates if the tenant image is currently in use
      returned: queried
      type: bool
      sample: no
    status:
      description:
        - Status of the uploaded tenant image ISO.
      returned: queried
      type: str
      sample: verified
  sample: hash/dictionary of values
system_info:
  description: System Information on the F5OS platform.
  returned: When C(system-info) is specified in C(gather_subset).
  type: complex
  contains:
    components:
      description:
        - Specifies a list of components of the target platform.
        - Currently only blade, chassis, controller components information is collected on VELOS platform.
        - General platform information is collected for rSeries devices.
      returned: queried
      type: complex
      contains:
        name:
          description:
            - Name of the component.
          returned: queried
          type: str
          sample: blade-1
        serial_no:
          description:
            - Serial number of the component.
          returned: queried
          type: str
          sample: f5-abcd-efgh
        part_no:
          description:
            - Part number of the component.
          returned: queried
          type: str
          sample: 000-9999-88 REV 99
        description:
          description:
            - Full name of the platform.
            - Only collected on rSeries.
          returned: queried
          type: str
          sample: r10900
        memory_usage:
          description: Overall memory usage on the platform.
          returned: queried
          type: complex
          contains:
            total:
              description: Total memory in bytes that is present on the platform.
              returned: queried
              type: int
              sample: 19356536832
            free:
              description: Free memory in bytes that is available on the platform.
              returned: queried
              type: int
              sample: 17659666432
            used_percent:
              description: Percentage of used memory on the platform.
              returned: queried
              type: int
              sample: 25
          sample: hash/dictionary of values
        system_temperature:
          description: General information on system temperature, all values given in Celsius.
          returned: queried
          type: complex
          contains:
            current:
              description: Current temperature as measured on the system.
              returned: queried
              type: float
              sample: 25.4
            average:
              description: Average temperature measured on the system during its uptime.
              returned: queried
              type: float
              sample: 35.4
            minimum:
              description: Minimum temperature recorded on the system during its uptime
              returned: queried
              type: float
              sample: 20.1
            maximum:
              description: Maximum temperature recorded on the system during its uptime.
              returned: queried
              type: float
              sample: 39.2
          sample: hash/dictionary of values
    installed_license:
      description: License information as present on the platform.
      returned: queried
      type: complex
      contains:
        base_registration_key:
          description: Base registration key of the license.
          returned: queried
          type: str
          sample: YYYYY-XXXXX-FFFFF-GGGG-JJJJJJ
        dossier:
          description: Dossier generated by device.
          returned: queried
          type: str
          sample: 01350fe7daea9e21a4ee
        service_check_date:
          description: Date when last service check was performed on the license
          returned: queried
          type: str
          sample: 2021/12/01
        license_date:
          description: Date when the system was licensed
          returned: queried
          type: str
          sample: 2021/08/01
      sample: hash/dictionary of values
    platform_type:
      description: Type of platform that the info is being gathered on.
      returned: queried
      type: str
      sample: rSeries Platform
    running_software:
      description: Information on the current version of F5OS software running on the device.
      returned: queried
      type: complex
      contains:
        blade_name:
          description:
            - Blade on which the software is running.
            - This is only collected when querying VELOS partitions.
          returned: queried
          type: str
          sample: blade-1
        controller_name:
          description:
            - Controller on which the software is running.
            - This is only collected when querying VELOS controllers.
          returned: queried
          type: str
          sample: controller-1
        os_version:
          description:
            - Version of OS component in the current running software.
          returned: queried
          type: str
          sample: 1.3.2-9645
        service_version:
          description:
            - Version of service component in the current running software.
          returned: queried
          type: str
          sample: 1.3.2-9645
      sample: hash/dictionary of values
  sample: hash/dictionary of values
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import (
    iteritems, string_types
)

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)
from ..module_utils.client import (
    F5Client, send_teem
)


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)
        self.kwargs = kwargs

    def exec_module(self):
        start = datetime.datetime.now().isoformat()
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        send_teem(self.client, start)
        return results


class Parameters(AnsibleF5Parameters):
    @property
    def gather_subset(self):
        if isinstance(self._values['gather_subset'], string_types):
            self._values['gather_subset'] = [self._values['gather_subset']]
        elif not isinstance(self._values['gather_subset'], list):
            raise F5ModuleError(
                "The specified gather_subset must be a list."
            )
        tmp = list(set(self._values['gather_subset']))
        tmp.sort()
        self._values['gather_subset'] = tmp

        return self._values['gather_subset']


class BaseParameters(Parameters):
    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result


class VlansParameters(BaseParameters):
    api_map = {
        'vlan-id': 'vlan_id'
    }

    returnables = [
        'name',
        'vlan_id'
    ]

    @property
    def name(self):
        return self._values['config'].get('name')


class VlansFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(VlansFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(vlans=facts)
        return result

    def _exec_module(self):
        if self.client.platform == 'Velos Controller':
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['vlan_id'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = VlansParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/openconfig-vlan:vlans"
        response = self.client.get(uri)

        if response['code'] == 204:
            return []
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['openconfig-vlan:vlans']['vlan']


class VelosImagesParameters(BaseParameters):
    api_map = {}

    returnables = [
        'version',
        'service',
        'os'
    ]


class ControllerImagesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ControllerImagesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(velos_controller_images=facts)
        return result

    def _exec_module(self):
        if not self.client.platform == 'Velos Controller':
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['os'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = VelosImagesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/f5-system-image:image/controller/config/iso"
        response = self.client.get(uri)

        if response['code'] == 204:
            return []
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-image:iso']['iso']


class PartitionImagesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(PartitionImagesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(velos_partition_images=facts)
        return result

    def _exec_module(self):
        if not self.client.platform == 'Velos Controller':
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['os'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = VelosImagesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/f5-system-image:image/partition/config/iso"
        response = self.client.get(uri)

        if response['code'] == 204:
            return []
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-image:iso']['iso']


class TenantImagesParameters(BaseParameters):
    api_map = {
        'in-use': 'in_use'
    }

    returnables = [
        'name',
        'in_use',
        'status'
    ]

    @property
    def in_use(self):
        return flatten_boolean(self._values['in_use'])


class TenantImagesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(TenantImagesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(tenant_images=facts)
        return result

    def _exec_module(self):
        if self.client.platform == 'Velos Controller':
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['name'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = TenantImagesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/f5-tenant-images:images"
        response = self.client.get(uri)

        if response['code'] == 204:
            return []
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-tenant-images:images']['image']


class InterfacesParameters(BaseParameters):
    api_map = {
    }

    returnables = [
        'name',
        'enabled',
        'l3_counters',
        'loopback_mode',
        'admin_status',
        'operational_status',
        'port_speed',
        'mac_address',
        'l2_counters',
    ]

    @property
    def enabled(self):
        return flatten_boolean(self._values['state']['enabled'])

    @property
    def loopback_mode(self):
        if 'loopback-mode' in self._values['state']:
            return flatten_boolean(self._values['state']['loopback-mode'])

    @property
    def admin_status(self):
        if 'admin-status' in self._values['state']:
            return self._values['state']['admin-status']

    @property
    def l3_counters(self):
        if 'counters' not in self._values['state']:
            return None
        raw_counters = self._values['state']['counters']
        mapped_names = {
            'in-octets': 'in_octets',
            'in-pkts': 'in_pkts',
            'in-unicast-pkts': 'in_unicast_pkts',
            'in-broadcast-pkts': 'in_broadcast_pkts',
            'in-multicast-pkts': 'in_multicast_pkts',
            'in-discards': 'in_discards',
            'in-errors': 'in_errors',
            'in-fcs-errors': 'in_fcs_errors',
            'in-unknown-protos': 'in_unknown_protos',
            'out-octets': 'out_octets',
            'out-pkts': 'out_pkts',
            'out-unicast-pkts': 'out_unicast_pkts',
            'out-broadcast-pkts': 'out_broadcast_pkts',
            'out-multicast-pkts': 'out_multicast_pkts',
            'out-discards': 'out_discards',
            'out-errors': 'out_errors'
        }
        return self._filter_counters(raw_counters, mapped_names)

    @property
    def operational_status(self):
        if 'oper-status' in self._values['state']:
            return self._values['state']['oper-status']

    @property
    def port_speed(self):
        if self._values['openconfig-if-ethernet:ethernet'] is None:
            return None
        if 'port-speed' in self._values['openconfig-if-ethernet:ethernet']['state']:
            raw_speed = self._values['openconfig-if-ethernet:ethernet']['state']['port-speed']
            if raw_speed:
                return raw_speed.strip('openconfig-if-ethernet:SPEED_')

    @property
    def mac_address(self):
        if self._values['openconfig-if-ethernet:ethernet'] is None:
            return None
        if 'hw-mac-address' in self._values['openconfig-if-ethernet:ethernet']['state']:
            return self._values['openconfig-if-ethernet:ethernet']['state']['hw-mac-address']

    @property
    def l2_counters(self):
        if self._values['openconfig-if-ethernet:ethernet'] is None:
            return None
        if 'counters' not in self._values['openconfig-if-ethernet:ethernet']['state']:
            return None
        raw_counters = self._values['openconfig-if-ethernet:ethernet']['state']['counters']
        mapped_names = {
            'in-mac-control-frames': 'in_mac_control_frames',
            'in-mac-pause-frames': 'in_mac-pause-frames',
            'in-oversize-frames': 'in_oversize_frames',
            'in-jabber-frames': 'in_jabber_frames',
            'in-fragment-frames': 'in_fragment_frames',
            'in-8021q-frames': 'in_8021q_frames',
            'in-crc-errors': 'in_crc_errors',
            'out-mac-control-frames': 'out_mac_control_frames',
            'out-mac-pause-frames': 'out_mac_pause_frames',
            'out-8021q-frames': 'out_8021q_frames'
        }
        return self._filter_counters(raw_counters, mapped_names)

    @staticmethod
    def _filter_counters(raw_counters, mapped_names):
        if raw_counters is None:
            return None
        result = dict()
        for k in raw_counters.keys():
            if k in mapped_names:
                result[mapped_names[k]] = int(raw_counters[k])
        return result


class InterfacesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(InterfacesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(interfaces=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['name'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = InterfacesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/openconfig-interfaces:interfaces"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['openconfig-interfaces:interfaces']['interface']


class ComponentsInfoParameters(BaseParameters):
    api_map = {
    }

    returnables = [
        'name',
        'serial_no',
        'part_no',
        'description',
        'memory_usage',
        'system_temperature'
    ]

    @property
    def serial_no(self):
        if 'serial-no' in self._values['state']:
            return self._values['state']['serial-no']

    @property
    def part_no(self):
        if 'part-no' in self._values['state']:
            return self._values['state']['part-no']

    @property
    def description(self):
        if 'description' in self._values['state']:
            return self._values['state']['description']

    @property
    def memory_usage(self):
        if 'f5-platform:memory' not in self._values['state']:
            return None
        result = dict()
        result['total'] = int(self._values['state']['f5-platform:memory']['available'])
        result['free'] = int(self._values['state']['f5-platform:memory']['free'])
        result['used_percent'] = self._values['state']['f5-platform:memory']['used-percent']
        return result

    @property
    def system_temperature(self):
        if 'f5-platform:temperature' not in self._values['state']:
            return None
        result = dict()
        result['current'] = float(self._values['state']['f5-platform:temperature']['current'])
        result['average'] = float(self._values['state']['f5-platform:temperature']['average'])
        result['minimum'] = float(self._values['state']['f5-platform:temperature']['minimum'])
        result['maximum'] = float(self._values['state']['f5-platform:temperature']['maximum'])
        return result


class LicenseInfoParameters(BaseParameters):
    api_map = {
    }

    returnables = [
        'base_registration_key',
        'dossier',
        'service_check_date',
        'license_date'
    ]

    @property
    def base_registration_key(self):
        return self._values['config']['registration-key']['base']

    @property
    def dossier(self):
        return self._values['config']['dossier']

    @property
    def service_check_date(self):
        lic_info = self._values['state']['license']
        tmp = lic_info.split('\n')
        for i in tmp:
            if i.startswith('Service check date'):
                return i.rsplit('Service check date')[1].strip()

    @property
    def license_date(self):
        lic_info = self._values['state']['license']
        tmp = lic_info.split('\n')
        for i in tmp:
            if i.startswith('Licensed date'):
                return i.rsplit('Licensed date')[1].strip()


class PlatformSoftwareInfoParameters(BaseParameters):
    api_map = {
    }

    returnables = [
        'os_version',
        'service_version',
        'software_installation_status',
    ]

    @property
    def os_version(self):
        return self._values['state']['install'].get('install-os-version')

    @property
    def service_version(self):
        return self._values['state']['install'].get('install-service-version')

    @property
    def software_installation_status(self):
        return self._values['state']['install'].get('install-status')


class ControllerSoftwareInfoParameters(BaseParameters):
    api_map = {
        'name': 'controller_name'
    }

    returnables = [
        'controller_name',
        'os_version',
        'service_version',
    ]


class PartitionSoftwareInfoParameters(BaseParameters):
    api_map = {
        'name': 'blade_name'
    }

    returnables = [
        'blade_name',
        'os_version',
        'service_version',
    ]

    @property
    def os_version(self):
        if self._values['os'] is None:
            return None
        for item in self._values['os']:
            if item['software-index'] == 'blade-os':
                return item['state']['version']

    @property
    def service_version(self):
        if self._values['os'] is None:
            return None
        for item in self._values['os']:
            if item['software-index'] == 'partition-services':
                return item['state']['version']


class SystemInfoFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SystemInfoFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(system_info=facts)
        return result

    def _exec_module(self):
        comps, soft, lic = self.read_facts()
        results = dict(
            components=list()
        )
        for item in comps:
            attrs = item.to_return()
            results['components'].append(attrs)
        results['components'] = sorted(results['components'], key=lambda k: k['name'])
        if isinstance(soft, list):
            results['running_software'] = list()
            for s in soft:
                attrs = s.to_return()
                results['running_software'].append(attrs)
            results['running_software'] = sorted(results['running_software'], key=self._soft_sorter)
        else:
            results['running_software'] = soft.to_return()
        results['installed_license'] = lic.to_return()
        results['platform_type'] = self.client.platform
        return results

    @staticmethod
    def _soft_sorter(k):
        if 'controller_name' in k:
            return k['controller_name']
        if 'blade_name' in k:
            return k['blade_name']

    def read_facts(self):
        comps = self._read_component_facts()
        soft = self._read_running_software_facts()
        lic = self._read_installed_license_facts()
        return comps, soft, lic

    def _read_running_software_facts(self):
        if self.client.platform == 'rSeries Platform':
            software = self.read_platform_software_info_from_device()
            return PlatformSoftwareInfoParameters(params=software)
        elif self.client.platform == 'Velos Controller':
            software = self.read_controller_software_info_from_device()
            result = list()
            for soft in software:
                attr = ControllerSoftwareInfoParameters(params=soft)
                result.append(attr)
            return result
        else:
            software = self.read_partition_software_info_from_device()
            result = list()
            for soft in software:
                attr = PartitionSoftwareInfoParameters(params=soft)
                result.append(attr)
            return result

    def _read_installed_license_facts(self):
        lic = self.read_license_from_device()
        return LicenseInfoParameters(params=lic)

    def _read_component_facts(self):
        results = []
        components = self.read_components_from_device()
        for comp in components:
            if comp['name'].startswith('blade') or comp['name'].startswith('platform') or \
                    comp['name'].startswith('chassis') or comp['name'].startswith('controller'):
                if comp['state']['empty'] is True:
                    continue
                item = ComponentsInfoParameters(params=comp)
                results.append(item)
        return results

    def read_components_from_device(self):
        uri = "/openconfig-platform:components"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['openconfig-platform:components']['component']

    def read_license_from_device(self):
        uri = "/openconfig-system:system/f5-system-licensing:licensing"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-licensing:licensing']

    def read_controller_software_info_from_device(self):
        uri = "/openconfig-system:system/f5-system-controller-image:image"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        controllers = response['contents']['f5-system-controller-image:image']['state']['controllers']['controller']
        result = list()
        for controller in controllers:
            info = dict()
            info["name"] = f"controller-{controller['number']}"
            info['os_version'] = controller['os-version']
            info['service_version'] = controller['service-version']
            result.append(info)
        return result

    def read_platform_software_info_from_device(self):
        uri = "/openconfig-system:system/f5-system-image:image"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-image:image']

    def read_partition_software_info_from_device(self):
        uri = "/openconfig-platform:components"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        comps = response['contents']['openconfig-platform:components']['component']
        result = list()
        for comp in comps:
            info = dict()
            if comp['name'].startswith('blade'):
                info['name'] = comp['name']
                info['os'] = comp['f5-platform:software']['state']['software-components']['software-component']
                result.append(info)
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.kwargs = kwargs
        self.want = Parameters(params=self.module.params)
        self.managers = {
            'interfaces': InterfacesFactManager,
            'vlans': VlansFactManager,
            'controller-images': ControllerImagesFactManager,
            'partition-images': PartitionImagesFactManager,
            'tenant-images': TenantImagesFactManager,
            'system-info': SystemInfoFactManager
        }

    def exec_module(self):
        self.handle_all_keyword()
        self.filter_excluded_meta_facts()
        res = self.check_valid_gather_subset(self.want.gather_subset)
        if res:
            invalid = ','.join(res)
            raise F5ModuleError(
                "The specified 'gather_subset' options are invalid: {0}".format(invalid)
            )
        result = self.filter_excluded_facts()

        managers = []
        for name in result:
            manager = self.get_manager(name)
            if manager:
                managers.append(manager)

        if not managers:
            result = dict(
                changed=False
            )
            return result

        result = self.execute_managers(managers)
        if result:
            result['queried'] = True
        else:
            result['queried'] = False
        return result

    def filter_excluded_facts(self):
        # Remove the excluded entries from the list of possible facts
        exclude = [x[1:] for x in self.want.gather_subset if x[0] == '!']
        include = [x for x in self.want.gather_subset if x[0] != '!']
        result = [x for x in include if x not in exclude]
        return result

    def filter_excluded_meta_facts(self):
        gather_subset = set(self.want.gather_subset)
        gather_subset -= {'!all'}

        if '!all' in self.want.gather_subset:
            gather_subset.clear()

        self.want.update({'gather_subset': list(gather_subset)})

    def handle_all_keyword(self):
        if 'all' not in self.want.gather_subset:
            return
        managers = list(self.managers.keys()) + self.want.gather_subset
        managers.remove('all')
        self.want.update({'gather_subset': managers})

    def check_valid_gather_subset(self, includes):
        """Check that the specified subset is valid

        The ``gather_subset`` parameter is specified as a "raw" field which means that
        any Python type could technically be provided

        :param includes:
        :return:
        """
        keys = self.managers.keys()
        result = []
        for x in includes:
            if x not in keys:
                if x[0] == '!':
                    if x[1:] not in keys:
                        result.append(x)
                else:
                    result.append(x)
        return result

    def execute_managers(self, managers):
        results = dict()
        for manager in managers:
            result = manager.exec_module()
            results.update(result)
        return results

    def get_manager(self, which):
        result = {}
        manager = self.managers.get(which, None)
        if not manager:
            return result
        kwargs = dict()
        kwargs.update(self.kwargs)

        kwargs['client'] = F5Client(module=self.module, client=self.connection)
        result = manager(**kwargs)
        return result


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            gather_subset=dict(
                type='list',
                elements='str',
                required=True,
                aliases=['include'],
                choices=[
                    # Meta choices
                    'all',

                    # Non-meta choices
                    'interfaces',
                    'vlans',
                    'controller-images',
                    'partition-images',
                    'tenant-images',
                    'system-info',

                    # Negations of meta choices
                    '!all',

                    # Negations of non-meta-choices
                    '!interfaces',
                    '!vlans',
                    '!controller-images',
                    '!partition-images',
                    '!tenant-images',
                    '!system-info',
                ]
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

        ansible_facts = dict()

        for key, value in iteritems(results):
            key = 'ansible_net_%s' % key
            ansible_facts[key] = value

        module.exit_json(ansible_facts=ansible_facts, **results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
