#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_allowed_ips
short_description: Manage allowed IPs using openAPI on F5OS based systems
description:
  - Manage allowed IPs using openAPI on F5OS based systems
version_added: "1.9.0"
options:
  allowed:
    description:
      - Specify Name, IP Address, Prefix Length and Port for an allowed address
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - Unique name for allowed address
            type: str
            required: true
        ipv4:
            type: dict
            elements: dict
            options:
                address: IPv4 address
                prefix: length of prefix
                port: allowed port
        ipv6:
            type: dict
            elements: dict
            options:
                address: IPv6 address
                prefix: length of prefix
                port: allowed port
  state:
    description:
      - Allowed IPs state of F5OS system
      - If C(present), Specified Allowed IPs configuration will be pushed to F5OS system.
      - If C(absent), deletes the Allowed IPs configuration if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Martin Vogel (@MVogel91)
'''

EXAMPLES = r'''
- name: Create IPv4 Allowed IPs
  f5os_allowed_ips:
    allowed:
      - name: admins
        ipv4:
          address: 192.168.0.0
          prefix: 24
      - name: snmp
        ipv4:
          address: 10.1.0.0
          prefix: 24
          port: 161

- name: Delete IPv4 Allowed IPs Config
   f5os_allowed_ips:
    allowed:
      - name: admins
        ipv4:
          address: 192.168.0.0
          prefix: 24
      - name: snmp
        ipv4:
          address: 10.1.0.0
          prefix: 24
          port: 161
    state: absent
'''

RETURN = r'''
allowed:
  description: Specifies allowed IP addresses per Service
  returned: changed
  type: list
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

    }

    api_attributes = [
        'allowed'
    ]

    returnables = [
        'allowed'
    ]

    updatables = [
        'allowed'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def allowed(self):
        if self._values['allowed'] is None:
            return None
        return self._values['allowed']

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
    @property
    def allowed(self):
        if self._values['allowed'] is None:
            return None
        allowed = []
        for val in self._values['allowed']:
            result = {
                'name': val['name'],
                'config': {
                }
            }
            for protocol_version in ['ipv6','ipv4']:
                if val[protocol_version] is not None:
                    result['config'][protocol_version] = dict()
                    result['config'][protocol_version]['address'] = val[protocol_version]['address']
                    result['config'][protocol_version]['prefix-length'] = val[protocol_version]['prefix']
                    if 'port' in result['config'][protocol_version] and result['config'][protocol_version]['port'] is not None:
                        result['config'][protocol_version]['port'] = val[protocol_version]['port']
                    break
            allowed.append(result)
        return allowed


class ReportableChanges(Changes):
    pass


class Difference(object):  # pragma: no cover
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        if hasattr(self,param):
            return getattr(self,param)
        else:
            return self.__default(param)

    def __default(self, param):
        want = getattr(self.want, param)
        if hasattr(self.have, param):
            have = getattr(self.have, param)
            if want != have:
                return want
        else:
            return want

    @property
    def allowed(self):
        '''Discrepancy between Module name (ipv4[prefix],ipv6[prefix]) and API name (ipv4[prefix-length],ipv6[prefix-length])'''
        if getattr(self.want, 'allowed') != None:
            for wallowed in self.want.allowed:
                for hallowed in getattr(self.have, 'allowed-ip'):
                    if wallowed['name'] == hallowed['name']:
                        for ip_version in ['ipv6','ipv4']:
                            if ip_version in wallowed and wallowed[ip_version] is not None:
                                if ip_version not in hallowed['config']:
                                    return self.want.allowed
                                if wallowed[ip_version] != hallowed['config'][ip_version]:
                                    if wallowed[ip_version]['address'] != hallowed['config'][ip_version]['address']:
                                        return self.want.allowed
                                    if wallowed[ip_version]['prefix'] != hallowed['config'][ip_version]['prefix-length']:
                                        return self.want.allowed
                                    if 'port' in wallowed[ip_version] and wallowed[ip_version]['port'] is not None:
                                        if wallowed[ip_version]['port'] != hallowed['config'][ip_version]['port']:
                                            return self.want.allowed
                                break
                        return None

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

    def _update_changed_options(self):  # pragma: no cover
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
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
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
        '''Wrapper for creation/update'''
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        '''Wrapper for removal'''
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self)->bool:
        '''Update object on F5OS system'''
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self)->bool:
        '''Remove object from F5OS system'''
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self)->bool:
        '''Create object on F5OS system'''
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self)->bool:
        '''Check object existance on F5OS system'''
        base_uri = "/openconfig-system:system/f5-allowed-ips:allowed-ips"
        if (hasattr(self.want,'allowed') and getattr(self.want,'allowed') != None):
            for val in getattr(self.want, 'allowed'):
                object_uri = "/allowed-ip={}".format(val['name'])

                uri = base_uri + object_uri
                response = self.client.get(uri)
                if response['code'] == 404:
                    return False
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        '''API communication to actually create the objects on the F5OS system'''
        params = self.changes.api_params()
        uri = "/openconfig-system:system/f5-allowed-ips:allowed-ips"

        if 'allowed' in params:
            for allow_entry in params['allowed']:
                payload = {'allowed-ip': [{'name': allow_entry['name'], 'config':allow_entry['config']}]}
                response = self.client.post(uri, data=payload)
                #raise Exception (uri + "     " + str(payload))
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        '''API communication to actually update the objects on the F5OS system'''
        params = self.changes.api_params()
        base_uri = "/openconfig-system:system/f5-allowed-ips:allowed-ips"
        
        if 'allowed' in params:
            for allow_entry in params['allowed']:
                object_uri = "/allowed-ip={}/config".format(allow_entry['name'])
                uri = base_uri + object_uri
                payload = {'config':allow_entry['config']}
                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        return True


    def remove_from_device(self):
        '''API communication to actually remove the objects on the F5OS system'''
        if self.want.allowed is not None:
            for val in self.want.allowed:
                uri = f"/openconfig-system:system/f5-allowed-ips:allowed-ips/allowed-ip={val['name']}"
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        '''API communication to read the objects on the F5OS system'''
        uri = "/openconfig-system:system/f5-allowed-ips:allowed-ips"
        response = self.client.get(uri)
        return_object = response['contents']['f5-allowed-ips:allowed-ips']
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=return_object)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            allowed=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str',required=True),
                    ipv4=dict(
                        type='dict',
                        #elements='dict',
                        options=dict(
                            address=dict(type='str'),
                            prefix=dict(type=int),
                            port=dict(type=int)
                        )
                    ),
                    ipv6=dict(
                        type='dict',
                        elements='dict',
                        options=dict(
                            address=dict(type='str'),
                            prefix=dict(type=int),
                            port=dict(type=int)
                        )
                    ),
                )
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_one_of = [('allowed')]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
