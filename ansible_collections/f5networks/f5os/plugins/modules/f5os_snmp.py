#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_snmp
short_description: Manage SNMP Communities, Users, and Targets using openAPI on F5OS based systems
description:
  - Manage SNMP Communities, Users, and Targets using openAPI on F5OS based systems.
version_added: "1.9.0"
options:
  snmp_community:
    description:
      - Specifies SNMP Community options to be configured on system
      - This parameter is required when creating a resource.
      - It is List of community options to be configured
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - Unique name for snmp community
            type: str
            required: true
        security_model:
            description:
                - Short description of the rule's purpose.
            type: list
            elements: str
  snmp_target:
    description:
      - Specifies SNMP targets options to be configured on system
      - It is List of community options to be configured
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - Unique name for snmp target
            type: str
            required: true
        security_model:
            description:
                - Security model to be configure on snmp target.
                - Options are [v1, v2c]
                - v3 is to be omitted and inherently applied by "user" attribute.
            type: str
        community:
            description:
                - SNMP community name to be configure on snmp target
            type: str
        user:
            description:
                - The user to be used for SNMPv3 targets
            type: str
        ipv4_address:
            description:
                - IPv4 address to be configured on SNMP target config
            type: str
        ipv6_address:
            description:
                - IPv6 address to be configured on SNMP target config
            type: str
        port:
            description:
                - Port number to used for snmp taget config ipv4/ipv6 address
            type: int
            required: true
  snmp_user:
    description:
      - Specifies SNMP users options to be configured on system
      - It is List of user options to be configured
      - Due to API restrictions, passwords can not be retrieved which leads to
      - Ansible always detecting changes.
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - Unique name for the snmp user
            type: str
            required: true
        auth_proto:
            description:
                - Authentication protocol to be used.
                - Options are [sha, md5]
            type: str
        auth_passwd:
            description:
                - Password to be used for authentication
            type: str
        privacy_proto:
            description:
                - Privacy protocol to be used.
                - Options are [aes, des]
                - Requires authentication to be configured as well.
            type: str
        privacy_passwd:
            description:
                - Password to be used for encryption
            type: str
  snmp_mib:
    description:
      - Specifies custom SNMP MIB entries for sysContact, sysLocation, sysName
    type: dict
    suboptions:
        sysname:
            description:
                - SNMPv2 sysName
            type: str
        syscontact:
            description:
                - SNMPv2 sysContact
            type: str
        syslocation:
            description:
                - SNMPv2 sysLocation
            type: str
  state:
    description:
      - snmp configuration state of F5OS system
      - If C(present), Specified snmp configuration will be pushed to F5OS system.
      - If C(absent), deletes the snmp configuration if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy (@chinthalapalli)
  - Martin Vogel (@MVogel91)
'''

EXAMPLES = r'''
- name: Create v1/v2c SNMP Community
  f5os_snmp:
    snmp_community:
      - name: test_1_2c_com
        security_model: ['v1', 'v2c']

- name: Create SNMP v3 User
  f5os_snmp:
    snmp_user:
      - name: v3user
        auth_proto: "sha"
        auth_passwd: "authpass"
        privacy_proto: "aes"
        privacy_passwd: "privpass"

- name: Create SNMP targets
  f5os_snmp:
    snmp_target:
      - name: v1_target
        security_model: v1
        ipv4_address: 10.144.140.17
        port: 5045
        community: test_1_2c_com
      - name: v2c_target
        security_model: v2c
        ipv4_address: 10.144.140.17
        port: 5045
        community: test_1_2c_com
      - name: v3_target
        user: v3user
        ipv4_address: 10.144.140.17
        port: 5045

- name: Set SNMP Contact/Location/Name
  f5os_snmp:
    snmp_mib:
      syscontact: admin@example.com
      syslocation: "DC/Room/Rack/Slot"
      sysname: F5-System1

- name: Update SNMP Config
  f5os_snmp:
    snmp_community:
      - name: test2_com
        security_model: ['v1', 'v2c']
      - name: test3_com
        security_model: ['v1', 'v2c']
    snmp_target:
      - name: v1_target
        security_model: v1
        ipv4_address: 10.144.140.17
        port: 5045
        community: test2_com
    snmp_user:
      - name: v3user
        auth_proto: "sha"
        auth_passwd: "authpass2"
        privacy_proto: "aes"
        privacy_passwd: "privpass2"

- name: Delete SNMP Config
  f5os_snmp:
    snmp_community:
      - name: test2_com
        security_model: ['v1', 'v2c']
      - name: test3_com
        security_model: ['v1', 'v2c']
    snmp_target:
      - name: v1_target
        security_model: v1
        ipv4_address: 10.144.140.17
        port: 5045
        community: test2_com
    state: absent
'''

RETURN = r'''
snmp_community:
  description: Specifies SNMP Community options to be configured on the system.
  returned: changed
  type: list
snmp_target:
  description: Specifies SNMP targets options to be configured on the system.
  returned: changed
  type: list
snmp_user:
  description: Specifies SNMP users options to be configured on the system.
  returned: changed
  type: list
snmp_mib:
  description: Specifies sysName, sysContact and sysLocation
  returned: changed
  type: str
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
        'snmp_community',
        'snmp_user',
        'snmp_target',
        'snmp_mib'
    ]

    returnables = [
        'snmp_community',
        'snmp_user',
        'snmp_target',
        'snmp_mib'
    ]

    updatables = [
        'snmp_community',
        'snmp_user',
        'snmp_target',
        'snmp_mib'
    ]


class ApiParameters(Parameters):
    @property
    def snmp_community(self):
        if 'communities' in self._values:
            result_community = []
            for x in self._values['communities']['community']:
                result_community.append(x['config'])
            return result_community

    @property
    def snmp_target(self):
        if 'targets' in self._values:
            result = {}
            result_targets = []
            for x in self._values['targets']['target']:
                result_targets.append(x['config'])
            return result_targets

    @property
    def snmp_user(self):
        if 'users' in self._values:
            result = {}
            result_users = []
            for x in self._values['users']['user']:
                result_users.append(x['config'])
            return result_users


class ModuleParameters(Parameters):
    @property
    def snmp_community(self):
        if self._values['snmp_community'] is None:
            return None
        return self._values['snmp_community']

    @property
    def snmp_target(self):
        if self._values['snmp_target'] is None:
            return None
        return self._values['snmp_target']

    @property
    def snmp_user(self):
        if self._values['snmp_user'] is None:
            return None
        return self._values['snmp_user']

    @property
    def snmp_mib(self):
        if self._values['snmp_mib'] is None:
            return None
        return self._values['snmp_mib']


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
    def snmp_community(self):
        if self._values['snmp_community'] is None:
            return None
        snmp_community = []
        for val in self._values['snmp_community']:
            if val['security_model'] is None:
                val['security_model'] = "v1"
            result = {
                'name': val['name'],
                'config': {
                    'security-model': val['security_model'],
                    'name': val['name'],
                }
            }
            snmp_community.append(result)
        return snmp_community

    @property
    def snmp_target(self):
        if self._values['snmp_target'] is None:
            return None
        snmp_targets = []
        snmp_target = dict()
        for val in self._values['snmp_target']:
            target_config = dict()
            target_config['name'] = val['name']

            if 'security_model' in val and val['security_model'] is not None:
                target_config['security-model'] = val['security_model']

            if 'community' in val and val['community'] is not None:
                target_config['community'] = val['community']

            if 'user' in val and val['user'] is not None:
                target_config['user'] = val['user']

            if val['ipv4_address'] is not None:
                ipv4_dict = {
                    'address': val['ipv4_address'],
                    'port': val['port'],
                }
                target_config['ipv4'] = ipv4_dict

            snmp_target['config'] = target_config
            snmp_target['name'] = val['name']
            snmp_targets.append(snmp_target)
        return snmp_targets

    @property
    def snmp_user(self):
        if self._values['snmp_user'] is None:
            return None
        snmp_user = []
        for val in self._values['snmp_user']:
            result = {
                'name': val['name'],
                'config': {
                    'name': val['name']
                }
            }
            if 'auth_proto' in val and val['auth_proto'] is not None:
                result['config']['authentication-protocol'] = val['auth_proto']

            if 'auth_passwd' in val and val['auth_passwd'] is not None:
                result['config']['authentication-password'] = val['auth_passwd']

            if 'privacy_proto' in val and val['privacy_proto'] is not None:
                result['config']['privacy-protocol'] = val['privacy_proto']

            if 'privacy_passwd' in val and val['privacy_passwd'] is not None:
                result['config']['privacy-password'] = val['privacy_passwd']

            snmp_user.append(result)
        return snmp_user

    @property
    def snmp_mib(self):
        if self._values['snmp_mib'] is None:
            return None
        snmp_mib = []
        result = dict()
        result['config'] = dict()
        if 'syscontact' in self._values['snmp_mib']:
            result['config']['SNMPv2-MIB:sysContact'] = self._values['snmp_mib']['syscontact']
        if 'sysname' in self._values['snmp_mib']:
            result['config']['SNMPv2-MIB:sysName'] = self._values['snmp_mib']['sysname']
        if 'syslocation' in self._values['snmp_mib']:
            result['config']['SNMPv2-MIB:sysLocation'] = self._values['snmp_mib']['syslocation']
        snmp_mib.append(result)
        return snmp_mib


class ReportableChanges(Changes):
    pass


class Difference(object):  # pragma: no cover
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        if hasattr(self, param):
            return getattr(self, param)
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
    def snmp_community(self):
        '''Discrepancy between Module name (security_model) and API name (security-model)'''
        if getattr(self.want, 'snmp_community') is not None:
            for wcommunity in self.want.snmp_community:
                for hcommunity in self.have.snmp_community:
                    if wcommunity['name'] == hcommunity['name']:
                        if wcommunity['security_model'] == hcommunity['security-model']:
                            return None
                        return self.want.snmp_community

    @property
    def snmp_target(self):
        '''Discrepancy between Module name (security_model, ipv4_address, ipv6_address, port) and
        API name (security-model, ipv4:{address, port}, ipv6:{address, port})'''
        if getattr(self.want, 'snmp_target') is not None:
            for wtarget in self.want.snmp_target:
                for htarget in self.have.snmp_target:
                    if wtarget['name'] == htarget['name']:
                        if 'security_model' in wtarget and wtarget['security_model'] is not None:
                            if 'security-model' not in htarget:
                                return self.want.snmp_target
                            if wtarget['security_model'] != htarget['security-model']:
                                return self.want.snmp_target

                        if 'community' in wtarget and wtarget['community'] is not None:
                            if 'community' not in htarget:
                                return self.want.snmp_target
                            if wtarget['community'] != htarget['community']:
                                return self.want.snmp_target

                        if 'user' in wtarget and wtarget['user'] is not None:
                            if 'user' not in htarget:
                                return self.want.snmp_target
                            if wtarget['user'] != htarget['user']:
                                return self.want.snmp_target

                        if 'ipv4_address' in wtarget and wtarget['ipv4_address'] is not None:
                            ip_ver = 'ipv4'
                            if ip_ver not in htarget or 'address' not in htarget[ip_ver]:
                                return self.want.snmp_target
                            if wtarget['ipv4_address'] != htarget[ip_ver]['address']:
                                return self.want.snmp_target

                        if 'ipv6_address' in wtarget and wtarget['ipv6_address'] is not None:
                            ip_ver = 'ipv6'
                            if ip_ver not in htarget or 'address' not in htarget[ip_ver]:
                                return self.want.snmp_target
                            if wtarget['ipv6_address'] != htarget[ip_ver]['address']:
                                return self.want.snmp_target

                        if 'port' in wtarget and wtarget['port'] is not None:
                            if ip_ver not in htarget or 'port' not in htarget[ip_ver]:
                                return self.want.snmp_target
                            if wtarget['port'] != htarget[ip_ver]['port']:
                                return self.want.snmp_target

                        return None

    @property
    def snmp_user(self):
        '''Discrepancy between Module name (auth_proto, auth_passwd, privacy_proto, privacy_passwd)
        and API name (authentication-protocol, authentication-password, privacy-protocol, privacy-password)'''
        if getattr(self.want, 'snmp_user') is not None:
            for wuser in self.want.snmp_user:
                for huser in self.have.snmp_user:
                    if wuser['name'] == huser['name']:
                        if 'auth_proto' in wuser:
                            if 'authentication-protocol' not in huser:
                                return self.want.snmp_user
                            if wuser['auth_proto'] != huser['authentication-protocol']:
                                return self.want.snmp_user

                        if 'auth_passwd' in wuser:
                            if 'authentication-password' not in huser:
                                return self.want.snmp_user
                            if wuser['auth_passwd'] != huser['authentication-password']:
                                return self.want.snmp_user

                        if 'privacy_proto' in wuser:
                            if 'privacy-protocol' not in huser:
                                return self.want.snmp_user
                            if wuser['privacy_proto'] != huser['privacy-protocol']:
                                return self.want.snmp_user

                        if 'privacy_passwd' in wuser:
                            if 'privacy-password' not in huser:
                                return self.want.snmp_user
                            if wuser['privacy_passwd'] != huser['privacy-password']:
                                return self.want.snmp_user

                        return None

    @property
    def snmp_mib(self):
        '''Discrepancy between Module name (syscontact, sysname, syslocation)
        and API name (SNMPv2-MIB:sysContact, SNMPv2-MIB:sysName, SNMPv2-MIB:sysLocation)'''
        if getattr(self.want, 'snmp_mib') is not None:
            wmib = self.want.snmp_mib
            hmib = self.have.snmp_mib
            if 'sysname' in wmib:
                if 'sysName' not in hmib:
                    return {'snmp_mib': wmib}
                if wmib['sysname'] != hmib['sysName']:
                    return {'snmp_mib': wmib}
            if 'syscontact' in wmib:
                if 'sysContact' not in hmib:
                    return {'snmp_mib': wmib}
                if wmib['syscontact'] != hmib['sysContact']:
                    return {'snmp_mib': wmib}
            if 'syslocation' in wmib:
                if 'sysLocation' not in hmib:
                    return {'snmp_mib': wmib}
                if wmib['syslocation'] != hmib['sysLocation']:
                    return {'snmp_mib': wmib}
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

    def update(self) -> bool:
        '''Update object on F5OS system'''
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self) -> bool:
        '''Remove object from F5OS system'''
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self) -> bool:
        '''Create object on F5OS system'''
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self) -> bool:
        '''Check object existance on F5OS system'''
        base_uri = "/openconfig-system:system/f5-system-snmp:snmp"
        for object in ['snmp_community', 'snmp_target', 'snmp_user']:
            if (hasattr(self.want, object) and getattr(self.want, object) is not None):
                for val in getattr(self.want, object):
                    if object == 'snmp_community':
                        object_uri = "/communities/community={}".format(val['name'])
                    elif object == 'snmp_target':
                        object_uri = "/targets/target={}".format(val['name'])
                    elif object == 'snmp_user':
                        object_uri = "/users/user={}".format(val['name'])

                    uri = base_uri + object_uri

                    if object == 'snmp_mib':
                        uri = "/SNMPv2-MIB:SNMPv2-MIB/system"

                    response = self.client.get(uri)
                    if response['code'] == 404:
                        return False
                    if response['code'] not in [200, 201, 202]:
                        raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        '''API communication to actually create the objects on the F5OS system'''
        params = self.changes.api_params()
        base_uri = "/openconfig-system:system/f5-system-snmp:snmp"

        if 'snmp_community' in params:
            for snmp_community in params['snmp_community']:
                object_uri = "/f5-system-snmp:communities"
                uri = base_uri + object_uri
                payload = {'community': [{'name': snmp_community['name'], 'config': snmp_community['config']}]}
                response = self.client.post(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'snmp_target' in params:
            for snmp_target in params['snmp_target']:
                object_uri = "/f5-system-snmp:targets"
                uri = base_uri + object_uri
                payload = {'target': [{'name': snmp_target['name'], 'config': snmp_target['config']}]}
                response = self.client.post(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'snmp_user' in params:
            for snmp_user in params['snmp_user']:
                object_uri = "/f5-system-snmp:users"
                uri = base_uri + object_uri
                payload = {'user': [{'name': snmp_user['name'], 'config': snmp_user['config']}]}
                response = self.client.post(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'snmp_mib' in params:
            for snmp_mib in params['snmp_mib']:
                uri = "/SNMPv2-MIB:SNMPv2-MIB/system"
                payload = snmp_mib['config']
                response = self.client.post(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        '''API communication to actually update the objects on the F5OS system'''
        params = self.changes.api_params()
        base_uri = "/openconfig-system:system/f5-system-snmp:snmp"

        if 'snmp_community' in params:
            for snmp_community in params['snmp_community']:
                object_uri = "/f5-system-snmp:communities/f5-system-snmp:community={}/config".format(snmp_community['name'])
                uri = base_uri + object_uri
                payload = {'config': snmp_community['config']}
                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'snmp_target' in params:
            for snmp_target in params['snmp_target']:
                object_uri = "/f5-system-snmp:targets/f5-system-snmp:target={}/config".format(snmp_target['name'])
                uri = base_uri + object_uri
                payload = {'config': snmp_target['config']}
                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'snmp_user' in params:
            for snmp_user in params['snmp_user']:
                object_uri = "/f5-system-snmp:users/f5-system-snmp:user={}/config".format(snmp_user['name'])
                uri = base_uri + object_uri
                payload = {'config': snmp_user['config']}
                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'snmp_mib' in params:
            for snmp_mib in params['snmp_mib']:
                uri = "/SNMPv2-MIB:SNMPv2-MIB/system/sysContact"
                payload = snmp_mib['config']
                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        '''API communication to actually remove the objects on the F5OS system'''
        if self.want.snmp_target is not None:
            for val in self.want.snmp_target:
                uri = f"/openconfig-system:system/f5-system-snmp:snmp/targets/target={val['name']}"
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])
        if self.want.snmp_community is not None:
            for val in self.want.snmp_community:
                uri = f"/openconfig-system:system/f5-system-snmp:snmp/communities/community={val['name']}"
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])
        if self.want.snmp_user is not None:
            for val in self.want.snmp_user:
                uri = f"/openconfig-system:system/f5-system-snmp:snmp/users/user={val['name']}"
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        '''API communication to read the objects on the F5OS system'''
        uri = "/openconfig-system:system/f5-system-snmp:snmp"
        response = self.client.get(uri)
        return_object = response['contents']['f5-system-snmp:snmp']
        snmp_mib_uri = "/SNMPv2-MIB:SNMPv2-MIB/system"
        snmp_mib_response = self.client.get(snmp_mib_uri)
        return_object['snmp_mib'] = snmp_mib_response['contents']['SNMPv2-MIB:system']
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=return_object)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            snmp_user=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    auth_proto=dict(type='str'),
                    auth_passwd=dict(
                        type='str',
                        no_log=True
                    ),
                    privacy_proto=dict(type='str'),
                    privacy_passwd=dict(
                        type='str',
                        no_log=True
                    ),
                )
            ),
            snmp_community=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    security_model=dict(type='list',
                                        elements='str'),
                )
            ),
            snmp_target=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    security_model=dict(type='str'),
                    community=dict(type='str'),
                    ipv4_address=dict(type='str'),
                    port=dict(type='int',
                              required=True),
                    ipv6_address=dict(type='str'),
                    user=dict(type='str')
                )
            ),
            snmp_mib=dict(
                type='dict',
                options=dict(
                    syscontact=dict(type='str'),
                    sysname=dict(type='str'),
                    syslocation=dict(type='str'),
                )
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_one_of = [('snmp_community', 'snmp_target', 'snmp_user', 'snmp_mib')]


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
