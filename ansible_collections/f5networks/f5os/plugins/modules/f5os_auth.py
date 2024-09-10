#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_auth
short_description: Manage authentication settings
description:
  - Manage authentication settings including
  - Remote Auth Servers
  - Remote Roles
  - Authentication order
  - Password Policy
  - Please Note This playbook is NOT IDEMPOTENT for API flaws, such as radius
  - and tacacs secrets are only reported encrypted and password policy always reports
  - as present. For these items, a change is always reported.
version_added: 1.10.0
options:
    servergroups:
        description:
            - Specifies Server Groups for remote authentication
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - Name of the server group
                type: str
            protocol:
                description:
                    - authentication protocol for the server group.
                    - options are [radius, tacacs, ldap, ocsp]
                type: str
            servers:
                description:
                    - Server list as members of the Server Group
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - Address of the remote host
                        type: str
                    port:
                        description:
                            - Network Port (TCP/UDP) to be used on the remote server
                        type: int
                    security:
                        description:
                            - Security setting for LDAP Servers (Applies to LDAP only)
                            - if present, should be None (LDAP) or "tls" (LDAPS)
                        type: str
                    secret:
                        description:
                            - Secret for RADIUS or TACACS+ Servers (Applies to RADIUS and TACACS+ only)
                        type: str
                    timeout:
                        description:
                            - Timeout for RADIUS Servers (Applies to RADIUS only)
                        default: 3
                        type: int
    remote_roles:
        description:
            - Specifies the conditions under which a role is applied to a remote-authenticated user
        type: list
        elements: dict
        suboptions:
            rolename:
                description:
                    - Name of the role as configured on the system
                    - Options are [admin, resource-admin, superuser, operator, user]
                type: str
            ldap_group:
                description:
                    - Name of the LDAP group (Applies to LDAP only)
                type: str
            remote_gid:
                description:
                    - Specifies the remote Group ID to be associated with the local role
                type: int
    auth_order:
        description:
            - Specifies the order in which the authentication providers are applied to login attempts
            - Options are [local, radius, tacacs, ldap]
        type: list
        elements: str
    password_policy:
        description:
            - Specifies the password policy for local user accounts
        type: dict
        suboptions:
            apply_to_root:
                description:
                    - Specifies if the password policy also applies to the root user
                type: bool
            max_age:
                description:
                    - Specifies the maximum age for a password
                type: int
            max_class_repeat:
                description:
                    - Specifies the maximum repetition of Characters within the same class
                type: int
            max_letter_repeat:
                description:
                    - Specifies the maximum repetition of the same character
                type: int
            max_login_failures:
                description:
                    - Specifies the maximum logon failures before a user is locked out
                type: int
            max_retries:
                description:
                    - Specifies the maximum attempts a user can try to create a valid password
                type: int
            max_sequence_repeat:
                description:
                    - Specifies the maximum repetition of a character sequence
                type: int
            min_differences:
                description:
                    - Specifies the number of characters that must be altered between updated passwords
                type: int
            min_length:
                description:
                    - Specifies the minimum password length
                type: int
            min_lower:
                description:
                    - Specifies the minimum number of lowercase characters
                type: int
            min_number:
                description:
                    - Specifies the minimum number of numeric characters
                type: int
            min_special:
                description:
                    - Specifies the minimum number of special character
                type: int
            min_upper:
                description:
                    - Specifies the minimum number of uppercase characters
                type: int
            reject_username:
                description:
                    - Specifies whether the system rejects passwords that contain the username
                type: bool
            root_lockout:
                description:
                    - Specifies whether the root user can be locked out
                type: bool
            root_unlock_time:
                description:
                    - Specifies the root users unlock time
                type: int
            unlock_time:
                description:
                    - Specifies the unlock the time
                type: int
    state:
        description:
            - If C(present), creates/updates the specified setting if necessary.
            - If C(absent), deletes the specified setting if it exists.
        type: str
        choices:
            - present
            - absent
        default: present
author:
  - Martin Vogel (@MVogel91)
'''

EXAMPLES = r'''
- name: Create Servers
  f5os_auth:
    servergroups:
      - name: radius_servers
        protocol: radius
        servers:
          - address: 10.2.3.4
            secret: TOPSECRET
            port: 1812
            timeout: 3
          - address: 10.2.3.5
            secret: TOPSECRET
            port: 1812
            timeout: 3
      - name: tacacs_servers
        protocol: tacacs
        servers:
          - address: 10.2.3.4
            secret: TOPSECRET
            port: 49
          - address: 10.2.3.5
            secret: TOPSECRET
            port: 49
      - name: ldap_servers
        protocol: ldap
        servers:
          - address: 10.2.3.4
            port: 389
          - address: 10.2.3.5
            port: 636
            security: tls
      - name: ocsp_servers
        protocol: ocsp
        servers:
          - address: 10.2.3.4
            port: 80
          - address: 10.2.3.5
            port: 80

- name: Set Auth Order
  f5os_auth:
    auth_order:
      - radius
      - tacacs
      - ldap
      - local

- name: Set Password Policy
  f5os_auth:
    password_policy:
      max_age: 30
      max_class_repeat: 2
      max_letter_repeat: 2
      max_login_failures: 10
      max_retries: 3
      max_sequence_repeat: 2
      min_differences: 8
      min_length: 16
      min_lower: 3
      min_number: 3
      min_special: 3
      min_upper: 3
      reject_username: true
      root_lockout: false
      root_unlock_time: 60
      unlock_time: 60

- name: Set Remote Roles
  f5os_auth:
    remote_roles:
      - rolename: admin
        remote_gid: 10
        ldap_group: admins
      - rolename: resource-admin
        remote_gid: 20
        ldap_group: resource-admins

- name: Delete Servers
  f5os_auth:
    servergroups:
      - name: radius_servers
        protocol: radius
        servers:
          - address: 10.2.3.4
            secret: TOPSECRET
            port: 1812
            timeout: 3
          - address: 10.2.3.5
            secret: TOPSECRET
            port: 1812
            timeout: 3
      - name: tacacs_servers
        protocol: tacacs
        servers:
          - address: 10.2.3.4
            secret: TOPSECRET
            port: 49
          - address: 10.2.3.5
            secret: TOPSECRET
            port: 49
      - name: ldap_servers
        protocol: ldap
        servers:
          - address: 10.2.3.4
            port: 389
          - address: 10.2.3.5
            port: 636
            security: tls
      - name: ocsp_servers
        protocol: ocsp
        servers:
          - address: 10.2.3.4
            port: 80
          - address: 10.2.3.5
            port: 80
    state: absent

- name: Set Auth Order
  f5os_auth:
    auth_order:
      - radius
      - tacacs
      - ldap
      - local
    state: absent

- name: Set Password Policy
  f5os_auth:
    password_policy:
      max_age: 30
      max_class_repeat: 2
      max_letter_repeat: 2
      max_login_failures: 10
      max_retries: 3
      max_sequence_repeat: 2
      min_differences: 8
      min_length: 16
      min_lower: 3
      min_number: 3
      min_special: 3
      min_upper: 3
      reject_username: true
      root_lockout: false
      root_unlock_time: 60
      unlock_time: 60
    state: absent

- name: Set Remote Roles
  f5os_auth:
    remote_roles:
      - rolename: admin
        remote_gid: 10
        ldap_group: admins
      - rolename: resource-admin
        remote_gid: 20
        ldap_group: resource-admins
    state: absent
'''

RETURN = r'''
servergroups:
  description: Specifies the servergroups
  returned: changed
  type: str
remote_roles:
  description: Specifies the remote roles
  returned: changed
  type: str
auth_order:
  description: Specifies the auth order
  returned: changed
  type: str
password_policy:
  description: Specifies the password policy
  returned: changed
  type: str
'''

import datetime

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

    }

    api_attributes = [
        'servergroups',
        'password_policy',
        'auth_order',
        'remote_roles'
    ]

    returnables = [
        'servergroups',
        'password_policy',
        'auth_order',
        'remote_roles'
    ]

    updatables = [
        'servergroups',
        'password_policy',
        'auth_order',
        'remote_roles'
    ]


class ApiParameters(Parameters):
    @property
    def servergroups(self):
        ''' Restructured API response to match the input pattern. '''
        try:
            return_list = list()
            for api in self._values['servergroups']:

                #   Types                          Protocols
                # - f5-openconfig-aaa-ldap:LDAP -> ldap
                # - f5-openconfig-aaa-ocsp:OCSP -> ocsp
                # - openconfig-aaa:RADIUS       -> radius
                # - openconfig-aaa:TACACS       -> tacacs

                auth_module = api['config']['type']
                protocol = auth_module.split(":")[1].lower()
                return_item = {
                    'name': api['name'],
                    'protocol': protocol
                }
                if 'servers' in api:
                    return_item['servers'] = list()
                    for server in api['servers']['server']:
                        server_conf = {
                            'address': server['address'],
                            'security': None,
                            'secret': None,
                            'timeout': 3
                        }
                        if protocol in ['radius', 'tacacs']:
                            auth_name = protocol
                        elif protocol in ['ldap', 'ocsp']:
                            auth_name = auth_module.lower()

                        if 'port' in server[auth_name]['config']:
                            server_conf['port'] = server[auth_name]['config']['port']
                        elif 'auth-port' in server[auth_name]['config']:
                            server_conf['port'] = server[auth_name]['config']['auth-port']

                        # add protocol specific settings
                        if 'type' in server[auth_name]['config']:
                            if server[auth_name]['config']['type'].lower() == 'f5-openconfig-aaa-ldap:ldaps':
                                server_conf['security'] = 'tls'

                        if 'secret-key' in server[auth_name]['config']:
                            server_conf['secret'] = server[auth_name]['config']['secret-key']

                        if 'f5-openconfig-aaa-radius:timeout' in server[auth_name]['config']:
                            server_conf['timeout'] = server[auth_name]['config']['f5-openconfig-aaa-radius:timeout']

                        return_item['servers'].append(server_conf)

                return_list.append(return_item)

            return return_list
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def password_policy(self):
        try:
            return_value = dict()
            api = self._values['password_policy']
            return_value['apply_to_root'] = api.get('apply-to-root')
            return_value['max_age'] = api.get('max-age')
            return_value['max_class_repeat'] = api.get('max-class-repeat')
            return_value['max_letter_repeat'] = api.get('max-letter-repeat')
            return_value['max_login_failures'] = api.get('max-login-failures')
            return_value['max_retries'] = api.get('retries')
            return_value['max_sequence_repeat'] = api.get('max-sequence-repeat')
            return_value['min_differences'] = api.get('required-differences')
            return_value['min_length'] = api.get('min-length')
            return_value['min_lower'] = api.get('required-lowercase')
            return_value['min_number'] = api.get('required-numeric')
            return_value['min_special'] = api.get('required-special')
            return_value['min_upper'] = api.get('required-uppercase')
            return_value['reject_username'] = api.get('reject-username')
            return_value['root_lockout'] = api.get('root-lockout')
            return_value['root_unlock_time'] = api.get('root-unlock-time')
            return_value['unlock_time'] = api.get('unlock-time')
            return return_value
        except (TypeError, ValueError):
            return None

    @property
    def auth_order(self):
        try:
            return_value = list()
            api = self._values['auth_order']
            for item in api:
                if item == 'openconfig-aaa-types:RADIUS_ALL':
                    return_value.append('radius')
                elif item == 'openconfig-aaa-types:TACACS_ALL':
                    return_value.append('tacacs')
                elif item == 'f5-openconfig-aaa-ldap:LDAP_ALL':
                    return_value.append('ldap')
                elif item == 'openconfig-aaa-types:LOCAL':
                    return_value.append('local')
            return return_value
        except (TypeError, ValueError):
            return None

    @property
    def remote_roles(self):
        try:
            conf_map = {
                'remote-gid': 'remote_gid',
                'ldap-group': 'ldap_group'
            }
            return_list = list()
            for api in self._values['remote_roles']:
                return_item = dict()
                for attr in api['config']:
                    if attr in ['description', 'gid']:
                        # ignore read-only attributes
                        continue
                    elif attr in conf_map:
                        return_item[conf_map[attr]] = api['config'].get(attr)
                    else:
                        return_item[attr] = api['config'].get(attr)

                return_list.append(return_item)

            return return_list
        except (TypeError, ValueError):
            return None


class ModuleParameters(Parameters):
    pass


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
        want = getattr(self.want, param)
        try:
            have = getattr(self.have, param)
            if want != have:
                return want
        except AttributeError:
            return want

    @property
    def password_policy(self):
        if self.want.password_policy is None:
            return None
        result = {
            'password_policy': dict()
        }
        password_policy = result['password_policy']
        identical = True
        for val in self.want.password_policy:
            if self.want.password_policy[val] is not None:
                password_policy[val] = self.want.password_policy[val]
                if self.want.password_policy[val] == self.have.password_policy.get(val):
                    continue
                else:
                    identical = False
        if identical:
            return None
        else:
            return result

    @property
    def remote_roles(self):
        if self.want.remote_roles is None:
            return None
        resultset = {
            'remote_roles': list()
        }
        identical = True
        for wrole in self.want.remote_roles:
            result = dict()
            for hrole in self.have.remote_roles:
                if wrole['rolename'] == hrole['rolename']:
                    for val in wrole:
                        if wrole[val] is not None:
                            result[val] = wrole[val]
                            if wrole[val] == hrole.get(val):
                                continue
                            else:
                                identical = False
            resultset['remote_roles'].append(result)
        if identical:
            return None
        else:
            return resultset


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

    def _set_password_policy(self, params):
        '''Helper for creating / updating password policy as both scenarios use the same
        method and syntax'''
        uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-password-policy:password-policy'
        payload = {
            'f5-openconfig-aaa-password-policy:password-policy': {
                'config': dict()
            }
        }
        config = payload['f5-openconfig-aaa-password-policy:password-policy']['config']

        values = params['password_policy']
        conf_map = {
            'apply_to_root': 'apply-to-root',
            'max_age': 'max-age',
            'max_class_repeat': 'max-class-repeat',
            'max_letter_repeat': 'max-letter-repeat',
            'max_login_failures': 'max-login-failures',
            'max_retries': 'retries',
            'max_sequence_repeat': 'max-sequence-repeat',
            'min_differences': 'required-differences',
            'min_length': 'min-length',
            'min_lower': 'required-lowercase',
            'min_number': 'required-numeric',
            'min_special': 'required-special',
            'min_upper': 'required-uppercase',
            'reject_username': 'reject-username',
            'root_lockout': 'root-lockout',
            'root_unlock_time': 'root-unlock-time',
            'unlock_time': 'unlock-time',
        }
        for attr in conf_map:
            if attr in values and values[attr] is not None:
                config[conf_map[attr]] = values[attr]

        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def _set_auth_order(self, params):
        '''Helper for creating / updating auth_order as both scenarios use the same
        method and syntax'''
        uri = '/openconfig-system:system/aaa/authentication/config/authentication-method'
        payload = {
            "openconfig-system:authentication-method": list()
        }
        config = payload['openconfig-system:authentication-method']

        values = params['auth_order']
        conf_map = {
            'radius': 'openconfig-aaa-types:RADIUS_ALL',
            'tacacs': 'openconfig-aaa-types:TACACS_ALL',
            'ldap': 'f5-openconfig-aaa-ldap:LDAP_ALL',
            'local': 'openconfig-aaa-types:LOCAL'
        }
        for item in values:
            config.append(conf_map[item])

        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def _set_remote_roles(self, params):
        '''Helper for creating / updating remote roles as both scenarios use the same
        method and syntax'''
        for remote_role in params['remote_roles']:
            uri = f'/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="{remote_role["rolename"]}"'
            payload = {
                'f5-system-aaa:role': [
                    {
                        'rolename': remote_role['rolename'],
                        'config': dict()
                    }
                ]
            }
            config = payload['f5-system-aaa:role'][0]['config']

            conf_map = {
                'remote_gid': 'remote-gid',
                'ldap_group': 'ldap-group'
            }
            for attr in remote_role:
                if remote_role[attr] is not None:
                    if attr in conf_map:
                        config[conf_map[attr]] = remote_role[attr]
                    else:
                        config[attr] = remote_role[attr]

            response = self.client.patch(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

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
        if self.all_exist():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.any_exists():
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
        if self.still_exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def any_exists(self):
        return self.exists(query='any')

    def all_exist(self):
        return self.exists(query='all')

    def still_exists(self):
        return self.exists(query='still')

    def exists(self, query=None):
        if hasattr(self.want, 'servergroups') and self.want.servergroups is not None:
            for servergroup in self.want.servergroups:
                uri = f'/openconfig-system:system/aaa/server-groups/server-group="{servergroup["name"]}"'
                response = self.client.get(uri)

                if response['code'] == 200:
                    if query in ['any', 'still']:
                        return True

                if response['code'] == 404:
                    if query == 'all':
                        return False

                if response['code'] not in [200, 201, 202, 404]:
                    raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'password_policy') and self.want.password_policy is not None:
            if hasattr(self.want, 'password_policy') and self.want.password_policy is not None:
                uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-password-policy:password-policy'
                response = self.client.get(uri)
                if response['code'] != 200:
                    # Password Policy always exists
                    raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'auth_order') and self.want.auth_order is not None:
            uri = '/openconfig-system:system/aaa/authentication/config/authentication-method'
            response = self.client.get(uri)

            if response['code'] == 200:
                if query in ['any', 'still']:
                    return True

            if response['code'] == 404:
                if query == 'all':
                    return False

            if response['code'] not in [200, 201, 202, 404]:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'remote_roles') and self.want.remote_roles is not None:
            for remote_role in self.want.remote_roles:
                uri = f'/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="{remote_role["rolename"]}"'
                response = self.client.get(uri)
                if response['code'] == 200:
                    # Password Policy always exists.
                    # After resetting with delete, it fails the removal check
                    config = response['contents']['f5-system-aaa:role'][0]['config']
                    if 'remote-gid' in config or 'ldap-group' in config:
                        # Non-Default config
                        if query in ['any', 'still']:
                            return True
                    else:
                        if query == 'all':
                            return False
                else:
                    raise F5ModuleError(response['contents'])

        if query == 'still':
            return False
        if query == 'any':
            if hasattr(self.want, 'password_policy') and self.want.password_policy is not None:
                return True
            else:
                return False
        return True

    def create_on_device(self):
        params = self.changes.api_params()

        if 'servergroups' in params and params['servergroups'] is not None:
            for servergroup in params['servergroups']:
                name = servergroup['name']
                protocol = servergroup['protocol']

                uri = '/openconfig-system:system/aaa/server-groups'
                payload = {
                    'openconfig-system:server-group': {
                        'name': name,
                        'config': {
                            'name': name
                        }
                    }
                }
                properties = payload['openconfig-system:server-group']
                config = properties['config']

                if 'servers' in servergroup:
                    properties['servers'] = {
                        'server': list()
                    }
                    servers = properties['servers']['server']

                    for server in servergroup['servers']:
                        server_conf = {
                            'address': server['address'],
                            'config': {
                                'address': server['address']
                            }
                        }
                        if protocol == 'ldap':
                            if server['security'] == 'tls':
                                server_type = 'ldaps'
                            else:
                                server_type = 'ldap'

                            server_conf['f5-openconfig-aaa-ldap:ldap'] = {
                                'config': {
                                    'auth-port': server['port'],
                                    'type': 'f5-openconfig-aaa-ldap:' + server_type
                                }
                            }
                        elif protocol == 'ocsp':
                            server_conf['f5-openconfig-aaa-ocsp:ocsp'] = {
                                'config': {
                                    'port': server['port']
                                }
                            }
                        elif protocol == 'radius':
                            server_conf[protocol] = {
                                'config': {
                                    'auth-port': server['port'],
                                    'secret-key': server['secret'],
                                    'f5-openconfig-aaa-radius:timeout': server['timeout']
                                }
                            }
                        elif protocol == 'tacacs':
                            server_conf[protocol] = {
                                'config': {
                                    'port': server['port'],
                                    'secret-key': server['secret']
                                }
                            }
                        servers.append(server_conf)

                if protocol == 'ldap':
                    config['type'] = 'f5-openconfig-aaa-ldap:LDAP'
                elif protocol == 'ocsp':
                    config['type'] = 'f5-openconfig-aaa-ocsp:OCSP'
                elif protocol == 'radius':
                    config['type'] = 'openconfig-aaa:RADIUS'
                elif protocol == 'tacacs':
                    config['type'] = 'openconfig-aaa:TACACS'

                response = self.client.post(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'remote_roles' in params and params['remote_roles'] is not None:
            self._set_remote_roles(params)

        if 'password_policy' in params and params['password_policy'] is not None:
            self._set_password_policy(params)

        if 'auth_order' in params and params['auth_order'] is not None:
            self._set_auth_order(params)

        return True

    def update_on_device(self):
        params = self.changes.api_params()

        if 'servergroups' in params and params['servergroups'] is not None:
            for servergroup in params['servergroups']:
                name = servergroup['name']
                protocol = servergroup['protocol']

                uri = f'/openconfig-system:system/aaa/server-groups/server-group="{name}"'
                payload = {
                    'openconfig-system:server-group': {
                        'name': name,
                        'config': {
                            'name': name
                        }
                    }
                }
                properties = payload['openconfig-system:server-group']
                config = properties['config']

                if 'servers' in servergroup:
                    properties['servers'] = {
                        'server': list()
                    }
                    servers = properties['servers']['server']

                    for server in servergroup['servers']:
                        server_conf = {
                            'address': server['address'],
                            'config': {
                                'address': server['address']
                            }
                        }
                        if protocol == 'ldap':
                            if server['security'] == 'tls':
                                server_type = 'ldaps'
                            else:
                                server_type = 'ldap'

                            server_conf['f5-openconfig-aaa-ldap:ldap'] = {
                                'config': {
                                    'auth-port': server['port'],
                                    'type': 'f5-openconfig-aaa-ldap:' + server_type
                                }
                            }
                        elif protocol == 'ocsp':
                            server_conf['f5-openconfig-aaa-ocsp:ocsp'] = {
                                'config': {
                                    'port': server['port']
                                }
                            }
                        elif protocol == 'radius':
                            server_conf[protocol] = {
                                'config': {
                                    'auth-port': server['port'],
                                    'secret-key': server['secret'],
                                    'f5-openconfig-aaa-radius:timeout': server['timeout']
                                }
                            }
                        elif protocol == 'tacacs':
                            server_conf[protocol] = {
                                'config': {
                                    'port': server['port'],
                                    'secret-key': server['secret']
                                }
                            }
                        servers.append(server_conf)

                if protocol == 'ldap':
                    config['type'] = 'f5-openconfig-aaa-ldap:LDAP'
                elif protocol == 'ocsp':
                    config['type'] = 'f5-openconfig-aaa-ocsp:OCSP'
                elif protocol == 'radius':
                    config['type'] = 'openconfig-aaa:RADIUS'
                elif protocol == 'tacacs':
                    config['type'] = 'openconfig-aaa:TACACS'

                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if 'remote_roles' in params and params['remote_roles'] is not None:
            self._set_remote_roles(params)

        if 'password_policy' in params and params['password_policy'] is not None:
            self._set_password_policy(params)

        if 'auth_order' in params and params['auth_order'] is not None:
            self._set_auth_order(params)

        return True

    def remove_from_device(self):
        if hasattr(self.want, 'servergroups') and self.want.servergroups is not None:
            for servergroup in self.want.servergroups:
                uri = f'/openconfig-system:system/aaa/server-groups/server-group="{servergroup["name"]}"'
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'password_policy') and self.want.password_policy is not None:
            uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-password-policy:password-policy'
            response = self.client.delete(uri)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'auth_order') and self.want.auth_order is not None:
            uri = '/openconfig-system:system/aaa/authentication/config/authentication-method'
            response = self.client.delete(uri)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'remote_roles') and self.want.remote_roles is not None:
            for remote_role in self.want.remote_roles:
                uri = f'/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="{remote_role["rolename"]}"/config/remote-gid'
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204, 404]:
                    raise F5ModuleError(response['contents'])

                uri = f'/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="{remote_role["rolename"]}"/config/ldap-group'
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204, 404]:
                    raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        params = dict()

        # Servergroup
        if hasattr(self.want, 'servergroups') and self.want.servergroups is not None:
            params['servergroups'] = list()
            for servergroup in self.want.servergroups:
                uri = f'/openconfig-system:system/aaa/server-groups/server-group="{servergroup["name"]}"'
                servergroup_response = self.client.get(uri)
                if servergroup_response['code'] == 404:
                    # add empty object
                    params['servergroups'] = params['servergroups'] + [{'name': servergroup["name"]}]
                elif servergroup_response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(servergroup_response['contents']['openconfig-system:server-group'])
                else:
                    params['servergroups'] = params['servergroups'] + (servergroup_response['contents']['openconfig-system:server-group'])

        # Password Policy
        if hasattr(self.want, 'password_policy') and self.want.password_policy is not None:
            uri = '/openconfig-system:system/aaa/f5-openconfig-aaa-password-policy:password-policy'
            password_policy_response = self.client.get(uri)
            if password_policy_response['code'] not in [200, 201, 202]:
                raise F5ModuleError(password_policy_response['contents']['f5-openconfig-aaa-password-policy:password-policy'])

            params['password_policy'] = password_policy_response['contents']['f5-openconfig-aaa-password-policy:password-policy']['config']

        # Auth Config order
        if hasattr(self.want, 'auth_order') and self.want.auth_order is not None:
            uri = '/openconfig-system:system/aaa/authentication/config/authentication-method'
            auth_order_response = self.client.get(uri)
            if auth_order_response['code'] not in [200, 201, 202]:
                raise F5ModuleError(auth_order_response['contents']['openconfig-system:authentication-method'])

            params['auth_order'] = auth_order_response['contents']['openconfig-system:authentication-method']

        # Remote Roles
        if hasattr(self.want, 'remote_roles') and self.want.remote_roles is not None:
            params['remote_roles'] = list()
            for remote_role in self.want.remote_roles:
                uri = f'/openconfig-system:system/aaa/authentication/f5-system-aaa:roles/role="{remote_role["rolename"]}"'
                remote_roles_response = self.client.get(uri)
                if remote_roles_response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(remote_roles_response['contents']['f5-system-aaa:role'])
                params['remote_roles'] = params['remote_roles'] + remote_roles_response['contents']['f5-system-aaa:role']

        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            servergroups=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str'),
                    protocol=dict(type='str'),
                    servers=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            address=dict(type='str'),
                            security=dict(type='str'),
                            port=dict(type='int'),
                            secret=dict(type='str', no_log=True),
                            timeout=dict(type='int', default=3)
                        )
                    )
                )
            ),
            password_policy=dict(
                type='dict',
                no_log=False,
                options=dict(
                    apply_to_root=dict(type='bool'),
                    max_age=dict(type='int'),
                    max_class_repeat=dict(type='int'),
                    max_letter_repeat=dict(type='int'),
                    max_login_failures=dict(type='int'),
                    max_retries=dict(type='int'),
                    max_sequence_repeat=dict(type='int'),
                    min_differences=dict(type='int'),
                    min_length=dict(type='int'),
                    min_lower=dict(type='int'),
                    min_number=dict(type='int'),
                    min_special=dict(type='int'),
                    min_upper=dict(type='int'),
                    reject_username=dict(type='bool'),
                    root_lockout=dict(type='bool'),
                    root_unlock_time=dict(type='int'),
                    unlock_time=dict(type='int')
                )
            ),
            auth_order=dict(
                type='list',
                elements='str'
            ),
            remote_roles=dict(
                type='list',
                elements='dict',
                options=dict(
                    rolename=dict(type='str'),
                    ldap_group=dict(type='str'),
                    remote_gid=dict(type='int')
                )
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_one_of = [('servergroups', 'password_policy', 'auth_config', 'remote_roles')]


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
