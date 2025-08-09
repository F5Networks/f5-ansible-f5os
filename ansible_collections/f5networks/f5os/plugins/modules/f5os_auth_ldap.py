#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_auth_ldap
short_description: Manage LDAP common configuration.
description:
    - Manage LDAP common configuration on F5OS system.
version_added: "1.15.0"
options:
    base_dn:
        description:
            - Specifies the base DN for the LDAP search
        type: str
    bind_dn:
        description:
            - Specifies the bind DN for the LDAP search
        type: str
    bind_password:
        description:
            - Specifies the bind password for the LDAP search
        type: str
    bind_timeout:
        description:
            - Specifies the bind timeout for the LDAP search
        type: int
    read_timeout:
        description:
            - Specifies the read timeout for the LDAP search
        type: int
    idle_timeout:
        description:
            - Specifies the idle timeout for the LDAP search
        type: int
    ldap_version:
        description:
            - Specifies the LDAP version to be used for the search
        type: int
    chase_referrals:
        description:
            - Specifies whether to chase referrals during the LDAP search
        type: bool
    tls:
        description:
            - Specifies whether to use tls for the LDAP search
        type: str
        choices:
            - 'start_tls'
            - 'off'
            - 'on'
    tls_certificate_validation:
        description:
            - Specifies whether to validate the TLS certificate during the LDAP search
            - Applies only when C(tls) is set to C(start_tls) or C(on).
        type: str
        choices:
            - 'never'
            - 'allow'
            - 'try'
            - 'hard'
            - 'demand'
    tls_ciphers:
        description:
            - Specifies the TLS ciphers to be used for the LDAP search
            - Applies only when C(tls) is set to C(start_tls) or C(on).
        type: str
    active_directory:
        description:
            - Specifies whether the LDAP server is an Active Directory server
        type: bool
    unix_attributes:
        description:
            - Specifies whether to use Unix attributes for the LDAP search
            - Unix attributes does not apply to Velos Partition.
        type: bool
    tls_certificate:
        description:
            - Specifies the TLS certificate to be used for the LDAP search
            - Applies only when C(tls) is set to C(start_tls) or C(on).
        type: str
    tls_key:
        description:
            - Specifies the TLS key to be used for the LDAP search
            - Applies only when C(tls) is set to C(start_tls) or C(on).
        type: str

notes:
    - This Module makes a PUT request to the F5OS system to update the LDAP common configuration.
    - The parameters not specified in the module will not be updated and will remain unchanged.
    - Changes on Bind Password will not be detected by the module.
author:
    - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''

- name: Create LDAP Common Configuration
  f5os_auth_ldap:
    base_dn: "dc=example,dc=com"
    bind_dn: "cn=admin,dc=example,dc=com"
    bind_password: "password"
    bind_timeout: 10
    read_timeout: 30
    idle_timeout: 300
    ldap_version: 3
    chase_referrals: true
    tls: "start_tls"
    tls_certificate_validation: "demand"
    tls_ciphers: "HIGH:!aNULL:!MD5"
    active_directory: true
    unix_attributes: false

'''

RETURN = r'''
base_dn:
  description: Base DN for the LDAP search.
  returned: changed
  type: str
bind_dn:
  description: Bind DN for the LDAP search.
  returned: changed
  type: str
bind_password:
  description: Bind password for the LDAP search.
  returned: changed
  type: str
bind_timeout:
  description: Bind timeout for the LDAP search.
  returned: changed
  type: int
read_timeout:
  description: Read timeout for the LDAP search.
  returned: changed
  type: int
idle_timeout:
  description: Idle timeout for the LDAP search.
  returned: changed
  type: int
ldap_version:
  description: LDAP version to be used for the search.
  returned: changed
  type: int
chase_referrals:
  description: Whether to chase referrals during the LDAP search.
  returned: changed
  type: bool
tls:
  description: Whether to use TLS for the LDAP search.
  returned: changed
  type: str
tls_certificate_validation:
  description: Whether to validate the TLS certificate during the LDAP search.
  returned: changed
  type: str
tls_ciphers:
  description: TLS ciphers to be used for the LDAP search.
  returned: changed
  type: str
active_directory:
  description: Whether the LDAP server is an Active Directory server.
  returned: changed
  type: bool
unix_attributes:
  description: Whether to use Unix attributes for the LDAP search.
  returned: changed
  type: bool
tls_certificate:
  description: TLS certificate to be used for the LDAP search.
  returned: changed
  type: str
tls_key:
  description: TLS key to be used for the LDAP search.
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
        'base_dn',
        'bind_dn',
        'bind_password',
        'bind_timeout',
        'read_timeout',
        'idle_timeout',
        'ldap_version',
        'chase_referrals',
        'tls',
        'tls_certificate_validation',
        'tls_ciphers',
        'active_directory',
        'unix_attributes',
        'tls_certificate',
        'tls_key'
    ]

    returnables = [
    ]

    updatables = [
        'base_dn',
        'bind_dn',
        # 'bind_password',
        'bind_timeout',
        'read_timeout',
        'idle_timeout',
        'ldap_version',
        'chase_referrals',
        'tls',
        'tls_certificate_validation',
        'tls_ciphers',
        'active_directory',
        'unix_attributes',
        'tls_certificate',
        'tls_key'
    ]


class ApiParameters(Parameters):

    @property
    def base_dn(self):
        if 'base' in self._values:
            return self._values['base'][0]
        return None

    @property
    def bind_dn(self):
        if 'binddn' in self._values:
            return self._values['binddn']
        return None

    @property
    def bind_password(self):
        if 'bindpw' in self._values:
            return self._values['bindpw']
        return None

    @property
    def bind_timeout(self):
        if 'bind_timelimit' in self._values:
            return self._values['bind_timelimit']
        return None

    @property
    def read_timeout(self):
        if 'timelimit' in self._values:
            return self._values['timelimit']
        return None

    @property
    def idle_timeout(self):
        if 'idle_timelimit' in self._values:
            return self._values['idle_timelimit']
        return None

    @property
    def ldap_version(self):
        if 'ldap_version' in self._values:
            return self._values['ldap_version']
        return None

    @property
    def tls(self):
        if 'ssl' in self._values:
            return self._values['ssl']
        return None

    @property
    def chase_referrals(self):
        if 'chase-referrals' in self._values:
            return self._values['chase-referrals']
        return None

    @property
    def tls_certificate_validation(self):
        if 'tls_reqcert' in self._values:
            return self._values['tls_reqcert']
        return None

    @property
    def tls_ciphers(self):
        if 'tls_ciphers' in self._values:
            return self._values['tls_ciphers']
        return None

    @property
    def active_directory(self):
        if 'active_directory' in self._values:
            return self._values['active_directory']
        return None

    @property
    def unix_attributes(self):
        if 'unix_attributes' in self._values:
            return self._values['unix_attributes']
        return None

    @property
    def tls_certificate(self):
        if 'tls_cert' in self._values:
            return self._values['tls_cert']
        return None

    @property
    def tls_key(self):
        if 'tls_key' in self._values:
            return self._values['tls_key']
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
        if param in ['tls_certificate_validation', 'tls_ciphers', 'tls_certificate', 'tls_key']:
            return self.tls_params(param)
        if hasattr(self, param):
            return getattr(self, param)
        else:
            return self.__default(param)

    def tls_params(self, param):
        tls = self.want.tls
        if tls is None:
            return None
        if tls == 'start_tls' or tls == 'on':
            return self.__default(param)
        return None

    def __default(self, param):
        want = getattr(self.want, param)
        if hasattr(self.have, param):
            have = getattr(self.have, param)
            if want != have:
                return want
        else:
            return want


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
        changed = self.present()
        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        '''Wrapper for creation/update'''
        return self.update()

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

    def update_on_device(self):
        '''API communication to actually update the objects on the F5OS system'''
        params = self.changes.api_params()
        base_uri = "/openconfig-system:system/aaa/authentication/f5-openconfig-aaa-ldap:ldap"
        payload = {
            "f5-openconfig-aaa-ldap:ldap": {
                "base": [params.get("base_dn") if params.get("base_dn") is not None else self.have.base_dn],
                "binddn": params.get("bind_dn") if params.get("bind_dn") is not None else self.have.bind_dn,
                "bindpw": params.get("bind_password") if params.get("bind_password") is not None else self.have.bind_password,
                "bind_timelimit": params.get("bind_timeout") if params.get("bind_timeout") is not None else self.have.bind_timeout,
                "timelimit": params.get("read_timeout") if params.get("read_timeout") is not None else self.have.read_timeout,
                "idle_timelimit": params.get("idle_timeout") if params.get("idle_timeout") is not None else self.have.idle_timeout,
                "ldap_version": params.get("ldap_version") if params.get("ldap_version") is not None else self.have.ldap_version,
                "chase-referrals": params.get("chase_referrals") if params.get("chase_referrals") is not None else self.have.chase_referrals,
                "ssl": params.get("tls") if params.get("tls") is not None else self.have.tls,
                "tls_reqcert": params.get("tls_certificate_validation") if params.get("tls_certificate_validation")
                is not None else self.have.tls_certificate_validation,
                "tls_ciphers": params.get("tls_ciphers") if params.get("tls_ciphers") is not None else self.have.tls_ciphers,
                "active_directory": params.get("active_directory") if params.get("active_directory") is not None else self.have.active_directory,
                "unix_attributes": params.get("unix_attributes") if params.get("unix_attributes") is not None else self.have.unix_attributes,
                "tls_cert": params.get("tls_certificate") if params.get("tls_certificate") is not None else self.have.tls_certificate,
                "tls_key": params.get("tls_key") if params.get("tls_key") is not None else self.have.tls_key,
            }
        }

        keys_to_remove = [k for k, v in payload["f5-openconfig-aaa-ldap:ldap"].items() if v is None or (isinstance(v, list) and (len(v) == 0 or v[0] is None))]
        for k in keys_to_remove:
            payload["f5-openconfig-aaa-ldap:ldap"].pop(k)

        response = self.client.put(base_uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        '''API communication to read the objects on the F5OS system'''
        uri = "/openconfig-system:system/aaa/authentication/f5-openconfig-aaa-ldap:ldap/"

        response = self.client.get(uri)
        if 'f5-openconfig-aaa-ldap:ldap' in response['contents']:
            return_object = response['contents']['f5-openconfig-aaa-ldap:ldap']
        else:
            return_object = None

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])  # pragma: no cover
        return ApiParameters(params=return_object)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            base_dn=dict(type='str'),
            bind_dn=dict(type='str'),
            bind_password=dict(type='str', no_log=True),
            bind_timeout=dict(type='int'),
            read_timeout=dict(type='int'),
            idle_timeout=dict(type='int'),
            ldap_version=dict(type='int'),
            chase_referrals=dict(type='bool'),
            tls=dict(
                type='str',
                choices=['start_tls', 'off', 'on']),
            tls_certificate_validation=dict(
                type='str',
                choices=['never', 'allow', 'try', 'hard', 'demand']),
            tls_ciphers=dict(type='str'),
            active_directory=dict(type='bool'),
            unix_attributes=dict(type='bool'),
            tls_certificate=dict(type='str'),
            tls_key=dict(type='str', no_log=True),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = []
        self.required_one_of = []


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_one_of=spec.required_one_of,
        mutually_exclusive=spec.mutually_exclusive
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
