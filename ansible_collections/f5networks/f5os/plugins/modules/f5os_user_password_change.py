#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_user_password_change
short_description: Change passwords for F5OS user accounts
description:
  - Supports updating passwords for default users (admin, root) as well as other accounts.
  - Allow an administrator to change passwords for F5OS user accounts by submitting RESTCONF API requests
version_added: "1.17.0"
options:
  user_name:
    description:
      - Name of the F5OS user account.
    type: str
    required: True
  old_password:
    description:
      - Current password for the specified user account.
    type: str
    required: True
  new_password:
    description:
      - New password for the specified user account.
    type: str
    required: True
notes:
  - This module is not idempotent.
  - This Module Manages only local authenticated user accounts.
  - when httpapi user is C(admin) and module user is non-admin, it will only set the password.
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Change password for admin
  f5os_user_password_change:
    user_name: admin
    old_password: default_pass
    new_password: new_admin_pass

- name: Change password for standard user
  f5os_user_password_change:
    user_name: user1
    old_password: default_pass
    new_password: mySecurePass@123

- name: Change password for root
  f5os_user_password_change:
    user_name: root
    old_password: root_default
    new_password: root_secure_password
'''

RETURN = r'''
# only common fields returned
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
        'old-password': 'old_password',
        'new-password': 'new_password',
        'confirm-password': 'confirm_pass',
    }

    api_attributes = [
        'old-password',
        'new-password',
        'confirm-password',
    ]

    returnables = [
        'old_password',
        'new_password',
        'confirm_pass',
    ]

    updatables = [

    ]


class ModuleParameters(Parameters):
    @property
    def confirm_pass(self):
        return self.new_password

    @property
    def new_password(self):
        if self._values['old_password'] == self._values['new_password']:
            raise F5ModuleError("Old and new password cannot be the same.")
        return self._values['new_password']

    @property
    def old_password(self):
        if self._values['old_password'] == self._values['new_password']:
            raise F5ModuleError("Old and new password cannot be the same.")
        return self._values['old_password']


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
    returnables = []


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.scope = "/restconf/operations/system/aaa"

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
        result = dict()

        changed = self.execute()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def execute(self):
        self._set_changed_options()
        result = self.change_password_on_device()
        return result

    def change_password_on_device(self):
        params = self.changes.api_params()
        if self.want.user_name == 'admin':
            uri = f"/authentication/users/user={self.want.user_name}/config/change-password"
            response = self.client.post(uri, data=params, scope=self.scope)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
            return True
        elif self.client.plugin.get_option('remote_user') != 'admin' and self.client.plugin.get_option('remote_user') == self.want.user_name:
            uri = f"/authentication/users/user={self.want.user_name}/config/change-password"
            response = self.client.post(uri, data=params, scope=self.scope, force_basic_auth=True)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
            return True
        else:
            uri = f"/openconfig-system:system/aaa/authentication/f5-system-aaa:users/user={self.want.user_name}/config/set-password"
            payload = {
                "password": self.want.new_password
            }
            response = self.client.post(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            user_name=dict(required=True),
            old_password=dict(required=True, no_log=True),
            new_password=dict(required=True, no_log=True)
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
