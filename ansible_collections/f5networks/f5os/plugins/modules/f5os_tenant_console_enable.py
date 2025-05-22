#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_tenant_console_enable
short_description: Manage tenant-console user access on F5 devices via RESTCONF/OpenApi
description:
  - It Handles enabling and locking B(tenant-console) user accounts on F5 devices.
  - It can either enable or lock the B(tenant-consol) user account.
  - When using the C(status) as C(enabled), it opens up the console access.
  - When using the C(status) as C(locked), it closes the console access.
  - The module uses two states, C(enabled) and C(locked), to manage the status of the expiry feature.
version_added: "1.17.0"
options:
  tenant_username:
    description:
      - Username of the B(tenant-console) to enable access. It is name of tenant created on the partition/appliance.
    type: str
    required: true
  role:
    description:
      - Role of the tenant user to be used, value of role will be always B(tenant-console)
    default: "tenant-console"
    type: str
  console_user_password:
    description:
      - Password for the B(tenant-console) user.
      - If specified, then tenant-console user password will be set with provided password value.
      - The password will be changed to the specified value during the initial configuration of the B(tenant-console) user
    type: str
  state:
    description:
      - Desired state of the B(tenant-console) user.
      - If C(enabled), provides the ability to access the B(tenant-console) user using SSH.
      - If C(locked), access to tenant-console disabled.
    default: enabled
    type: str
    choices:
      - enabled
      - locked
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Create a tenant-console user with expiry enabled
  f5os_tenant_console_enable:
    tenant_username: "example_user"
    role: "tenant-console"
    state: "enabled"

- name: Lock a tenant-console user
  f5os_tenant_console_enable:
    tenant_username: "example_user"
    role: "tenant-console"
    state: "locked"
'''

RETURN = r'''
tenant_username:
  description: The username of the tenant-console user that was configured.
  returned: always
  type: str
  sample: "example_user"
role:
  description: The role assigned to the tenant-console user.
  returned: always
  type: str
  sample: "tenant-console"
expiry_status:
  description: The expiry status of the user after the operation.
  returned: always
  type: str
  sample: "enabled"
changed:
  description: Whether any changes were made to the tenant-console configuration.
  returned: always
  type: bool
'''

import secrets
import string
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {}  # Mapping between module params and API response keys
    api_attributes = ['tenant_username', 'role', 'expiry_status']
    returnables = ['tenant_username', 'role', 'expiry_status']
    updatables = ['expiry_status']


class ApiParameters(Parameters):
    @property
    def tenant_username(self):
        return self._values['username']

    @property
    def role(self):
        return self._values['config']['role']

    @property
    def expiry_status(self):
        return self._values['config']['expiry-status']


class ModuleParameters(Parameters):

    @property
    def expiry_status(self):
        return self._values['state']


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
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.scope = "/restconf/operations"

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
            # raise F5ModuleError(f'changed options: {changed}')
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
        changed = False
        result = dict()
        state = self.want.state

        if state == "enabled":
            changed = self.present()
        elif state == "locked":
            changed = self.locked()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()
        return False

    def locked(self):
        if self.exists():
            return self.update()
        return False

    def exists(self):
        uri = f"/openconfig-system:system/aaa/authentication/f5-system-aaa:users/f5-system-aaa:user={self.want.tenant_username}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        uri = "/openconfig-system:system/aaa"
        params = self.changes.api_params()
        payload = {
            "openconfig-system:aaa": {
                "authentication": {
                    "f5-system-aaa:users": {
                        "f5-system-aaa:user": {
                            "f5-system-aaa:username": self.want.tenant_username,
                            "f5-system-aaa:config": {
                                "f5-system-aaa:expiry-status": self.want.state,
                                "f5-system-aaa:role": self.want.role
                            }
                        }
                    }
                }
            }
        }
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 204]:
            raise F5ModuleError(response['contents'])
        if self.want.console_user_password is not None and self.want.state == "enabled":
            self.update_tenant_console_user_password()
        return True

    def update_tenant_console_user_password(self):
        uri = f"/openconfig-system:system/aaa/authentication/f5-system-aaa:users/f5-system-aaa:user={self.want.tenant_username}/f5-system-aaa:config/f5-system-aaa:set-password"  # noqa E501
        payload = {
            "f5-system-aaa:password": self.want.console_user_password
        }
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 204]:
            raise F5ModuleError(response['contents'])
        time.sleep(10)
        # uri = f"/system/aaa/authentication/users/user={self.want.tenant_username}/config/change-password"
        # payload = {
        #     "old-password": "TempPassword@123",
        #     "new-password": self.want.console_user_password,
        #     "confirm-password": self.want.console_user_password
        # }
        # self.client.plugin.set_option("remote_user", self.want.tenant_username)
        # self.client.plugin.set_option("password", "TempPassword@123")
        # self.client.plugin.set_auth(('f5oscli', 'TempPassword@123'))
        # response = self.client.post(uri, data=dict(payload), scope=self.scope, headers={'force_basic_auth': True})
        # if response['code'] not in [200, 201, 204]:
        #     raise F5ModuleError(response['contents'])
        return True

    def generate_password(self, length=12):
        # Define character sets
        letters = string.ascii_letters
        digits = string.digits
        special_chars = string.punctuation
        alphabet = letters + digits + special_chars
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        return password

    def should_update(self):
        result = self._update_changed_options()
        result = True
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

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "/openconfig-system:system/aaa"
        payload = {
            "openconfig-system:aaa": {
                "authentication": {
                    "f5-system-aaa:users": {
                        "f5-system-aaa:user": {
                            "f5-system-aaa:username": self.want.tenant_username,
                            "f5-system-aaa:config": {
                                "f5-system-aaa:expiry-status": self.want.state,
                                "f5-system-aaa:role": self.want.role
                            }
                        }
                    }
                }
            }
        }
        if 'expiry_status' in params:
            response = self.client.patch(uri, data=payload)
            if response['code'] not in [200, 201, 204]:
                raise F5ModuleError(response['contents'])
        if self.want.console_user_password is not None and self.want.state == "enabled":
            self.update_tenant_console_user_password()
        return True

    # def remove(self):
    #     """Remove the tenant-console user."""
    #     if self.module.check_mode:
    #         return True
    #     uri = f"/openconfig-system:system/aaa/authentication/f5-system-aaa:users/f5-system-aaa:user={self.want.tenant_username}"
    #     response = self.client.delete(uri)
    #     if response['code'] not in [200, 204, 404]:
    #         raise F5ModuleError(response['contents'])
    #     return True

    def read_current_from_device(self):
        uri = f"/openconfig-system:system/aaa/authentication/f5-system-aaa:users/f5-system-aaa:user={self.want.tenant_username}"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents']['f5-system-aaa:user'][0])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            tenant_username=dict(type="str", required=True),
            role=dict(type="str", default='tenant-console'),
            console_user_password=dict(type='str', no_log=True),
            state=dict(
                default='enabled',
                choices=['enabled', 'locked']
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
