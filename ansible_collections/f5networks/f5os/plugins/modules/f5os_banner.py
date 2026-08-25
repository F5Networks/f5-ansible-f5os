#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_banner
short_description: Manage login banner and Message of the Day (MoTD) on F5OS devices
description:
  - Manage the login banner and Message of the Day (MoTD) banner on F5OS based systems.
  - The login banner is displayed before user authentication.
  - The MoTD banner is displayed after successful login.
version_added: "1.23.0"
options:
  login_banner:
    description:
      - The login banner text to display before user authentication.
      - When C(state) is C(present), at least one of C(login_banner) or C(motd_banner) must be provided.
      - When C(state) is C(absent), the value is ignored; only the presence of this parameter
        determines whether the login banner is targeted for removal. If not specified, the login
        banner will not be removed.
    type: str
  motd_banner:
    description:
      - The Message of the Day banner text to display after successful login.
      - When C(state) is C(present), at least one of C(login_banner) or C(motd_banner) must be provided.
      - When C(state) is C(absent), the value is ignored; only the presence of this parameter
        determines whether the MoTD banner is targeted for removal. If not specified, the MoTD
        banner will not be removed.
    type: str
  state:
    description:
      - The banner configuration state.
      - If C(present), creates or updates the specified banner(s).
      - If C(absent), removes the specified banner(s). If neither C(login_banner) nor C(motd_banner) is
        specified, both banners will be removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - F5 Networks (@F5Networks)
'''

EXAMPLES = r'''
- name: Set login banner
  f5os_banner:
    login_banner: "Unauthorized access is prohibited."

- name: Set MoTD banner
  f5os_banner:
    motd_banner: "Welcome to the F5OS platform."

- name: Set both login banner and MoTD
  f5os_banner:
    login_banner: "Unauthorized access is prohibited."
    motd_banner: "Welcome to the F5OS platform."

- name: Remove login banner
  # Specifying the parameter targets that banner for removal; the value is ignored.
  f5os_banner:
    login_banner: "any value"
    state: absent

- name: Remove both banners
  f5os_banner:
    state: absent
'''

RETURN = r'''
login_banner:
  description: The login banner text.
  returned: changed
  type: str
  sample: "Unauthorized access is prohibited."
motd_banner:
  description: The Message of the Day banner text.
  returned: changed
  type: str
  sample: "Welcome to the F5OS platform."
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
    api_map = {}

    api_attributes = [
        'login_banner',
        'motd_banner',
    ]

    returnables = [
        'login_banner',
        'motd_banner',
    ]

    updatables = [
        'login_banner',
        'motd_banner',
    ]


class ApiParameters(Parameters):
    @property
    def login_banner(self):
        return self._values.get('login_banner')

    @property
    def motd_banner(self):
        return self._values.get('motd_banner')


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
        if self.want.login_banner is not None and self.want.login_banner == '':
            raise F5ModuleError(
                "login_banner cannot be an empty string with state 'present'. "
                "Use state 'absent' to remove a banner."
            )
        if self.want.motd_banner is not None and self.want.motd_banner == '':
            raise F5ModuleError(
                "motd_banner cannot be an empty string with state 'present'. "
                "Use state 'absent' to remove a banner."
            )
        self.have = self.read_current_from_device()
        if not self._update_changed_options():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def absent(self):
        self.have = self.read_current_from_device()
        # Determine which banners to remove
        both_unset = self.want.login_banner is None and self.want.motd_banner is None
        remove_login = self.want.login_banner is not None or both_unset
        remove_motd = self.want.motd_banner is not None or both_unset

        changed = False
        changes = {}

        if remove_login and self.have.login_banner:
            changed = True
            changes['login_banner'] = ''
        if remove_motd and self.have.motd_banner:
            changed = True
            changes['motd_banner'] = ''

        if not changed:
            return False

        self.changes = UsableChanges(params=changes)

        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device(
            remove_login and bool(self.have.login_banner),
            remove_motd and bool(self.have.motd_banner),
        )
        return True

    def update_on_device(self):
        params = self.changes.to_return()
        if 'login_banner' in params:
            uri = "/openconfig-system:system/config/login-banner"
            payload = {"openconfig-system:login-banner": params['login_banner']}
            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

        if 'motd_banner' in params:
            uri = "/openconfig-system:system/config/motd-banner"
            payload = {"openconfig-system:motd-banner": params['motd_banner']}
            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self, remove_login, remove_motd):
        if remove_login:
            uri = "/openconfig-system:system/config/login-banner"
            response = self.client.delete(uri)
            if response['code'] not in [200, 201, 202, 204, 404]:
                raise F5ModuleError(response['contents'])

        if remove_motd:
            uri = "/openconfig-system:system/config/motd-banner"
            response = self.client.delete(uri)
            if response['code'] not in [200, 201, 202, 204, 404]:
                raise F5ModuleError(response['contents'])

        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/config"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        config = response['contents'].get('openconfig-system:config', {})
        params = {
            'login_banner': config.get('login-banner'),
            'motd_banner': config.get('motd-banner'),
        }
        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            login_banner=dict(type='str'),
            motd_banner=dict(type='str'),
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
        supports_check_mode=spec.supports_check_mode,
        required_if=[
            ['state', 'present', ['login_banner', 'motd_banner'], True],
        ],
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
