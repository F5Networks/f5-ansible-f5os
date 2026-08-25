#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_login_policy
short_description: Manage login policy settings on F5OS devices
description:
  - Manage login policy settings on F5OS 2.0.0 and later platforms.
  - Controls the admin role limit, RESTCONF maximum session limit, and SSH maximum session limit.
  - This module requires F5OS 2.0.0 or later. On earlier versions a clear error is raised.
version_added: "1.23.0"
options:
  admin_role_limit:
    description:
      - When C(true), limits the number of concurrent admin role sessions.
    type: bool
  restconf_max_session_limit:
    description:
      - Maximum number of concurrent RESTCONF sessions permitted.
    type: int
  ssh_max_session_limit:
    description:
      - Maximum number of concurrent SSH sessions permitted.
    type: int
  state:
    description:
      - If C(present), creates or updates the login policy configuration.
      - If C(absent), resets the login policy configuration to defaults by deleting it.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - This module requires F5OS 2.0.0 or later. Attempting to use it on earlier versions
    will result in a clear error message.
author:
  - F5 Networks (@F5Networks)
'''

EXAMPLES = r'''
- name: Set login policy
  f5os_login_policy:
    admin_role_limit: true
    restconf_max_session_limit: 10
    ssh_max_session_limit: 5

- name: Update SSH session limit only
  f5os_login_policy:
    ssh_max_session_limit: 8

- name: Reset login policy to defaults
  f5os_login_policy:
    state: absent
'''

RETURN = r'''
admin_role_limit:
  description: Whether the admin role session limit is enabled.
  returned: changed
  type: bool
  sample: true
restconf_max_session_limit:
  description: Maximum number of concurrent RESTCONF sessions permitted.
  returned: changed
  type: int
  sample: 10
ssh_max_session_limit:
  description: Maximum number of concurrent SSH sessions permitted.
  returned: changed
  type: int
  sample: 5
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

LOGIN_POLICY_URI = '/openconfig-system:system/aaa/f5-openconfig-aaa-login-policy:login-policy/config'
MIN_VERSION = (2, 0, 0)


def _parse_version(version_str):
    # robust parsing that accepts '2.0', '2.0.0', and '2.0.0-9817'
    m = None
    try:
        import re
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(version_str or ''))
    except Exception:
        m = None
    if m:
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) is not None else 0
        return (major, minor, patch)
    return (0, 0, 0)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'admin-role-limit': 'admin_role_limit',
        'restconf-max-session-limit': 'restconf_max_session_limit',
        'ssh-max-session-limit': 'ssh_max_session_limit',
    }

    api_attributes = [
        'admin_role_limit',
        'restconf_max_session_limit',
        'ssh_max_session_limit',
    ]

    returnables = [
        'admin_role_limit',
        'restconf_max_session_limit',
        'ssh_max_session_limit',
    ]

    updatables = [
        'admin_role_limit',
        'restconf_max_session_limit',
        'ssh_max_session_limit',
    ]


class ApiParameters(Parameters):
    @property
    def admin_role_limit(self):
        return self._values.get('admin_role_limit')

    @property
    def restconf_max_session_limit(self):
        return self._values.get('restconf_max_session_limit')

    @property
    def ssh_max_session_limit(self):
        return self._values.get('ssh_max_session_limit')


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

    def _check_version(self):
        # determine device software version; if unavailable, raise a clear error
        try:
            version_str = self.client.software_version or ''
        except Exception:
            version_str = ''
        if not version_str:
            raise F5ModuleError(
                'f5os_login_policy requires F5OS 2.0.0 or later, but the device software version '
                'could not be determined. Ensure the device reports its software_version or run this '
                'module on an F5OS >= v2.0.0 device.'
            )
        version = _parse_version(version_str)
        if version < MIN_VERSION:
            raise F5ModuleError(
                'f5os_login_policy requires F5OS 2.0.0 or later. Detected software version: {0}.'.format(version_str)
            )

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
        self._check_version()
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        self.have = self.read_current_from_device()
        if not self._update_changed_options():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def absent(self):
        self.have = self.read_current_from_device()
        if self.have.admin_role_limit is None and \
                self.have.restconf_max_session_limit is None and \
                self.have.ssh_max_session_limit is None:
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        return True

    def update_on_device(self):
        # Merge current device state with requested changes to avoid overwriting
        # untouched fields when performing a PUT on the config container
        params = self.changes.to_return()
        conf_map = {
            'admin_role_limit': 'admin-role-limit',
            'restconf_max_session_limit': 'restconf-max-session-limit',
            'ssh_max_session_limit': 'ssh-max-session-limit',
        }
        # start with current values from device
        config = {}
        for attr, api_key in conf_map.items():
            try:
                val = getattr(self.have, attr)
            except Exception:
                val = None
            if val is not None:
                config[api_key] = val
        # overlay requested changes
        for attr, api_key in conf_map.items():
            if attr in params and params[attr] is not None:
                config[api_key] = params[attr]
        payload = {'f5-openconfig-aaa-login-policy:config': config}
        response = self.client.put(LOGIN_POLICY_URI, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        response = self.client.delete(LOGIN_POLICY_URI)
        if response['code'] not in [200, 201, 202, 204, 404]:
            raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        response = self.client.get(LOGIN_POLICY_URI)
        if response['code'] == 404:
            return ApiParameters(params={})
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        raw = response['contents'].get('f5-openconfig-aaa-login-policy:config', {})
        params = {
            'admin_role_limit': raw.get('admin-role-limit'),
            'restconf_max_session_limit': raw.get('restconf-max-session-limit'),
            'ssh_max_session_limit': raw.get('ssh-max-session-limit'),
        }
        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            admin_role_limit=dict(type='bool'),
            restconf_max_session_limit=dict(type='int'),
            ssh_max_session_limit=dict(type='int'),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        # When state == present, require at least one of these parameters
        self.required_if = [
            ['state', 'present', ('admin_role_limit', 'restconf_max_session_limit', 'ssh_max_session_limit'), True],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
