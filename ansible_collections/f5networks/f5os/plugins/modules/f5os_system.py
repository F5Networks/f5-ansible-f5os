#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_system
short_description: Manage generic system settings
description:
  - Manage generic system settings
version_added: 1.10.0
options:
  hostname:
    description:
      - Specifies the system hostname
    type: str
  motd:
    description:
      - Specifies the message of the day
    type: str
  login_banner:
    description:
      - Specifies the Login Banner
    type: str
  timezone:
    description:
      - Specifies the timezone for the system per TZ database name
    type: str
  state:
    description:
      - State for the settings. Please note, this is kept for future additions and currently
      - unused as implemented settings can't be removed.
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
- name: Set system settings
  f5os_system:
    hostname: system.example.net
    motd: Todays weather is great!
    login_banner: With great power comes great responsibility
    timezone: UTC
'''

RETURN = r'''
hostname:
  description: Specifies the system hostname
  returned: changed
  type: str
  sample: system.example.net
motd:
  description: Specifies the message of the day
  returned: changed
  type: str
  sample: Todays weather is great!
login_banner:
  description: Specifies the Specifies the Login Banner
  returned: changed
  type: str
  sample: With great power comes great responsibility
timezone:
  description: Specifies the timezone for the system per TZ database name
  returned: changed
  type: str
  sample: UTC
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
        'timezone',
        'motd',
        'login_banner',
        'hostname'
    ]

    returnables = [
        'timezone',
        'motd',
        'login_banner',
        'hostname'
    ]

    updatables = [
        'timezone',
        'motd',
        'login_banner',
        'hostname'
    ]


class ApiParameters(Parameters):
    @property
    def timezone(self):
        try:
            return self._values['clock']['config']['timezone-name']
        except (TypeError, ValueError):
            return None

    @property
    def motd(self):
        try:
            return self._values['config']['motd-banner']
        except (TypeError, ValueError):
            return None

    @property
    def login_banner(self):
        try:
            return self._values['config']['login-banner']
        except (TypeError, ValueError):
            return None

    @property
    def hostname(self):
        try:
            return self._values['config']['hostname']
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
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
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
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "/openconfig-system:system"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        # not applicable for system parameters
        pass

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "/openconfig-system:system"
        payload = {
            'openconfig-system:system': {
                'config': dict()
            }
        }
        system = payload['openconfig-system:system']
        config = system['config']
        if 'hostname' in params:
            config['hostname'] = params['hostname']
        if 'timezone' in params:
            # Clock is nested
            system['clock'] = dict()
            system['clock']['config'] = dict()
            system['clock']['config']['timezone-name'] = params['timezone']
        if 'motd' in params:
            config['motd-banner'] = params['motd']
        if 'login_banner' in params:
            config['login-banner'] = params['login_banner']

        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        # not applicable for system parameters
        pass

    def read_current_from_device(self):
        uri = "/openconfig-system:system"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents']['openconfig-system:system'])

        params = response['contents']['openconfig-system:system']
        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            hostname=dict(type='str'),
            login_banner=dict(type='str'),
            motd=dict(type='str'),
            timezone=dict(type='str'),
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
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
