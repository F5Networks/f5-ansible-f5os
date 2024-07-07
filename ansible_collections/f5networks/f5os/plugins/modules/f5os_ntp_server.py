#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_ntp_server
short_description: Manage NTP servers on F5OS based systems
description:
  - Manage NTP servers on Velos controller and rseries platform.
version_added: 1.8.0
options:
  server:
    description:
      - Specifies the address of the NTP server.
      - It can be either an IPv4 or IPv6 or an FQDN.
    type: str
    required: True
  key_id:
    description:
      - Specifies the key ID which identifies the key used for authentication.
    type: int
  state:
    description:
      - The NTP server state.
      - If C(present), creates the specified NTP server if it does not exist, or updates the existing one.
      - If C(absent), deletes the NTP server if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Rohit Upadhyay (@rupadhyay)
'''

EXAMPLES = r'''
- name: Create an ntp server
  f5os_ntp_server:
    server: "1.2.3.4"
    key_id: 10

- name: Update an ntp server
  f5os_ntp_server:
    server: "1.2.3.4"
    key_id: 15

- name: Delete an ntp server
  f5os_ntp_server:
    server: "1.2.3.4"
    state: absent
'''

RETURN = r'''
server:
  description: Specifies the address of the NTP server.
  returned: changed
  type: str
  sample: "1.2.3.4"
key_id:
  description: Specifies the key ID which identifies the key used for authentication.
  returned: changed
  type: int
  sample: 102
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
        'server',
        'key_id',
    ]

    returnables = [
        'server',
        'key_id',
    ]

    updatables = [
        'key_id'
    ]


class ApiParameters(Parameters):
    @property
    def server(self):
        return self._values['address']

    @property
    def key_id(self):
        return self._values['config'].get('f5-openconfig-system-ntp:key-id')


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
        uri = f"/openconfig-system:system/ntp/openconfig-system:servers/server={self.want.server}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        payload = {
            'server': [
                {
                    'address': params['server'],
                    'config': {
                        'address': params['server']
                    }
                }
            ]
        }
        if params.get('key_id'):
            payload['server'][0]['config']['f5-openconfig-system-ntp:key-id'] = params['key_id']

        uri = "/openconfig-system:system/ntp/openconfig-system:servers"
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = f"/openconfig-system:system/ntp/openconfig-system:servers/server={self.want.server}"
        payload = {
            'server': [
                {
                    'address': self.want.server,
                    'config': {
                        'address': self.want.server,
                        'f5-openconfig-system-ntp:key-id': params['key_id']
                    }
                }
            ]
        }

        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        uri = f"/openconfig-system:system/ntp/openconfig-system:servers/server={self.want.server}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/openconfig-system:system/ntp/openconfig-system:servers/server={self.want.server}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        params = response['contents']['openconfig-system:server'][0]
        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            server=dict(required=True),
            key_id=dict(type='int'),
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
