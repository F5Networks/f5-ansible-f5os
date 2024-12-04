#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_primarykey
short_description: Manage F5OS Devices Primary-key Setting.
description:
  - Manage Setting system primary-key using C(passphrase) and C(salt) on F5OS Devices.
version_added: "1.11.0"
options:
  passphrase:
    description:
      - Specifies Passphrase for generating primary key.
    required: True
    type: str
  salt:
    description:
      - Specifies Salt for generating primary key.
    required: True
    type: str
  force_update:
    description:
        - Force update the primary key on F5OS Device.
    type: bool
    default: False
    version_added: "1.13.0"
  state:
    description:
      - Primary key on F5OS Device state.
      - If C(present), Creates/Set the Primary key on F5OS Device.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
    - This module does not support deleting the primary key.
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Setting Primary Key on F5OS Device
  f5os_primarykey:
    passphrase: "test-passphrase"
    salt: "test-salt"
    state: present

- name: Update Primary Key on F5OS Device
  f5os_primarykey:
    passphrase: "test-passphrase"
    salt: "test-salt"
    state: present
    force_update: true
'''

RETURN = r'''
passphrase:
  description: Specifies Passphrase for generating primary key.
  returned: changed
  type: str
  sample: "test-passphrase"
salt:
  description: Specifies Salt for generating primary key.
  returned: changed
  type: str
  sample: "test-salt"
'''

import datetime
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
    api_map = {}

    api_attributes = [
        'passphrase',
        'salt'
    ]
    returnables = [
        'passphrase',
        'salt'
    ]
    updatables = returnables


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def passphrase(self):
        result = self._values['passphrase']
        if result is None:
            return None
        return result

    @property
    def salt(self):
        result = self._values['salt']
        if result is None:
            return None
        return result


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
        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()
        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        # send_teem(self.client, start)
        return result

    def present(self):
        if not self.exists() or self.want.force_update:
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
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        pass
        # if self.module.check_mode:  # pragma: no cover
        #     return True
        # self.remove_from_device()
        # # if self.exists():
        # #     raise F5ModuleError("Failed to delete the resource.")
        # return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        if self.want.passphrase is None and self.want.salt is None:
            return False
        response = self.client.get("/openconfig-system:system/aaa/f5-primary-key:primary-key")
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if 'state' in response['contents']['f5-primary-key:primary-key']:
            if response['contents']['f5-primary-key:primary-key']['state']['status'].find("COMPLETE") != -1:
                return True
        return False

    def create_on_device(self):
        params = self.changes.api_params()
        # we use name parameter separately in UsableChanges
        uri = "/openconfig-system:system/aaa/f5-primary-key:primary-key/f5-primary-key:set"
        payload = {
            "f5-primary-key:passphrase": params['passphrase'],
            "f5-primary-key:confirm-passphrase": params['passphrase'],
            "f5-primary-key:salt": params['salt'],
            "f5-primary-key:confirm-salt": params['salt']
        }
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        time.sleep(60)
        return True

    def remove_from_device(self):
        uri = "/openconfig-system:system/aaa/f5-primary-key:primary-key"
        response = self.client.delete(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            passphrase=dict(type='str', no_log=True, required=True),
            salt=dict(type='str', no_log=True, required=True),
            force_update=dict(type='bool', default=False),
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
