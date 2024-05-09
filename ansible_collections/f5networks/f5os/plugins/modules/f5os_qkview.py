#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_qkview
short_description: Manage Generation of qkview file
description:
  - Generate qkview file.
version_added: "1.0.0"
options:
  filename:
    description:
      - Name of the File.
    type: str
    required: True
  timeout:
    description:
      - Timeout value in seconds.
    type: int
    default: 0
  max_file_size:
    description:
      - Maximum File Size in Megabytes.
      - This parameter value should lie between 2-1000.
    type: int
    default: 500
  max_core_size:
    description:
      - Maximum Core Size in Megabytes.
      - This parameter value should lie between 2-1000.
    type: int
    default: 25
  exclude_cores:
    description:
      - Specifies whether to exclude cores or not.
    type: bool
    default: false
  state:
    description:
      - If C(present), this option creates qkview file on specified remote host.
      - If C(absent), this option deletes qkview file on the device (if it exists).
    type: str
    choices:
      - present
      - absent
    default: present


author:
  - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''
- name: Generate qkview file on F5OS device
  f5os_qkview:
    file_name: test
    timeout: 10
    max_file_size: 500
    max_core_size: 25
    exclude_cores: true
    state: present
'''
RETURN = r'''

filename:
  description: file name of the qkview file generated.
  returned: changed
  type: str
  sample: test.tar
max_file_size:
  description: Maximum File Size in Megabytes.
  returned: changed
  type: int
  sample: 500
max_core_size:
  description: Maximum Core Size in Megabytes.
  returned: changed
  type: int
  sample: 30
exclude_cores:
  description: Specifies whether cores are excluded or not.
  returned: changed
  type: bool
  sample: false
timeout:
  description: Timeout value in seconds.
  returned: changed
  type: int
  sample: 30


'''


import datetime

import json
import time
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
        'max_file_size': 'maxfilesize',
        'max_core_size': 'maxcoresize',
        'exclude_cores': 'exclude-cores'
    }

    api_attributes = [
        'filename',
        'timeout',
        'maxfilesize',
        'maxcoresize',
        'exclude-cores'
    ]

    returnables = [
        'filename',
        'timeout',
        'max_file_size',
        'max_core_size',
        'exclude_cores'
    ]

    updatables = [
        'filename',
        'timeout',
        'max_file_size',
        'max_core_size',
        'exclude_cores'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):

    def _validate_max_size(self, size, param):

        if 2 > size or size > 1000:
            raise F5ModuleError(
                "Valid " + param + " must be in range 2 - 1000."
            )

    @property
    def max_core_size(self):
        if self._values['maxcoresize'] is None:
            return 25
        self._validate_max_size(self._values['maxcoresize'], "max_core_size")
        return self._values['maxcoresize']

    @property
    def max_file_size(self):
        if self._values['maxfilesize'] is None:
            return 500

        self._validate_max_size(self._values['maxfilesize'], "max_file_size")
        return self._values['maxfilesize']

    @property
    def exclude_cores(self):
        if self._values['exclude-cores'] is None:
            return False
        return self._values['exclude-cores']

    @property
    def timeout(self):
        if self._values['timeout'] is None:
            return 0
        return self._values['timeout']


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
    returnables = [
        'filename',
        'timeout',
        'max_file_size',
        'max_core_size',
        'exclude_cores'
    ]


class Difference(object):
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
        except AttributeError:  # pragma: no cover
            return attr1


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params, client=self.client)
        self.changes = UsableChanges()
        self.have = ApiParameters()

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
        return self.create()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        uri = "/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/qkview/capture"
        response = self.client.post(uri, data=params)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.check_status()
        return True

    def check_status(self):
        uri = "/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/qkview/status"
        statuses = ["collating", "collecting"]
        messages = ["Collecting Data", "Collating data"]
        while True:
            response = self.client.post(uri)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])
            res = json.loads(response['contents']['f5-system-diagnostics-qkview:output']['result'])
            if res["Percent"] < 100 and res["Status"] in statuses and res["Message"] in messages:
                time.sleep(15)
                continue
            elif res["Percent"] == 100 and res["Status"] == "complete" and res["Message"] == "Completed collection.":
                return True
            raise F5ModuleError(response['contents'])

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def update(self):
        pass

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def remove_from_device(self):
        uri = "/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/qkview/delete"
        response = self.client.post(uri, data={"filename": self.read_filename_from_device()})

        if response['code'] not in [200, 201, 202] or "Error deleting" in response['contents']['f5-system-diagnostics-qkview:output']['result']:
            raise F5ModuleError(response['contents'])

        return True

    def exists(self):
        uri = "/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/qkview/list"
        response = self.client.post(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        res = json.loads(response['contents']['f5-system-diagnostics-qkview:output']['result'])
        if res['Qkviews'] is None:
            return False
        for item in res['Qkviews']:
            filename = self.want.filename
            if item['Filename'].split(':')[1].endswith('.tar'):
                filename = filename + '.tar'
            if filename == item['Filename'].split(':')[1]:
                return True
        return False

    def read_filename_from_device(self):
        uri = "/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/qkview/list"
        response = self.client.post(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        res = json.loads(response['contents']['f5-system-diagnostics-qkview:output']['result'])
        for item in res['Qkviews']:
            filename = self.want.filename
            if not filename.endswith('.tar'):
                filename = filename + '.tar'

            existingFilename = item['Filename'].split(':')[1]
            if not existingFilename.endswith('.tar'):
                existingFilename = existingFilename + '.tar'

            if filename == existingFilename:
                return item['Filename']


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            filename=dict(
                required=True,
            ),
            timeout=dict(
                type="int",
                default=0
            ),
            max_file_size=dict(
                type="int",
                default=500
            ),
            max_core_size=dict(
                type="int",
                default=25
            ),
            exclude_cores=dict(
                type="bool",
                default=False
            ),
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
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
