#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_config_backup
short_description: Manage F5OS config backups.
description:
  - Create, remove, and import F5OS system backups.
version_added: "1.2.0"
options:
  name:
    description:
      - Name of the config backup file.
    type: str
    required: True
  remote_host:
    description:
      - The hostname or IP address of the remote server used for storing the config backup file.
      - Make the server accessible using the specified C(protocol).
    type: str
  remote_port:
    description:
      - The port on the remote host to which you want to connect.
      - If the port is not provided, a default port for the selected C(protocol) is used.
    type: int
  protocol:
    description:
      - Protocol for config backup file transfer.
      - Configuring SFTP or SCP might require adding the target device to known hosts on the F5OS device,
        otherwise there is a chance transfer will fail due to connection error.
    type: str
    default: https
    choices:
      - https
      - scp
      - sftp
  remote_user:
    description:
      - User name for the remote server used for exporting the created config backup file.
    type: str
  remote_password:
    description:
      - User password for the remote server used for exporting the created config backup file.
    type: str
  remote_path:
    description:
      - The path on the remote server used for uploading the created config backup file.
    type: path
  timeout:
    description:
      - The number of seconds to wait for config backup file import to finish.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  force:
    description:
      - If C(true), then the backup file is overridden (if it exists).
      - Use this option to overwrite config backup files that exist on the device.
    type: bool
    default: false
  state:
    description:
      - If C(present), this option creates a config backup file and uploads it to the specified remote host.
      - If C(absent), this option deletes the config backup on the device (if it exists).
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create backup config and import it to remote server
  f5os_config_backup:
    name: foo
    remote_host: builds.mydomain.com
    remote_path: /uploads/upload.php
    timeout: 300
    state: present

- name: Recreate existing backup file and upload it to remote server
  f5os_config_backup:
    name: foo
    remote_host: builds.mydomain.com
    remote_path: /uploads/upload.php
    timeout: 300
    force: true
    state: present

- name: Remove backup file
  f5os_config_backup:
    name: foo
    state: absent
'''
RETURN = r'''
remote_host:
  description: The hostname or IP address of the remote server.
  returned: changed
  type: str
  example: foo.bar.baz.net
remote_port:
  description: The port on the remote host to which you want to connect.
  returned: changed
  type: int
  example: 443
remote_path:
  description: The path on the remote server used for uploading the config backup file.
  returned: changed
  type: str
  example: /upload/upload.php
message:
  description: Informative message of the file backup status.
  returned: changed
  type: dict
  sample: Backup success
'''

import datetime
import time
from ipaddress import ip_interface

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
        'remote-host': 'remote_host',
        'remote-port': 'remote_port',
        'remote-file': 'remote_path',
        'local-file': 'local_path',
        'username': 'remote_user',
        'password': 'remote_password',
    }
    api_attributes = [
        'protocol',
        'remote-host',
        'remote-port',
        'remote-file',
        'local-file',
        'username',
        'password',
    ]

    returnables = [
        'protocol',
        'remote_host',
        'remote_port',
        'remote_path',
        'local_path',
        'image_name',
        'remote_user',
        'remote_password',
        'message',
    ]

    updatables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def timeout(self):
        divisor = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / divisor

        return delay, divisor

    @property
    def remote_host(self):
        try:
            addr = ip_interface(u'{0}'.format(self._values['remote_host']))
            return str(addr.ip)
        except ValueError:
            # Assume hostname was passed in.
            return self._values['remote_host']

    @property
    def local_path(self):
        return f"configs/{self._values['name']}"


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


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.operation_id = None

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
        if self.exists() and not self.want.force:
            return False
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

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
        self.create_backup()
        self.export_file()
        self.is_export_complete()
        return True

    def exists(self):
        uri = "/f5-utils-file-transfer:file/list"
        payload = {
            "f5-utils-file-transfer:path": "configs"
        }

        response = self.client.post(uri, data=payload)

        if response['code'] == 204:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        for item in response['contents']['f5-utils-file-transfer:output']['entries']:
            if item['name'] == self.want.name:
                return True

        return False

    def create_backup(self):
        uri = "/openconfig-system:system/f5-database:database/f5-database:config-backup"
        payload = {
            "f5-database:name": self.want.name
        }
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to create backup: {self.want.name}, system returned {response['contents']}")
        return True

    def export_file(self):
        params = self.changes.api_params()
        uri = "/f5-utils-file-transfer:file/export"
        params['insecure'] = ""
        payload = dict(input=[params])
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to export backup file: {self.want.name}")
        self.operation_id = response['contents']['f5-utils-file-transfer:output'].get('operation-id')
        return True

    def is_export_complete(self):
        delay, period = self.want.timeout
        for x in range(0, period):
            if self.is_still_uploading():
                time.sleep(delay)
                continue
            self.changes.update({"message": f"Config {self.want.name} backup and upload successful."})
            return True
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def is_still_uploading(self):
        uri = "/f5-utils-file-transfer:file/transfer-operations/transfer-operation"
        response = self.client.get(uri)
        if response['code'] == 204:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        for item in response['contents']['f5-utils-file-transfer:transfer-operation']:
            if item.get('operation-id') is not None and item.get('operation-id') == self.operation_id:
                status = item['status'].strip()
                if status == 'Completed':
                    return False
                elif status.startswith('In Progress') or status.startswith('File Transfer Initiated'):
                    return True
                else:
                    raise F5ModuleError(f"File export failed with the following result: {status}")
        raise F5ModuleError("File export job not has not started, check device logs for more information.")

    def remove_from_device(self):
        uri = "/f5-utils-file-transfer:file/delete"
        payload = {"f5-utils-file-transfer:file-name": self.want.local_path}
        response = self.client.post(uri, data=payload)
        if response['code'] in [200, 201, 202, 204]:
            if response['contents']['f5-utils-file-transfer:output']['result'] != 'Deleting the file':
                raise F5ModuleError(
                    f"Operation failed with: {response['contents']['f5-utils-file-transfer:output']['result']}"
                )
            return True
        raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            remote_host=dict(),
            remote_user=dict(),
            remote_port=dict(type='int'),
            remote_password=dict(no_log=True),
            remote_path=dict(type='path'),
            protocol=dict(
                default='https',
                choices=['https', 'scp', 'sftp']
            ),
            force=dict(
                default='no',
                type='bool'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['remote_host', 'remote_path']],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
