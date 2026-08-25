#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_config_restore
short_description: Restore F5OS configuration from a backup file
description:
  - Restore the F5OS configuration database from a previously created backup file.
  - The backup file can already exist on the device, or it can be imported from a remote server
    before restoring.
  - When remote server parameters are provided and the backup file does not exist on the device,
    the module will first import the file from the remote server and then perform the restore.
  - This module is supported on rSeries platforms and VELOS partitions.
  - It is not supported on VELOS controllers.
version_added: "1.23.0"
options:
  name:
    description:
      - Name of the config backup file to restore.
      - The file must exist in the C(configs/) directory on the device, or remote server
        parameters must be provided to import it first.
    type: str
    required: true
  remote_host:
    description:
      - The hostname or IP address of the remote server from which to import the backup file.
      - Required when the backup file does not exist on the device.
    type: str
  remote_port:
    description:
      - The port on the remote host to which you want to connect.
      - If not provided, a default port for the selected C(protocol) is used.
    type: int
  protocol:
    description:
      - Protocol for importing the backup file from a remote server.
      - Configuring SFTP or SCP might require adding the target device to known hosts on the F5OS device.
    type: str
    default: https
    choices:
      - https
      - scp
      - sftp
  remote_user:
    description:
      - User name for the remote server used for importing the backup file.
      - Required when C(remote_host) is specified.
    type: str
  remote_password:
    description:
      - Password for the remote server used for importing the backup file.
      - Required when C(remote_host) is specified.
    type: str
  remote_path:
    description:
      - The path on the remote server where the backup file is located.
      - Required when C(remote_host) is specified.
    type: path
  timeout:
    description:
      - The number of seconds to wait for the backup file import to finish.
      - The accepted value range is between C(150) and C(3600) seconds.
      - Only relevant when importing from a remote server.
    type: int
    default: 300
  state:
    description:
      - The desired state. Only C(present) is supported.
      - When C(present), restores the configuration from the specified backup file.
    type: str
    choices:
      - present
    default: present
author:
  - F5 Networks (@f5networks)
notes:
  - This module is supported on F5OS rSeries platforms and VELOS partitions.
  - It is not supported on VELOS controllers.
  - Restoring a configuration may cause service disruption. Ensure you understand the impact
    before running this module in a production environment.
  - The restore operation is initiated via the F5OS API and the module reports success when the
    API accepts the request. The module does not poll for restore completion as F5OS does not
    provide a dedicated status endpoint for the restore RPC.
  - When importing from a remote server, TLS certificate verification is not performed
    (consistent with the F5OS file transfer API behavior and the C(f5os_config_backup) module).
    Ensure the remote server is trusted before importing backup files.
  - The primary key configured on the device must match the one used when the backup was created,
    otherwise encrypted values in the configuration will fail to decrypt. The primary key is
    not passed via this module and must be configured on the device prior to restore.
'''

EXAMPLES = r'''
- name: Restore configuration from a local backup file
  f5networks.f5os.f5os_config_restore:
    name: "my-backup-2024-01-15"
    state: present

- name: Import backup from remote server and restore
  f5networks.f5os.f5os_config_restore:
    name: "my-backup-2024-01-15"
    remote_host: "10.1.1.100"
    remote_user: "admin"
    remote_password: "secret"
    remote_path: "/backups/my-backup-2024-01-15"
    protocol: scp
    timeout: 600
    state: present
'''

RETURN = r'''
name:
  description: The name of the backup file used for the restore.
  returned: changed
  type: str
  sample: "my-backup-2024-01-15"
message:
  description: Informative message about the restore operation status.
  returned: changed
  type: str
  sample: "Config restore from my-backup-2024-01-15 successful."
remote_host:
  description: The hostname or IP address of the remote server.
  returned: changed
  type: str
  sample: "10.1.1.100"
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

_MAX_TRANSIENT_ERRORS = 3


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
        'name',
        'protocol',
        'remote_host',
        'remote_port',
        'remote_path',
        'local_path',
        'remote_user',
        'remote_password',
        'message',
    ]

    updatables = []


class ModuleParameters(Parameters):
    @property
    def timeout(self):
        max_polls = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / max_polls

        return delay, max_polls

    @property
    def remote_host(self):
        if self._values['remote_host'] is None:
            return None
        try:
            addr = ip_interface(u'{0}'.format(self._values['remote_host']))
            return str(addr.ip)
        except ValueError:
            # Assume hostname was passed in.
            return self._values['remote_host']

    @property
    def name(self):
        name = self._values['name']
        if name:
            name = name.strip()
        if not name or '/' in name or '..' in name:
            raise F5ModuleError(
                "Backup file name must not be empty or contain '/' or '..' path separators."
            )
        return name

    @property
    def local_path(self):
        return f"configs/{self.name}"


class Changes(Parameters):
    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    returnables = [
        'name',
        'protocol',
        'remote_host',
        'remote_port',
        'remote_path',
        'local_path',
        'message',
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.operation_id = None
        self._transient_error_count = 0

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
        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if not self.backup_exists():
            if self.want.remote_host is None:
                raise F5ModuleError(
                    f"Backup file '{self.want.name}' does not exist on the device. "
                    f"Provide remote server parameters to import it first."
                )
            self.import_file()
            self.wait_for_import()
        self.restore_config()
        return True

    def backup_exists(self):
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

    def import_file(self):
        params = self.changes.api_params()
        uri = "/f5-utils-file-transfer:file/import"
        params['insecure'] = ""
        payload = dict(input=[params])
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(
                f"Failed to import backup file: {self.want.name}"
            )
        self.operation_id = response['contents']['f5-utils-file-transfer:output'].get('operation-id')
        return True

    def wait_for_import(self):
        delay, max_polls = self.want.timeout
        for x in range(0, max_polls):
            if self._is_still_importing():
                time.sleep(delay)
                continue
            return True
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _is_still_importing(self):
        uri = "/f5-utils-file-transfer:file/transfer-operations/transfer-operation"
        response = self.client.get(uri)
        if response['code'] == 204:
            # No transfer operations listed yet — treat as still importing
            return True
        if response['code'] not in [200, 201, 202]:
            self._transient_error_count += 1
            if self._transient_error_count >= _MAX_TRANSIENT_ERRORS:
                raise F5ModuleError(response['contents'])
            return True
        self._transient_error_count = 0
        for item in response['contents']['f5-utils-file-transfer:transfer-operation']:
            if item.get('operation-id') is not None and item.get('operation-id') == self.operation_id:
                status = item['status'].strip()
                if status == 'Completed':
                    return False
                elif any(status.lower().startswith(err) for err in
                         ['failed', 'aborted', "couldn't connect",
                          'connection refused', 'authentication failed']):
                    raise F5ModuleError(
                        f"File import failed with the following result: {status}"
                    )
                else:
                    return True
        # Job not yet visible in transfer list — treat as still importing
        return True

    def restore_config(self):
        uri = "/openconfig-system:system/f5-database:database/f5-database:config-restore"
        payload = {
            "f5-database:name": self.want.name
        }
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(
                f"Failed to restore config from backup: {self.want.name}, "
                f"system returned {response['contents']}"
            )
        self.changes.update({
            "message": f"Config restore from {self.want.name} successful."
        })
        return True


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
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['present'],
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_by = {
            'remote_host': ['remote_user', 'remote_password', 'remote_path'],
        }


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_by=spec.required_by,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
