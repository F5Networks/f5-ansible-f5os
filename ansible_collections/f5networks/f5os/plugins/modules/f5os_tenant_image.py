#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_tenant_image
short_description: Manage F5OS tenant images
description:
  - Manage F5OS tenant images.
version_added: "1.0.0"
options:
  image_name:
    description:
      - Name of the tenant image.
    type: str
    required: True
  remote_host:
    description:
      - The hostname or IP address of the remote server on which the tenant image is
        stored.
      - The server must make the image accessible via the specified C(protocol).
    type: str
  remote_port:
    description:
      - The port on the remote host to which you want to connect.
      - If the port is not provided, a default port for the selected C(protocol) is used.
    type: int
  protocol:
    description:
      - Protocol for image transfer.
    type: str
    default: scp
    choices:
      - scp
      - sftp
      - https
  remote_user:
    description:
      - User name for the remote server on which the tenant image is stored.
    type: str
  remote_password:
    description:
      - Password for the user on the remote server on which the tenant image is stored.
    type: str
  remote_path:
    description:
      - The path to the tenant image on the remote server.
    type: path
  local_path:
    description:
      - The path on the F5OS where the the tenant image is to be uploaded.
    type: str
    choices:
      - "images/import"
      - "images/staging"
      - "images/tenant"
      - images
  timeout:
    description:
      - The number of seconds to wait for image import to finish.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  state:
    description:
      - The tenant image state.
      - If C(import), starts the image import task if the image does not exist.
      - If C(present), checks for the status of the import task if the image does not exist.
      - If C(absent), deletes the tenant image if it exists.
    type: str
    choices:
      - import
      - present
      - absent
    default: import
notes:
  - Repeating the same image import task immediately after the previous is not idempotent
    if the image has not finished downloading.
  - This module will not execute on VELOS controller.
author:
  - Ravinder Reddy (@chinthalapalli)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Import tenant image 'foo' onto the F5OS device
  f5os_tenant_image:
    image_name: foo
    remote_host: builds.mydomain.com
    remote_user: admin
    remote_password: secret
    remote_path: /images/
    local_path: images/tenant
    state: import

- name: Check the status of the image import onto the F5OS device
  f5os_tenant_image:
    image_name: foo
    timeout: 600
    state: present

- name: Remove tenant image 'foo'
  f5os_tenant_image:
    name: foo
    state: absent
'''
RETURN = r'''
image_name:
  description: Name of the tenant image.
  returned: changed
  type: str
  example: BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip
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
  description: The path to the tenant image on the remote server.
  returned: changed
  type: str
  example: /foo/bar/
local_path:
  description: The path on F5OS device where the tenant image will be uploaded.
  returned: changed
  type: str
  example: images/tenant
message:
  description: Informative message of the image import status.
  returned: changed
  type: dict
  sample: Import success
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
        if self._values['remote_host'] is None:
            return None
        try:
            addr = ip_interface(u'{0}'.format(self._values['remote_host']))
            return str(addr.ip)
        except ValueError:
            # Assume hostname was passed in.
            return self._values['remote_host']

    @property
    def remote_path(self):
        if self._values['remote_path'] is None:
            return None
        if not self._values['remote_path'].endswith(self._values['image_name']):
            # API seems to require server_remote_path include the image name.
            return "{0}/{1}".format(self._values['remote_path'].rstrip('/'), self._values['image_name'])

        return self._values['remote_path']


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
        'remote_host',
        'remote_port',
        'remote_path',
        'local_path',
        'image_name',
        'remote_user',
        'message',
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.image_is_valid = False

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

        if state == "import":
            changed = self.import_image()
        elif state == "present":
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

    def import_image(self):
        if self.exists() and self.image_is_valid:
            return False
        else:
            return self.create()

    def present(self):
        if self.exists():
            if self.image_is_valid:
                return False
        else:
            return self.import_status_complete()

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
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/f5-tenant-images:images/image={self.want.image_name}/status"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if response['contents']['f5-tenant-images:status'] == 'replicated' or \
                response['contents']['f5-tenant-images:status'] == 'verified':
            self.image_is_valid = True
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        uri = "/f5-utils-file-transfer:file/import"
        params['insecure'] = ""
        if params['username'] == "":
            del params['username']
        if params['password'] == "":
            del params['password']
        payload = dict(input=[params])
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to import tenant image with {response['contents']}")
        self.changes.update({"message": f"Image {self.want.image_name} import started."})
        return True

    def import_status_complete(self):
        delay, period = self.want.timeout
        for x in range(0, period):
            if self.is_still_uploading():
                time.sleep(delay)
                continue
            if not self.is_imported():
                time.sleep(delay)
                continue
            if not self.changes.message:
                self.changes.update({"message": f"Image {self.want.image_name} import successful."})
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
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        for item in response['contents']['f5-utils-file-transfer:transfer-operation']:
            if item['remote-host'] == self.want.remote_host and item['remote-file-path'] == self.want.remote_path:
                status = item['status'].strip()
                if status == 'Completed':
                    return False
                elif status.startswith('In Progress'):
                    return True
                else:
                    raise F5ModuleError(f"File upload failed with the following result: {status}")
        raise F5ModuleError("File upload job not has not started, check device logs for more information.")

    def is_imported(self):
        uri = f"/f5-tenant-images:images/image={self.want.image_name}/status"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] == 204:
            return False
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        status = response['contents']['f5-tenant-images:status']
        if 'replicated' in status or 'verified' in status:
            return True
        if 'verification-failed' in status:
            raise F5ModuleError(f"The image: {self.want.image_name} was imported, but it failed signature verification,"
                                f" remove the image and try again.")
        return False

    def remove_from_device(self):
        uri = "/f5-tenant-images:images/remove"
        payload = dict(input=[{"name": self.want.image_name}])
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to remove tenant image: {self.want.image_name} {response['contents']}")
        result = response['contents']["f5-tenant-images:output"]["result"]
        if result == "Successful.":
            return True
        raise F5ModuleError(f"Failed to remove tenant image: {self.want.image_name} {result}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            image_name=dict(required=True),
            remote_host=dict(),
            remote_port=dict(type='int'),
            remote_user=dict(),
            remote_password=dict(no_log=True),
            remote_path=dict(type='path'),
            local_path=dict(
                choices=['images/import', 'images/staging', 'images/tenant', 'images']
            ),
            protocol=dict(
                default='scp',
                choices=['scp', 'sftp', 'https']
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='import',
                choices=['import', 'present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'import', ['remote_host', 'remote_path', 'local_path']],
            ['state', 'present', ['remote_host', 'remote_path', 'local_path']],
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
