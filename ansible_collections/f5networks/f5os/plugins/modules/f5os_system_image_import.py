#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# https://my.f5.com/manage/s/article/K93807441

DOCUMENTATION = r'''
---
module: f5os_system_image_import
short_description: Manage F5OS System image import.
description:
  - Manage the import of system images onto F5OS devices.
version_added: "1.11.0"
options:
  remote_image_url:
    description:
      - The path/url to the system image on the remote server.
    type: str
    required: true
  remote_user:
    description:
      - Provide the remote system username where the system image is stored.
    type: str
  remote_password:
    description:
      - Provide the remote system password where the system image is stored.
    type: str
  local_path:
    description:
      - The path on the F5OS where the the system image will be imported.
    type: str
    choices:
      - "images/import"
      - "images/staging"
      - "images/tenant"
      - images
  operation_id:
    description:
      - The import operation ID of the image import task.
    type: str
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
      - If C(present), checks for the status of the import operation if the image does not exist.
      - If C(absent), deletes the system image if it exists.
    type: str
    choices:
      - import
      - present
      - absent
    default: import
notes:
  - Repeating the same image import task immediately after the previous is not idempotent
    if the image has not finished downloading.
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Import system image 'foo' onto the F5OS device
  f5os_system_image_import:
    remote_image_url: https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso
    local_path: images/staging
    state: import

- name: Check the status of the image import onto the F5OS device
  f5os_system_image_import:
    remote_image_url: https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso
    local_path: images/staging
    operation_id: IMPORT-lZsT6P7M
    timeout: 600
    state: present

- name: Remove system image 'F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso' from the F5OS device
  f5os_system_image_import:
    remote_image_url: https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso
    state: absent
'''
RETURN = r'''
remote_image_url:
  description: The path/url to the system image on the remote server.
  returned: changed
  type: str
  example: https://foo.bar.baz.net/foo/bar/F5OS-A-1.8.0-14139.R5R10.CANDIDATE.iso
operation_id:
  description: Operation ID of the image import task.
  returned: changed
  type: str
  example: IMPORT-lZsT6P7M
local_path:
  description: The path on the F5OS where the the system image will be imported.
  returned: changed
  type: str
  example: images/staging
'''

import datetime
import time
import re

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
        'remote-url': 'remote_image_url',
        'local-file': 'local_path',
        'username': 'remote_user',
        'password': 'remote_password',
        'image-name': 'image_name',
    }
    api_attributes = [
        'remote-url',
        'local-file',
        'username',
        'password',
        'image-name',
    ]

    returnables = [
        'remote_image_url',
        'local_path',
        'image_name',
        'remote_user',
        'message',
        'operation_id',
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
    def image_name(self):
        if self._values['remote_image_url'] is None:
            return None
        return self._values['remote_image_url'].split('/')[-1]

    @property
    def remote_image_url(self):
        if self._values['remote_image_url'] is None:
            return None
        return self._values['remote_image_url']


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
        'remote_image_url',
        'local_path',
        'remote_user',
        'operation_id',
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
        # if self.client.platform == 'Velos Controller':
        #     raise F5ModuleError("Target device is a VELOS controller, aborting.")
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
        if self.exists():
            return False
        else:
            return self.create()

    def present(self):
        if self.exists():
            if self.image_is_valid:
                return False
            return True

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
        uri = "/f5-utils-file-transfer:file/list"
        self.image_exist = False
        if self.want.operation_id and self.want.state == 'import':
            raise F5ModuleError("when operation_id is provided state must be not import.")
        if self.want.operation_id and self.want.state == 'present':
            return self.import_status_complete()
        payload = {
            "f5-utils-file-transfer:path": "images/staging"
        }
        response = self.client.post(uri, data=payload)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        for item in response['contents']['f5-utils-file-transfer:output']['entries']:
            if item['name'] == self.want.image_name:
                self.image_exist = True
                self.image_is_valid = True
                break
        return self.image_exist

    def create_on_device(self):
        params = self.changes.api_params()
        uri = "/f5-utils-file-transfer:file/import"
        params['insecure'] = ""
        if 'username' in params and params['username'] == "":
            del params['username']
        if 'password' in params and params['password'] == "":
            del params['password']
        del params['image-name']
        payload = dict(input=[params])
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to import system image with {response['contents']}")
        if 'f5-utils-file-transfer:output' in response['contents'] and 'result' in response['contents']['f5-utils-file-transfer:output']:
            result = response['contents']['f5-utils-file-transfer:output']['result']
            if result.startswith('Aborted: local-file already exists'):
                raise F5ModuleError(f"Failed to import system image, error: {result}")
            if result.startswith('File import with same local file name is in progress'):
                raise F5ModuleError(f"Failed to import system image, error: {result}")
            operation_id = response['contents']['f5-utils-file-transfer:output']['operation-id']
            self.changes.update({"operation_id": operation_id})
        time.sleep(20)
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
            # check if the operation-id is exist in the response
            if 'operation-id' not in item:
                continue
            if item['operation-id'] == self.want.operation_id:
                status = item['status'].strip()
                if status == 'Completed':
                    return False
                elif status.startswith('In Progress') or status.startswith('File Transfer Initiated'):
                    return True
                else:
                    raise F5ModuleError(f"File upload failed with the following result: {status}")
        raise F5ModuleError("File upload job not has not started, check device logs for more information.")

    def is_imported(self):
        uri = "/openconfig-system:system/f5-system-image:image/f5-system-image:state/f5-system-image:iso/f5-system-image:iso"
        if "CONTROLLER" in self.want.image_name:
            # Check the status of the image for F5OS-C Controller
            uri = "/f5-system-image:image/controller/state/controllers/controller"
        if 'PARTITION' in self.want.image_name:
            # Check the status of the image for F5OS-C Partition
            uri = "/f5-system-image:image/partition/state/controllers/controller"
        response = self.client.get(uri)
        # raise F5ModuleError(response['contents'])
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        pattern = r'(\d+\.\d+\.\d+-\d+)'
        # Search for the pattern in the filename
        match = re.search(pattern, self.want.image_name)
        img_str = match.group(1)
        status = ""
        if "CONTROLLER" in self.want.image_name:
            images = response['contents']['f5-system-image:controller']
            for image in images:
                for isoimg in image['iso']['iso']:
                    if isoimg['version-iso-controller'] == img_str:
                        status = isoimg['status']
                        break
            if 'ready' in status:
                return True
            if 'verifying' in status:
                return False
            if 'verification-failed' in status:
                raise F5ModuleError(f"The image: {self.want.image_name} was imported, but it failed signature verification, "
                                    f"remove the image and try again.")
            return False
        if 'PARTITION' in self.want.image_name:
            images = response['contents']['f5-system-image:controller']
            for image in images:
                for isoimg in image['iso']['iso']:
                    if isoimg['version-iso-partition'] == img_str:
                        status = isoimg['status']
                        break
            if 'ready' in status:
                return True
            if 'verifying' in status:
                return False
            if 'verification-failed' in status:
                raise F5ModuleError(f"The image: {self.want.image_name} was imported, but it failed signature verification, "
                                    f"remove the image and try again.")
            return False
        images = response['contents']['f5-system-image:iso']
        for image in images:
            if image['version-iso'] == img_str:
                status = image['status']
                break
        if 'ready' in status:
            time.sleep(10)
            return True
        if 'verifying' in status:
            return False
        if 'verification-failed' in status:
            raise F5ModuleError(f"The image: {self.want.image_name} was imported, but it failed signature verification, "
                                f"remove the image and try again.")
        return False

    def remove_from_device(self):
        uri = "/openconfig-system:system/f5-system-image:image/remove"
        pattern = r'(\d+\.\d+\.\d+-\d+)'
        # Search for the pattern in the filename
        match = re.search(pattern, self.want.image_name)
        img_str = match.group(1)
        if "CONTROLLER" in self.want.image_name:
            # Remove the image for F5OS-C Controller
            uri = "/f5-system-image:image/controller/remove"
        if 'PARTITION' in self.want.image_name:
            # Remove the image for F5OS-C Partition
            uri = "/f5-system-image:image/partition/remove"
        # payload_keys = ["iso", "os", "service"]
        payload_keys = ["iso"]
        success = False
        result = ""
        for key in payload_keys:
            payload = {
                key: img_str,
            }
            response = self.client.post(uri, data=payload)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to remove system {key} image: {self.want.image_name} {response['contents']}")
            result = response['contents']["f5-system-image:output"]['response']
            time.sleep(10)
            if 'Success' in result:
                success = True
            else:
                success = False
        if success:
            return True
        raise F5ModuleError(f"Failed to remove system image: {self.want.image_name} {result}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            remote_image_url=dict(type='str', required=True),
            remote_user=dict(),
            remote_password=dict(no_log=True),
            local_path=dict(
                choices=['images/import', 'images/staging', 'images/tenant', 'images']
            ),
            operation_id=dict(type='str'),
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
            ['state', 'import', ['remote_image_url', 'local_path']],
            ['state', 'present', ['remote_image_url', 'local_path']],
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
