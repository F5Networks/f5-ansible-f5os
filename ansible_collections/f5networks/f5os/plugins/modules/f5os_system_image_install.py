#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_system_image_install
short_description: Manage F5OS system software installation.
description:
  - Manage F5OS system software installation.
version_added: "1.11.0"
options:
  partition_name:
    description:
      - Partition Name for which ISO image version is to be installed or upgraded.
    type: str
  image_version:
    description:
      - Image/software version to be installed on the F5OS device.
    type: str
    required: true
  timeout:
    description:
      - The number of seconds to wait for software installation to complete.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  state:
    description:
      - If C(install), starts the installation of the system image on the F5OS device.
      - If C(present), checks for the status of the installation of the system image and waits for completion.
      - If C(absent), presently this option is not supported.It will not remove the image from the device/uninstall the image.
    type: str
    choices:
      - install
      - present
      - absent
    default: install
notes:
  - Presently, the C(absent) option is not supported. It will not remove the image from the device/uninstall the image.
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Install Software Image
  f5os_system_image_install:
    image_version: "1.8.0-13846"
    state: install

- name: check status of Image Install
  f5os_system_image_install:
    image_version: "1.8.0-13846"
    state: install
    timeout: 600

- name: Update Partition Image Version
  f5os_system_image_install:
    partition_name: test100GbEoptics
    image_version: "1.6.2-30244"
    state: install
    timeout: 600

- name: check status of Image Install
  f5os_system_image_install:
    partition_name: test100GbEoptics
    image_version: "1.6.2-30244"
    state: present
    timeout: 600
'''
RETURN = r'''
image_version:
  description: Image/software version to be installed on the F5OS device.
  returned: changed
  type: str
  example: 1.8.0-13846
'''

import datetime
import time

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
        'image-name': 'image_version',
    }
    api_attributes = [
        'image-name',
    ]

    returnables = [
        'image_version',
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
    def image_version(self):
        if self._values['image_version'] is None:
            return None
        return self._values['image_version']


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
        'image_version',
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.image_is_valid = False
        self.partition_exists = False

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
        if self.client.platform == 'Velos Partition':
            raise F5ModuleError("Target device is a Velos Partition, aborting.")
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == "install":
            changed = self.install_image()
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

    def install_image(self):
        if self.exists():
            return False
        else:
            return self.create()

    def present(self):
        if self.exists():
            return False

    def absent(self):
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
        if self.want.partition_name is not None:
            self.update_partition_image()
        else:
            self.install_software_image()
        return True

    def exists(self):
        if self.want.partition_name is not None:
            if self.want.state == "present":
                return self.install_status_complete()
            else:
                exists, version = self.check_partition()
                self.partition_exists = exists
                if exists and version == self.want.image_version:
                    return True
                return False
        else:
            if self.install_status_complete():
                pass
            # try:
            #     result = self.install_status_complete()
            #     return True
            uri = "/openconfig-system:system/f5-system-image:image/state/install"
            response = self.client.get(uri)
            if response['code'] == 404 and self.client.platform == 'Velos Controller':
                uri = "/openconfig-system:system/f5-system-controller-image:image"
                response = self.client.get(uri)
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
                for key in response['contents']['f5-system-controller-image:image']['state']['controllers']['controller']:
                    if key['install-status'] == "success" and key['os-version'] == self.want.image_version:
                        return True
                return False
            if response['code'] == 404 and self.client.platform == 'Velos Partition':
                uri = "/openconfig-platform:components"
                response = self.client.get(uri)
                platform_data = response['contents']['openconfig-platform:components']['component'][0]
                for key in platform_data['f5-platform:software']['state']['software-components']['software-component']:
                    if key['state']['version'] != self.want.image_version:
                        return False
                return True
            if response['code'] in [200, 201, 202] and self.client.platform == 'rSeries Platform':
                if response['contents']['f5-system-image:install']['install-os-version'] == self.want.image_version and \
                        response['contents']['f5-system-image:install']['install-status'] == 'success':
                    return True
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])
                # {
                #     "f5-system-image:install": {
                #         "install-os-version": "1.8.0-13819",
                #         "install-service-version": "1.8.0-13819",
                #         "install-status": "success"
                #     }
                # }
            return False

    def check_partition(self):
        uri = "/f5-system-partition:partitions?with-defaults=report-all"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if 'f5-system-partition:partitions' in response['contents']:
            if 'partition' in response['contents']['f5-system-partition:partitions']:
                if len(response['contents']['f5-system-partition:partitions']['partition']) > 0:
                    for partition in response['contents']['f5-system-partition:partitions']['partition']:
                        if partition['name'] == self.want.partition_name:
                            return True, partition['config']['iso-version']
        return False, ''

    def update_partition_image(self):
        if not self.partition_exists:
            raise F5ModuleError("Partition does not exists.")
        partition_image_exists = False
        uri = '/f5-system-image:image/partition/config/iso'
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if 'f5-system-image:iso' in response['contents']:
            if 'iso' in response['contents']['f5-system-image:iso'] and len(response['contents']['f5-system-image:iso']['iso']) > 0:
                for iso_version in response['contents']['f5-system-image:iso']['iso']:
                    if iso_version['version'] == self.want.image_version:
                        partition_image_exists = True
                        break
        if not partition_image_exists:
            raise F5ModuleError(f"Partition Image with ISO version {self.want.image_version} does not exists.")
        uri = f'/f5-system-partition:partitions/partition={self.want.partition_name}/set-version'
        payload = {
            "f5-system-partition:iso-version": self.want.image_version
        }
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def install_software_image(self):
        params = self.changes.api_params()
        if self.client.platform == 'rSeries Platform':
            uri = "/openconfig-system:system/f5-system-image:image/f5-system-image:set-version"
            payload = {
                "f5-system-image:iso-version": params['image-name'],
                "f5-system-image:proceed": "yes"
            }
            response = self.client.post(uri, data=payload)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to install system image with {response['contents']}")
            # {'f5-system-image:output': {'response': 'System ISO version has been set.\\nEstimated time: 11 minutes\\nReboot(s): 1'}}
            # raise F5ModuleError(f"code {response['code']} contents: {response['contents']}")
            if 'f5-system-image:output' in response['contents'] and 'response' in response['contents']['f5-system-image:output']:
                result = response['contents']['f5-system-image:output']['response']
                if result.startswith('System ISO version has been set'):
                    self.changes.update({"message": f"Image {self.want.image_version} install started."})
                    return True
                if result.startswith('File import with same local file name is in progress'):
                    raise F5ModuleError(f"Failed to import system image, error: {result}")
            return True
        if self.client.platform == 'Velos Controller':
            uri = "/openconfig-system:system/f5-system-controller-image:image/f5-system-controller-image:set-version"
            # openconfig-system:system/f5-system-controller-image:image/f5-system-controller-image:set-version
            payload = {
                "f5-system-controller-image:iso-version": params['image-name'],
                "f5-system-controller-image:proceed": "yes"
            }
            response = self.client.post(uri, data=payload)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to install system image with {response['contents']}")
            if 'f5-system-controller-image:output' in response['contents'] and 'response' in response['contents']['f5-system-controller-image:output']:
                result = response['contents']['f5-system-controller-image:output']['response']
                if result.startswith('System ISO version has been set'):
                    self.changes.update({"message": f"Image {self.want.image_version} install started."})
                    return True
                if result.startswith('File import with same local file name is in progress'):
                    raise F5ModuleError(f"Failed to import system image, error: {result}")
            return True
        if self.client.platform == 'Velos Partition':
            raise F5ModuleError("Target device is a VELOS partition, aborting.")

    def install_status_complete(self):
        delay, period = self.want.timeout
        for x in range(0, period):
            if self.is_still_installing():
                time.sleep(delay)
                continue
            if not self.changes.message:
                self.changes.update({"message": f"Image {self.want.image_version} import successful."})
            return True
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def is_still_installing(self):
        try:
            if self.want.partition_name:
                uri = "/f5-system-partition:partitions?with-defaults=report-all"
                response = self.client.get(uri)
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
                if 'f5-system-partition:partitions' in response['contents']:
                    if 'partition' in response['contents']['f5-system-partition:partitions']:
                        if len(response['contents']['f5-system-partition:partitions']['partition']) > 0:
                            for partition in response['contents']['f5-system-partition:partitions']['partition']:
                                if partition['name'] == self.want.partition_name and 'state' in partition and 'install-status' in partition['state']:
                                    if partition['state']['install-status'] == ['in-progress', 'switching-role', 'pending']:
                                        return True
                                    elif partition['state']['install-status'] == "success":
                                        return False
                                    else:
                                        raise F5ModuleError('Installation Failed with status' + partition['state']['install-status'])

            else:
                uri = "api"
                response = self.client.get(uri, scope="/")
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
                return False
        except Exception as e:
            if e.__class__.__name__ == 'ConnectionError':
                return True
            raise F5ModuleError(f"Failed to check the status of the api: {self.want.image_version} {e}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            partition_name=dict(type='str'),
            image_version=dict(type='str', required=True),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='install',
                choices=['install', 'present', 'absent']
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
