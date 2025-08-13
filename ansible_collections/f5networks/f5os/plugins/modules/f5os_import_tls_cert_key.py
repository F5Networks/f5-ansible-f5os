#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_import_tls_cert_key
short_description: Import TLS certificate and key onto F5OS devices.
description:
  - Import an existing TLS certificate and private key onto F5OS devices.
version_added: 1.12.0
options:
  certificate:
    description:
      - The PEM-formatted certificate string or path to a certificate file.
      - Sensitive value, will not be shown in logs or output.
    type: str
    required: true
  key:
    description:
      - The PEM-formatted private key string or path to a key file.
      - Sensitive value, will not be shown in logs or output.
    type: str
    required: true
  key_passphrase:
    description:
      - The passphrase for the private key, if it is encrypted.
      - Sensitive value, will not be shown in logs or output.
    type: str
  verify_client:
    description:
      - Whether to enable client certificate verification.
    type: bool
    default: false
  verify_client_depth:
    description:
      - The maximum depth for client certificate verification.
    type: int
    default: 0
  state:
    description:
      - Whether the cert/key should be present or absent on the device.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy(@chinthalapalli)
'''

EXAMPLES = r'''
- name: Import TLS cert and key onto F5OS
  f5os_import_tls_cert_key:
    certificate: "{{ lookup('file', 'certs/mycert.pem') }}"
    key: "{{ lookup('file', 'certs/mykey.pem') }}"
    key_passphrase: "{{ lookup('file', 'certs/mykey_passphrase.txt') }}"
    state: present
'''

RETURN = r'''
changed:
  description: Indicates if the module made any changes to the device.
  returned: always
  type: bool
  sample: true
certificate:
  description: The PEM-formatted certificate that was imported.
  returned: changed
  type: str
  sample: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAL5k5y5k5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y
    -----END CERTIFICATE-----
key:
  description: The PEM-formatted private key that was imported.
  returned: changed
  type: str
  sample: |
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
    MIIDXTCCAkWgAwIBAgIJAL5k5y5k5k5y5k5y55k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y5k5y
    -----END PRIVATE KEY-----
key_passphrase:
  description: The passphrase for the private key, if it was encrypted.
  returned: changed
  type: str
  sample: mysecretpassphrase
verify_client:
  description: Whether client certificate verification is enabled.
  returned: changed
  type: bool
  sample: false
verify_client_depth:
  description: The maximum depth for client certificate verification.
  returned: changed
  type: int
  sample: 1
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ..module_utils.client import F5Client
from ..module_utils.common import F5ModuleError
from ..module_utils.common import AnsibleF5Parameters


class Parameters(AnsibleF5Parameters):
    """
    Parameter class for F5OS TLS cert/key import module, extends AnsibleF5Parameters for advanced handling.
    """
    api_map = {
        "f5-openconfig-aaa-tls:certificate": "certificate",
        "f5-openconfig-aaa-tls:key": "key",
        "f5-openconfig-aaa-tls:passphrase": "key_passphrase",
        "f5-openconfig-aaa-tls:verify-client": "verify_client",
        "f5-openconfig-aaa-tls:verify-client-depth": "verify_client_depth",
    }
    api_attributes = [
        "f5-openconfig-aaa-tls:certificate",
        "f5-openconfig-aaa-tls:key",
        "f5-openconfig-aaa-tls:passphrase",
        "f5-openconfig-aaa-tls:verify-client",
        "f5-openconfig-aaa-tls:verify-client-depth",
    ]

    returnables = [
        "certificate",
        "key",
        "key_passphrase",
    ]

    updatables = [
        "certificate",
        "key",
        "key_passphrase",
    ]


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:  # pragma: no cover
            raise
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class ApiParameters(Parameters):
    """API parameters class for F5OS TLS cert/key import module, extends Parameters for API-specific handling.
    """

    @property
    def certificate(self):
        # Handles both config and direct mapping for certificate
        if hasattr(self, '_values') and 'certificate' in self._values:
            return self._values['certificate']
        if hasattr(self, '_values') and 'config' in self._values and 'certificate' in self._values['config']:
            return self._values['config']['certificate']
        return None

    @property
    def key(self):
        # Handles both config and direct mapping for key
        if hasattr(self, '_values') and 'key' in self._values:
            return self._values['key']
        if hasattr(self, '_values') and 'config' in self._values and 'key' in self._values['config']:
            return self._values['config']['key']
        return None


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        # Ignore 'key' for difference checks
        if param == 'key':
            return None
        # Ignore 'key_passphrase' for difference checks
        if param == 'key_passphrase':
            return None
        try:
            result = getattr(self, param)
            return result  # pragma: no cover
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


# Helper class for module parameters
class ModuleParameters(object):
    def __init__(self, params):
        self._params = params

    @property
    def certificate(self):
        return self._params.get('certificate')

    @property
    def key(self):
        return self._params.get('key')

    @property
    def key_passphrase(self):
        return self._params.get('key_passphrase')

    @property
    def state(self):
        return self._params.get('state', 'present')


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

    # def _set_changed_options(self):
    #     changed = {}
    #     for key in Parameters.returnables:
    #         if getattr(self.want, key) is not None:
    #             changed[key] = getattr(self.want, key)

    #     if changed:
    #         self.changes = UsableChanges(params=changed)
    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)  # pragma: no cover
                else:
                    changed[k] = change
        self.module.warn(f"[DEBUG] Changed options: {changed}")
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
        changed = False
        result = dict()
        state = self.want.state

        self.module.warn(f"[DEBUG] Starting exec_module with state: {state}")

        if state == "present":
            self.module.warn("[DEBUG] Calling present() method.")
            changed = self.present()
        elif state == "absent":
            self.module.warn("[DEBUG] Calling absent() method.")
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        self.module.warn(f"[DEBUG] exec_module result: {result}")
        return result

    def present(self):
        self.module.warn("[DEBUG] Calling update() directly for present(). Skipping exists() check.")
        return self.update()

    def absent(self):
        self.module.warn("[DEBUG] Checking if resource exists for absent().")
        return self.remove()

    def should_update(self):
        self.module.warn("[DEBUG] Checking if update is needed.")
        result = self._update_changed_options()
        if result:
            self.module.warn("[DEBUG] Update is needed.")
            return True
        self.module.warn("[DEBUG] No update needed.")
        return False

    def update(self):
        self.module.warn("[DEBUG] Reading current state from device for update().")
        self.have = self.read_current_from_device()
        if not self.should_update():
            self.module.warn("[DEBUG] No update required.")
            return False
        if self.module.check_mode:  # pragma: no cover
            self.module.warn("[DEBUG] Check mode enabled, skipping update.")
            return True
        self.module.warn("[DEBUG] Calling create_on_device() for update().")
        self.create_on_device()
        return True

    def remove(self):
        self.module.warn("[DEBUG] Removing resource from device.")
        if self.module.check_mode:  # pragma: no cover
            self.module.warn("[DEBUG] Check mode enabled, skipping remove.")
            return True
        if not self.exists():
            self.module.warn("[DEBUG] Resource does not exist, nothing to remove.")
            return False
        return self.remove_from_device()

    def exists(self):
        self.module.warn("[DEBUG] Checking if resource exists on device.")
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls"
        self.module.warn(f"[DEBUG] GET {uri}")
        response = self.client.get(uri)
        self.module.warn(f"[DEBUG] Response: {response}")

        if response['code'] == 404:
            self.module.warn("[DEBUG] Resource not found (404).")
            return False

        if response['code'] not in [200, 201, 202]:
            self.module.warn(f"[DEBUG] Unexpected response code: {response['code']}")
            raise F5ModuleError(response['contents'])

        config = response['contents']['f5-openconfig-aaa-tls:tls']['config']
        if 'certificate' not in config or 'key' not in config:  # pragma: no cover
            return False  # pragma: no cover
        return True

    def create_on_device(self):
        self.module.warn("[DEBUG] create_on_device() called. Implement device creation logic here.")
        params = self.changes.api_params()
        if params is None:
            params = {}  # pragma: no cover
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/config"

        if 'f5-openconfig-aaa-tls:key' not in params:
            params['f5-openconfig-aaa-tls:key'] = self.want.key
        if 'f5-openconfig-aaa-tls:passphrase' not in params:
            params['f5-openconfig-aaa-tls:passphrase'] = self.want.key_passphrase
        if 'f5-openconfig-aaa-tls:verify-client' not in params:
            params['f5-openconfig-aaa-tls:verify-client'] = False  # self.want.verify_client
        if 'f5-openconfig-aaa-tls:verify-client-depth' not in params:
            params['f5-openconfig-aaa-tls:verify-client-depth'] = 0  # self.want.verify_client_depth
        payload = {
            "f5-openconfig-aaa-tls:config": params
        }

        self.module.warn(f"[DEBUG] PATCH {uri} with payload: {payload}")
        response = self.client.patch(uri, data=payload)
        self.module.warn(f"[DEBUG] Response: {response}")
        if response['code'] not in [200, 201, 202, 204]:
            self.module.warn(f"[DEBUG] Failed to create TLS cert/key. Response code: {response['code']}")
            raise F5ModuleError(response['contents'])
        self.module.warn("[DEBUG] TLS cert/key created successfully on device.")
        return True

    def remove_from_device(self):
        self.module.warn("[DEBUG] remove_from_device() called. Implement device removal logic here.")
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:config"
        self.module.warn(f"[DEBUG] DELETE {uri}")
        response = self.client.delete(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        self.module.warn("[DEBUG] TLS cert/key removed successfully from device.")
        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls"
        self.module.warn("[DEBUG] read_current_from_device() called. Implement device read logic here.")
        self.module.warn(f"[DEBUG] GET {uri}")
        response = self.client.get(uri)
        self.module.warn(f"[DEBUG] Response {response}")

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents']['f5-openconfig-aaa-tls:tls'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            certificate=dict(type='str', required=True, no_log=True),
            key=dict(type='str', required=True, no_log=True),
            key_passphrase=dict(type='str', no_log=True),
            verify_client=dict(type='bool', default=False),
            verify_client_depth=dict(type='int', default=0),
            state=dict(type='str', default='present', choices=['present', 'absent'])
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
