#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_client_cert_auth
short_description: Manage client certificate authentication on F5OS devices
description:
  - Enable or disable client certificate authentication and configure the trusted
    CA bundle for client certificates on F5OS rSeries and VELOS partition devices
    via the F5OS RESTCONF API.
  - This module is not supported on VELOS controllers.
version_added: "1.23.0"
options:
  enabled:
    description:
      - Whether client certificate authentication should be enabled or disabled.
      - Required when C(state) is C(present).
    type: bool
  trusted_ca:
    description:
      - The name of the trusted CA bundle to use for client certificate verification.
      - Optional. When specified, configures the trusted CA bundle used to validate
        client certificates.
      - Set to an empty string C('') to explicitly clear a previously configured
        trusted CA without removing the entire client cert auth configuration.
    type: str
  state:
    description:
      - The desired state of the client certificate authentication configuration.
      - If C(present), creates or updates the configuration.
      - If C(absent), removes the client certificate authentication configuration,
        restoring default values.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - F5 Networks (@f5networks)
notes:
  - This module is supported on F5OS rSeries platforms and VELOS partitions.
  - It is not supported on VELOS controllers.
'''

EXAMPLES = r'''
- name: Enable client certificate authentication
  f5networks.f5os.f5os_client_cert_auth:
    enabled: true
    state: present

- name: Enable client certificate authentication with trusted CA
  f5networks.f5os.f5os_client_cert_auth:
    enabled: true
    trusted_ca: "my-ca-bundle"
    state: present

- name: Disable client certificate authentication
  f5networks.f5os.f5os_client_cert_auth:
    enabled: false
    state: present

- name: Remove client certificate authentication configuration
  f5networks.f5os.f5os_client_cert_auth:
    state: absent
'''

RETURN = r'''
enabled:
  description: Whether client certificate authentication is enabled.
  returned: changed
  type: bool
  sample: true
trusted_ca:
  description: The trusted CA bundle name for client certificate verification.
  returned: changed
  type: str
  sample: "my-ca-bundle"
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    returnables = [
        'enabled',
        'trusted_ca',
    ]

    updatables = [
        'enabled',
        'trusted_ca',
    ]


class ApiParameters(Parameters):
    @property
    def enabled(self):
        config = self._values.get('f5-openconfig-aaa-tls:client-cert-auth', {})
        if not config:
            return None
        return config.get('config', {}).get('enabled')

    @property
    def trusted_ca(self):
        config = self._values.get('f5-openconfig-aaa-tls:client-cert-auth', {})
        if not config:
            return None
        return config.get('config', {}).get('trusted-ca')


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
        except AttributeError:
            return attr1

    @property
    def trusted_ca(self):
        # An empty string means the user wants to clear the trusted CA.
        if self.want.trusted_ca is None:
            return None
        if self.want.trusted_ca != self.have.trusted_ca:
            return self.want.trusted_ca
        return None


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

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
        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
        start = datetime.datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        self.have = self.read_current_from_device()
        if not self._update_changed_options():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def absent(self):
        self.have = self.read_current_from_device()
        if self.have.enabled is None:
            return False
        if self.module.check_mode:
            return True
        self.remove_from_device()
        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:client-cert-auth"
        response = self.client.get(uri)
        if response['code'] == 404:
            return ApiParameters(params={})
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents'])

    def update_on_device(self):
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:client-cert-auth"
        config = {
            "enabled": self.want.enabled,
        }
        if self.want.trusted_ca is not None and self.want.trusted_ca != '':
            config["trusted-ca"] = self.want.trusted_ca
        payload = {
            "f5-openconfig-aaa-tls:client-cert-auth": {
                "config": config
            }
        }
        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:client-cert-auth"
        response = self.client.delete(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            enabled=dict(type='bool'),
            trusted_ca=dict(type='str'),
            state=dict(
                default='present',
                choices=['present', 'absent'],
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=[
            ['state', 'present', ['enabled']],
        ],
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
