#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_audit_log
short_description: Manage audit logging on F5OS devices
description:
  - Manage audit logging configuration on F5OS devices.
  - Enable or disable audit logging and configure remote forwarding of audit logs.
version_added: "1.23.0"
options:
  enabled:
    description:
      - Enable or disable audit logging on the device.
    type: bool
  remote_forwarding:
    description:
      - Configure remote forwarding of audit logs to an external server.
    type: dict
    suboptions:
      enabled:
        description:
          - Enable or disable remote forwarding of audit logs.
        type: bool
      server:
        description:
          - The remote server IP address or hostname to forward audit logs to.
        type: str
      port:
        description:
          - The remote server port to forward audit logs to.
        type: int
      protocol:
        description:
          - The protocol to use when forwarding audit logs to the remote server.
        type: str
        choices:
          - udp
          - tcp
  state:
    description:
      - The state of the audit log configuration.
      - When C(present), ensures the audit log configuration is applied.
      - When C(read), returns the current audit log configuration state without making changes.
    type: str
    choices:
      - present
      - read
    default: present
author:
  - F5 Networks (@F5Networks)
'''

EXAMPLES = r'''
- name: Enable audit logging
  f5os_audit_log:
    enabled: true
    state: present

- name: Disable audit logging
  f5os_audit_log:
    enabled: false
    state: present

- name: Configure audit log with remote forwarding
  f5os_audit_log:
    enabled: true
    remote_forwarding:
      enabled: true
      server: 10.10.10.100
      port: 514
      protocol: udp
    state: present

- name: Disable remote forwarding of audit logs
  f5os_audit_log:
    remote_forwarding:
      enabled: false
    state: present

- name: Read audit log configuration state
  f5os_audit_log:
    state: read
'''

RETURN = r'''
enabled:
  description: Whether audit logging is enabled.
  returned: changed or read
  type: bool
  sample: true
remote_forwarding:
  description: The remote forwarding configuration.
  returned: changed or read
  type: dict
  sample:
    enabled: true
    server: "10.10.10.100"
    port: 514
    protocol: "udp"
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client,
    send_teem,
)
from ..module_utils.common import (
    F5ModuleError,
    AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    returnables = [
        'enabled',
        'remote_forwarding',
    ]
    updatables = [
        'enabled',
        'remote_forwarding',
    ]


class ApiParameters(Parameters):
    @property
    def enabled(self):
        config = self._values.get('config', {})
        if not config:
            config = self._values.get('state', {})
        if not config:
            return None
        enabled = config.get('enabled')
        if enabled is None:
            return None
        return enabled

    @property
    def remote_forwarding(self):
        config = self._values.get('config', {})
        if not config:
            config = self._values.get('state', {})
        if not config:
            return None
        remote = config.get('remote-forwarding', {})
        if not remote:
            return None
        result = {}
        rf_config = remote.get('config', remote.get('state', {}))
        if 'enabled' in rf_config:
            result['enabled'] = rf_config['enabled']
        if 'host' in rf_config:
            result['server'] = rf_config['host']
        if 'port' in rf_config:
            port = rf_config['port']
            try:
                port = int(port)
            except (TypeError, ValueError):
                pass
            result['port'] = port
        if 'protocol' in rf_config:
            result['protocol'] = rf_config['protocol']
        if not result:
            return None
        return result


class ModuleParameters(Parameters):
    @property
    def enabled(self):
        return self._values.get('enabled')

    @property
    def remote_forwarding(self):
        rf = self._values.get('remote_forwarding')
        if rf is not None and 'port' in rf and rf['port'] is not None:
            if rf['port'] < 1 or rf['port'] > 65535:
                raise F5ModuleError(
                    "The 'port' value must be between 1 and 65535."
                )
        return rf


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


class Difference(object):
    def __init__(self, want, have):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        want = getattr(self.want, param)
        try:
            have = getattr(self.have, param)
            if want != have:
                return want
        except AttributeError:
            return want

    @property
    def enabled(self):
        if self.want.enabled is None:
            return None
        if self.want.enabled != self.have.enabled:
            return self.want.enabled

    @property
    def remote_forwarding(self):
        if self.want.remote_forwarding is None:
            return None
        if self.have.remote_forwarding is None:
            # Filter out None values from want before returning
            return {k: v for k, v in self.want.remote_forwarding.items() if v is not None} or None

        want_rf = self.want.remote_forwarding
        have_rf = self.have.remote_forwarding

        changed = False
        result = {}
        for key in ('enabled', 'server', 'port', 'protocol'):
            if key in want_rf and want_rf[key] is not None:
                if want_rf[key] != have_rf.get(key):
                    changed = True
                result[key] = want_rf[key]
            elif key in have_rf:
                result[key] = have_rf[key]

        if changed:
            return result
        return None


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
        result = dict()

        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'read':
            changed = self.read()
        else:
            changed = False

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

    def exists(self):
        uri = "/openconfig-system:system/logging/f5-openconfig-system-logging:audit-log"
        response = self.client.get(uri)

        if response['code'] == 200:
            return True
        if response['code'] == 404:
            return False
        raise F5ModuleError(response['contents'])

    def read(self):
        self.read_current_from_device()
        params = {}
        for key in Parameters.returnables:
            val = getattr(self.have, key, None)
            if val is not None:
                params[key] = val
        self.changes = UsableChanges(params=params)
        return False

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def update(self):
        self.have = self.read_current_from_device()
        if not self._update_changed_options():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/logging/f5-openconfig-system-logging:audit-log"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        data = response['contents'].get('f5-openconfig-system-logging:audit-log', {})
        self.have = ApiParameters(params=data)
        return self.have

    def _build_payload(self):
        config = {}

        # Merge changes with current state so PUT replaces the full resource correctly
        enabled = self.changes.enabled
        if enabled is None and self.have.enabled is not None:
            enabled = self.have.enabled
        if enabled is not None:
            config['enabled'] = enabled

        remote_forwarding = self.changes.remote_forwarding
        if remote_forwarding is None and self.have.remote_forwarding is not None:
            remote_forwarding = self.have.remote_forwarding
        if remote_forwarding is not None:
            rf_config = {}
            if remote_forwarding.get('enabled') is not None:
                rf_config['enabled'] = remote_forwarding['enabled']
            if remote_forwarding.get('server') is not None:
                rf_config['host'] = remote_forwarding['server']
            if remote_forwarding.get('port') is not None:
                rf_config['port'] = remote_forwarding['port']
            if remote_forwarding.get('protocol') is not None:
                rf_config['protocol'] = remote_forwarding['protocol']
            if rf_config:
                config['remote-forwarding'] = {'config': rf_config}

        payload = {
            'f5-openconfig-system-logging:audit-log': {
                'config': config
            }
        }
        return payload

    def _push_to_device(self):
        payload = self._build_payload()
        uri = "/openconfig-system:system/logging/f5-openconfig-system-logging:audit-log"
        response = self.client.put(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def create_on_device(self):
        self._push_to_device()

    def update_on_device(self):
        self._push_to_device()


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            enabled=dict(
                type='bool',
            ),
            remote_forwarding=dict(
                type='dict',
                options=dict(
                    enabled=dict(type='bool'),
                    server=dict(type='str'),
                    port=dict(type='int'),
                    protocol=dict(
                        type='str',
                        choices=['udp', 'tcp'],
                    ),
                ),
            ),
            state=dict(
                default='present',
                choices=['present', 'read'],
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['enabled', 'remote_forwarding'], True],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
