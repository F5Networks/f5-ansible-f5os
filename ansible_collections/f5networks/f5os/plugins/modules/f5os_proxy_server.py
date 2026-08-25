#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_proxy_server
short_description: Manage proxy server settings on F5OS devices
description:
  - Configure or remove proxy server settings for licensing and iHealth uploads
    on F5OS rSeries and VELOS partition devices via the F5OS RESTCONF API.
  - This module is not supported on VELOS controllers.
version_added: "1.23.0"
options:
  proxy_server:
    description:
      - The proxy server address or hostname.
      - Required when C(state) is C(present).
    type: str
  proxy_port:
    description:
      - The proxy server port number.
      - Required when C(state) is C(present).
    type: int
  proxy_username:
    description:
      - The username for proxy server authentication.
      - Optional for create operations.
      - When existing credentials are configured, updates to C(proxy_server) or
        C(proxy_port) require both C(proxy_username) and C(proxy_password).
    type: str
  proxy_password:
    description:
      - The password for proxy server authentication.
      - Optional for create operations.
      - When existing credentials are configured, updates to C(proxy_server) or
        C(proxy_port) require both C(proxy_username) and C(proxy_password).
      - This value is not returned in API responses for security reasons.
    type: str
  state:
    description:
      - The desired state of the proxy server configuration.
      - If C(present), creates or updates the proxy server configuration.
      - If C(absent), removes the proxy server configuration.
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
  - The module manages the diagnostics proxy RESTCONF endpoint.
  - On replace-style APIs, updates to server/port are blocked when existing
    credentials are present and new credentials are omitted.
  - Proxy passwords are not returned by the API; therefore, if only the password
    changes, the module cannot detect the difference and will report no change.
    To force a password update, also change another parameter or remove and re-add
    the proxy configuration.
'''

EXAMPLES = r'''
- name: Configure proxy server with authentication
  f5networks.f5os.f5os_proxy_server:
    proxy_server: "10.1.1.100"
    proxy_port: 3128
    proxy_username: "proxyuser"
    proxy_password: "proxypass"
    state: present

- name: Configure proxy server without authentication
  f5networks.f5os.f5os_proxy_server:
    proxy_server: "proxy.example.com"
    proxy_port: 8080
    state: present

- name: Remove proxy server configuration
  f5networks.f5os.f5os_proxy_server:
    state: absent
'''

RETURN = r'''
proxy_server:
  description: The proxy server address.
  returned: changed
  type: str
  sample: "10.1.1.100"
proxy_port:
  description: The proxy server port number.
  returned: changed
  type: int
  sample: 3128
proxy_username:
  description: The proxy server authentication username.
  returned: changed
  type: str
  sample: "proxyuser"
'''

import datetime
from urllib.parse import urlparse

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
        'proxy_server',
        'proxy_port',
        'proxy_username',
    ]

    updatables = [
        'proxy_server',
        'proxy_port',
        'proxy_username',
        # proxy_password is intentionally excluded from updatables because
        # the API never returns passwords, making comparison impossible.
    ]


class ApiParameters(Parameters):
    def _get_proxy_node(self):
        return (
            self._values.get('f5-system-proxy:proxy')
            or self._values.get('f5-system-diagnostics-proxy:proxy')
            or {}
        )

    def _get_proxy_source(self):
        node = self._get_proxy_node()
        return node.get('config', {}) if node.get('config') else node.get('state', {})

    @property
    def proxy_server(self):
        source = self._get_proxy_source()
        value = source.get('proxy-server')
        if value in [None, '']:
            return None
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return parsed.hostname
        return value

    @property
    def proxy_port(self):
        source = self._get_proxy_source()
        port = source.get('proxy-port')
        if port is not None:
            return int(port)
        value = source.get('proxy-server')
        if value:
            parsed = urlparse(value)
            if parsed.port is not None:
                return int(parsed.port)
        return None

    @property
    def proxy_username(self):
        source = self._get_proxy_source()
        value = source.get('proxy-username')
        if value == '':
            return None
        return value


class ModuleParameters(Parameters):
    def _parse_proxy_server(self):
        """Parse user-supplied proxy_server, returning (scheme, hostname).

        Normalizes inputs that already contain a scheme or embedded port
        so that update_on_device never produces malformed double-scheme URLs.
        """
        value = self._values.get('proxy_server')
        if value is None:
            return None, None
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return parsed.scheme, parsed.hostname
        # Handle bare host:port without scheme (e.g. 'proxy.example.com:8080')
        if ':' in value:
            return 'http', value.split(':', 1)[0]
        return 'http', value

    @property
    def proxy_server(self):
        parsed = self._parse_proxy_server()
        return parsed[1]

    @property
    def proxy_scheme(self):
        parsed = self._parse_proxy_server()
        return parsed[0]


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
    DIAG_PROXY_URI = '/openconfig-system:system/f5-system-diagnostics-qkview:diagnostics/f5-system-diagnostics-proxy:proxy'

    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()
        self.proxy_uri = self.DIAG_PROXY_URI
        self.proxy_kind = 'diagnostics'

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
            # If no updatable fields changed and the proxy already exists,
            # treat as idempotent (no change). Password cannot be compared
            # since the API never returns it, so we trust it is already set
            # when the rest of the config matches.
            if self.have.proxy_server is not None:
                return False
            # Proxy does not exist yet; proceed to create.
        if self.module.check_mode:
            return True
        self._validate_safe_credential_update()
        self.update_on_device()
        return True

    def _validate_safe_credential_update(self):
        existing_username = self.have.proxy_username
        if existing_username in [None, '']:
            return

        if not any(k in self.changes._values for k in ['proxy_server', 'proxy_port']):
            return

        if self.want.proxy_username is None and self.want.proxy_password is None:
            raise F5ModuleError(
                'Existing proxy credentials detected. Provide both proxy_username and '
                'proxy_password when updating proxy_server/proxy_port to avoid '
                'accidental credential loss.'
            )

    def absent(self):
        self.have = self.read_current_from_device()
        if self.have.proxy_server is None:
            return False
        if self.module.check_mode:
            return True
        self.remove_from_device()
        return True

    def _resolve_proxy_endpoint(self):
        response = self.client.get(self.DIAG_PROXY_URI)
        if response['code'] == 404:
            return dict(code=404, contents={})
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response

    def read_current_from_device(self):
        response = self._resolve_proxy_endpoint()
        if response['code'] == 404:
            return ApiParameters(params={})
        return ApiParameters(params=response['contents'])

    def update_on_device(self):
        host = self.want.proxy_server
        port = self.want.proxy_port
        scheme = self.want.proxy_scheme or 'http'

        config = {
            'proxy-server': '{0}://{1}:{2}'.format(scheme, host, port)
        }

        if self.want.proxy_username is not None:
            config["proxy-username"] = self.want.proxy_username
        if self.want.proxy_password is not None:
            config["proxy-password"] = self.want.proxy_password
        payload = {
            'f5-system-diagnostics-proxy:proxy': {
                "config": config
            }
        }
        response = self.client.put(self.proxy_uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        response = self.client.delete(self.proxy_uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            proxy_server=dict(type='str'),
            proxy_port=dict(type='int'),
            proxy_username=dict(type='str'),
            proxy_password=dict(type='str', no_log=True),
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
            ['state', 'present', ['proxy_server', 'proxy_port']],
        ],
        required_together=[
            ['proxy_username', 'proxy_password'],
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
