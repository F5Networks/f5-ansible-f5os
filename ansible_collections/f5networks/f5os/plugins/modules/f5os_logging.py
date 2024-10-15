#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_logging
short_description: Manage logging settings
description:
  - Enable / disable remote logging
  - Specify to include hostname
  - Specify remote servers
  - Specify logs and files to forward to the remote server
  - Specify TLS settings (cert, key, trusted CA) for mTLS
  - This Module is not idempotent due to API restrictions
version_added: 1.10.0
options:
    servers:
        description: Specifies the logservers
        type: list
        elements: dict
        suboptions:
            address:
                description: Specifies the servers IP address.
                type: str
            port:
                description: Specifies the transport layer port
                type: int
            protocol:
                description: Specifies the transport layer protocol
                type: str
                choices:
                    - tcp
                    - udp
            authentication:
                description:
                    - Specifies if the system uses mutual TLS to transfer logs encrypted and authenticated.
                    - The client certificate and key are to be specified in the tls parameter.
                    - Only applies for protocol(tcp).
                type: bool
            logs:
                description: Specifies the logs to be sent to this specific server
                type: list
                elements: dict
                suboptions:
                    facility:
                        description: Filter logs on facility local0 or authpriv.
                        type: str
                    severity:
                        description: Specify the minimum seceverity to be forwarded to this server
                        type: str
                        choices:
                            - debug
                            - informational
                            - notice
                            - warning
                            - error
                            - critical
                            - alert
                            - emergency
    remote_forwarding:
        description: Specifies logs and files for remote forwarding
        type: dict
        suboptions:
            enabled:
                description: Enables remote log forwarding
                type: bool
            logs:
                description: Specifies the logs to be sent to remote servers
                type: list
                elements: dict
                suboptions:
                    facility:
                        description: Filter logs on facility.
                        type: str
                    severity:
                        description: Specify the minimum seceverity to be forwarded to remote servers
                        type: str
                        choices:
                            - debug
                            - informational
                            - notice
                            - warning
                            - error
                            - critical
                            - alert
                            - emergency
            files:
                description: Specifies the files to be sent to remote servers
                type: list
                elements: dict
                suboptions:
                    name:
                        description: Specifies the file path (starting from the log directory) that shall be forwarded
                        type: str
    include_hostname:
        description: Specifies whether or not to include the hostname in the logmessages
        type: bool
    tls:
        description: Specifies the TLS certificate and key for mutual TLS with TCP log forwarding
        type: dict
        suboptions:
            certificate:
                description: Specifies the TLS certificate
                type: str
            key:
                description: Specifies the TLS key
                type: str
    ca_bundles:
        description: Specifies the trusted CA bundles for mutual TLS with TCP log forwarding
        type: list
        elements: dict
        suboptions:
            name:
                description: Specifies the name for the bundle
                type: str
            content:
                description: Specifies certificate files in PEM format
                type: str
    state:
        description:
            - If C(present), creates/updates the specified setting if necessary.
            - If C(absent), deletes the specified setting if it exists.
        type: str
        choices:
            - present
            - absent
        default: present
author:
  - Martin Vogel (@MVogel91)
'''

EXAMPLES = r'''
- name: Configure TLS settings
  f5os_logging:
    tls:
      certificate: <Cert as PEM>
      key: <KEY as PEM>
    ca_bundles:
      - name: "test"
        content: <Bundle as PEM>
      - name: "test2"
        content: <Bundle as PEM>

- name: Create logservers
  f5os_logging:
    servers:
      - address: 1.2.3.4
        protocol: udp
        port: 514
        logs:
          - facility: local0
            severity: notice
          - facility: authpriv
            severity: notice
      - address: 1.2.3.5
        protocol: udp
        port: 514
        logs:
          - facility: local0
            severity: notice
          - facility: authpriv
            severity: notice

- name: Send hostname
  f5os_logging:
    include_hostname: true

- name: Configure Remote Forwarding
  f5os_logging:
    remote_forwarding:
      enabled: true
      logs:
        - facility: local0
          severity: informational
        - facility: authpriv
          severity: notice
        - facility: auth
          severity: emergency
      files:
        - name: ansible.log
        - name: audit/
        - name: boot.log

- name: Remove logservers
  f5os_logging:
    servers:
      - address: 1.2.3.4
        protocol: udp
        port: 514
        logs:
          - facility: local0
            severity: notice
          - facility: authpriv
            severity: notice
      - address: 1.2.3.5
        protocol: udp
        port: 514
        logs:
          - facility: local0
            severity: notice
          - facility: authpriv
            severity: notice
    state: absent

- name: Disable sending of hostname
  f5os_logging:
    include_hostname: false

- name: Remove Remote Forwarding config
  f5os_logging:
    remote_forwarding:
      enabled: true
      logs:
        - facility: local0
          severity: informational
        - facility: authpriv
          severity: notice
        - facility: auth
          severity: emergency
      files:
        - name: ansible.log
        - name: audit/
        - name: boot.log
    state: absent

- name: Remove TLS settings
  f5os_logging:
    tls:
      certificate: <Cert as PEM>
      key: <KEY as PEM>
    ca_bundles:
      - name: "test"
        content: <Bundle as PEM>
      - name: "test2"
        content: <Bundle as PEM>
    state: absent
'''

RETURN = r'''
tls:
  description: TLS settings
  returned: changed
  type: str
ca_bundles:
  description: CA bundles
  returned: changed
  type: str
servers:
  description: Remote Log server configs
  returned: changed
  type: str
include_hostname:
  description: inclusion of hostname in logs
  returned: changed
  type: str
remote_forwarding:
  description: forwarding settings for log files
  returned: changed
  type: str
'''

import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        'tls',
        'ca_bundles',
        'servers',
        'include_hostname',
        'remote_forwarding'
    ]

    returnables = [
        'tls',
        'ca_bundles',
        'servers',
        'include_hostname',
        'remote_forwarding'
    ]

    updatables = [
        'tls',
        'ca_bundles',
        'servers',
        'include_hostname',
        'remote_forwarding'
    ]


class ApiParameters(Parameters):
    @property
    def servers(self):
        try:
            result_set = []
            for server in self._values["servers"]:
                conf = server["config"]
                server_conf = {
                    'address': conf["host"],
                    'port': conf["remote-port"],
                    'protocol': conf["f5-openconfig-system-logging:proto"]
                }
                if 'f5-openconfig-system-logging:authentication' in conf:
                    server_conf['authentication'] = conf['f5-openconfig-system-logging:authentication']['enabled']
                else:
                    server_conf['authentication'] = None
                if 'selectors' in server:
                    server_conf['logs'] = list()
                    for selector in server['selectors']['selector']:
                        log_conf = {
                            'facility': selector['facility'].split(":")[1].lower(),
                            'severity': selector['severity'].lower()
                        }
                        server_conf['logs'].append(log_conf)
                result_set.append(server_conf)
            return result_set
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def remote_forwarding(self):
        try:
            values = self._values['remote_forwarding']
            resultset = {
                'enabled': values['remote-forwarding']['enabled']
            }
            if 'selectors' in values:
                resultset['logs'] = list()
                for log in values['selectors']['selector']:
                    log_conf = {
                        'facility': log['facility'].split(":")[1].lower(),
                        'severity': log['severity'].lower()
                    }
                    resultset['logs'].append(log_conf)
            if 'files' in values:
                # no changes needed
                resultset['files'] = values['files']['file']
            return resultset
        except (TypeError, ValueError):
            return None

    @property
    def ca_bundles(self):
        try:
            resultset = list()
            for bundle in self._values['ca_bundles']:
                resultset.append(bundle['config'])
            return resultset
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []


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
        want = getattr(self.want, param)
        try:
            have = getattr(self.have, param)
            if want != have:
                return want
        except AttributeError:
            return want


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
        if self.all_exist():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.any_exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.still_exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def any_exists(self):
        return self.exists(query='any')

    def all_exist(self):
        return self.exists(query='all')

    def still_exists(self):
        return self.exists(query='still')

    def exists(self, query=None):
        base_uri = '/openconfig-system:system/logging'

        if hasattr(self.want, 'servers') and self.want.servers is not None:
            for server in self.want.servers:
                uri = f'{base_uri}/remote-servers/remote-server="{server["address"]}"'
                response = self.client.get(uri)

                if response['code'] == 200:
                    if query in ['any', 'still']:
                        return True

                if response['code'] == 404:
                    if query in ['all']:
                        return False

                if response['code'] not in [200, 201, 202, 404]:
                    raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'include_hostname') and self.want.include_hostname is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:config'
            response = self.client.get(uri)

            if response['code'] not in [200, 404]:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'remote_forwarding') and self.want.remote_forwarding is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:host-logs'
            response = self.client.get(uri)

            if response['code'] != 200:
                # Host-logs always exists
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'tls') and self.want.tls is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:tls'
            response = self.client.get(uri)

            if response['code'] == 200:
                if query in ['any', 'still']:
                    return True
            elif response['code'] == 204:
                if query in ['all']:
                    return False
            else:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'ca_bundles') and self.want.ca_bundles is not None:
            for bundle in self.want.ca_bundles:
                uri = f'{base_uri}/f5-openconfig-system-logging:tls/ca-bundles/ca-bundle={bundle["name"]}'
                response = self.client.get(uri)

                if response['code'] == 200:
                    if query in ['any', 'still']:
                        return True
                elif response['code'] == 404:
                    if query in ['all']:
                        return False
                else:
                    raise F5ModuleError(response['contents'])

        if query == 'still':
            return False
        if query == 'any':
            if hasattr(self.want, 'include_hostname') and self.want.include_hostname is not None:
                return True
            else:
                return False
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        base_uri = '/openconfig-system:system/logging'

        if 'tls' in params and params['tls'] is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:tls'
            payload = {
                'f5-openconfig-system-logging:tls': params['tls']
            }
            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 204]:
                raise F5ModuleError(response['contents'])

        if 'ca_bundles' in params and params['ca_bundles'] is not None:
            for bundle in params['ca_bundles']:
                uri = f'{base_uri}/f5-openconfig-system-logging:tls/ca-bundles'
                payload = {
                    'ca-bundle': {
                        'name': bundle["name"],
                        'config': bundle
                    }
                }

                response = self.client.post(uri, data=payload)
                if response['code'] == 409:
                    # This object exists already, so override it
                    put_uri = f'{uri}/ca-bundle="{bundle["name"]}"'
                    response = self.client.put(put_uri, data=payload)

                if response['code'] not in [200, 201, 204]:
                    raise F5ModuleError(response['contents'])

        if 'remote_forwarding' in params and params['remote_forwarding'] is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:host-logs'
            payload = {
                'f5-openconfig-system-logging:host-logs': {
                    'config': dict()
                }
            }
            conf = payload['f5-openconfig-system-logging:host-logs']['config']
            conf['remote-forwarding'] = {
                'enabled': params['remote_forwarding']['enabled']
            }
            if 'logs' in params['remote_forwarding'] and params['remote_forwarding']['logs'] is not None:
                conf['selectors'] = {
                    'selector': list()
                }
                for log in params['remote_forwarding']['logs']:
                    log_conf = {
                        'facility': f'openconfig-system-logging:{log["facility"].upper()}',
                        'severity': log['severity'].upper()
                    }
                    conf['selectors']['selector'].append(log_conf)

            if 'files' in params['remote_forwarding'] and params['remote_forwarding']['files'] is not None:
                conf['files'] = {
                    'file': list()
                }
                for file in params['remote_forwarding']['files']:
                    file_conf = {
                        'name': file['name']
                    }
                    conf['files']['file'].append(file_conf)
            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 204]:
                raise F5ModuleError(response['contents'])

        if 'servers' in params and params['servers'] is not None:
            for server in params['servers']:
                uri = f'{base_uri}/remote-servers/'
                payload = {
                    'remote-server': list()
                }
                server_list = payload['remote-server']
                server_conf = {
                    'host': server['address'],
                    'config': {
                        'host': server['address'],
                        'remote-port': server['port'],
                        'f5-openconfig-system-logging:proto': server['protocol']
                    }
                }
                if 'authentication' in server and server['authentication'] is not None:
                    server_conf['config'] = {
                        'f5-openconfig-system-logging:authentication': {
                            'enabled': server['authentication']
                        }
                    }
                if 'logs' in server and server['logs'] is not None:
                    server_conf['selectors'] = {
                        'selector': list()
                    }
                    for log in server['logs']:
                        log_conf = {
                            'facility': f'f5-system-logging-types:{log["facility"].upper()}',
                            'severity': log['severity'].upper(),
                            'config': {
                                'facility': f'f5-system-logging-types:{log["facility"].upper()}',
                                'severity': log['severity'].upper(),
                            }
                        }
                        server_conf['selectors']['selector'].append(log_conf)
                server_list.append(server_conf)

                response = self.client.post(uri, data=payload)
                if response['code'] == 409:
                    # This object exists already, so override it
                    put_uri = f'{uri}/remote-server="{server["address"]}"'
                    response = self.client.put(put_uri, data=payload)

                if response['code'] not in [200, 201, 204]:
                    raise F5ModuleError(response['contents'])

        if 'include_hostname' in params and params['include_hostname'] is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:config'
            payload = {
                'f5-openconfig-system-logging:config': {
                    'include-hostname': params['include_hostname']
                }
            }
            response = self.client.put(uri, data=payload)

            if response['code'] not in [200, 201, 204]:
                raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        params = self.changes.api_params()
        base_uri = '/openconfig-system:system/logging'

        if 'tls' in params and params['tls'] is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:tls'
            payload = {
                'f5-openconfig-system-logging:tls': params['tls']
            }

            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 204]:
                raise F5ModuleError(response['contents'])

        if 'ca_bundles' in params and params['ca_bundles'] is not None:
            for bundle in params['ca_bundles']:
                uri = f'{base_uri}/f5-openconfig-system-logging:tls/ca-bundles/ca-bundle="{bundle["name"]}"'
                payload = {
                    'ca-bundle': {
                        'name': bundle["name"],
                        'config': bundle
                    }
                }

                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 201, 204]:
                    raise F5ModuleError(response['contents'])

        if 'remote_forwarding' in params and params['remote_forwarding'] is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:host-logs/config'
            payload = {
                'f5-openconfig-system-logging:config' : dict()
            }
            conf = payload['f5-openconfig-system-logging:config']
            conf['remote-forwarding'] = {
                'enabled': params['remote_forwarding']['enabled']
            }
            if 'logs' in params['remote_forwarding'] and params['remote_forwarding']['logs'] is not None:
                conf['selectors'] = {
                    'selector': list()
                }
                for log in params['remote_forwarding']['logs']:
                    log_conf = {
                        'facility': f'openconfig-system-logging:{log["facility"].upper()}',
                        'severity': log['severity'].upper()
                    }
                    conf['selectors']['selector'].append(log_conf)

            if 'files' in params['remote_forwarding'] and params['remote_forwarding']['files'] is not None:
                conf['files'] = {
                    'file': list()
                }
                for file in params['remote_forwarding']['files']:
                    file_conf = {
                        'name': file['name']
                    }
                    conf['files']['file'].append(file_conf)

            response = self.client.put(uri, data=payload)
            if response['code'] not in [200, 204]:
                raise F5ModuleError(response['contents'])

        if 'servers' in params and params['servers'] is not None:
            uri = f'{base_uri}/remote-servers'
            payload = {
                'openconfig-system:remote-servers': {
                    'remote-server': list()
                }
            }
            server_list = payload['openconfig-system:remote-servers']['remote-server']
            for server in params['servers']:
                server_conf = {
                    'host': server['address'],
                    'config': {
                        'host': server['address'],
                        'remote-port': server['port'],
                        'f5-openconfig-system-logging:proto': server['protocol']
                    }
                }

                if 'authentication' in server and server['authentication'] is not None:
                    server_conf['config'] = {
                        'f5-openconfig-system-logging:authentication': {
                            'enabled': server['authentication']
                        }
                    }

                if 'logs' in server and server['logs'] is not None:
                    server_conf['selectors'] = {
                        'selector': list()
                    }
                    for log in server['logs']:
                        log_conf = {
                            'facility': f'f5-system-logging-types:{log["facility"].upper()}',
                            'severity': log['severity'].upper(),
                            'config': {
                                'facility': f'f5-system-logging-types:{log["facility"].upper()}',
                                'severity': log['severity'].upper(),
                            }
                        }
                        server_conf['selectors']['selector'].append(log_conf)
                server_list.append(server_conf)

                response = self.client.put(uri, data=payload)
                if response['code'] not in [200, 204]:
                    raise F5ModuleError(response['contents'])

        if 'include_hostname' in params and params['include_hostname'] is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:config'
            payload = {
                'f5-openconfig-system-logging:config': {
                    'include-hostname': params['include_hostname']
                }
            }
            response = self.client.put(uri, data=payload)

            if response['code'] not in [200, 201, 204]:
                raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        base_uri = '/openconfig-system:system/logging'

        if hasattr(self.want, 'servers') and self.want.servers is not None:
            for server in self.want.servers:
                uri = f'{base_uri}/remote-servers/remote-server="{server["address"]}"'
                response = self.client.delete(uri)

                if response['code'] not in [200, 204, 404]:
                    raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'include_hostname') and self.want.include_hostname is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:config'
            response = self.client.delete(uri)

            if response['code'] not in [200, 204, 404]:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'remote_forwarding') and self.want.remote_forwarding is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:host-logs'
            response = self.client.delete(uri)

            if response['code'] not in [200, 204, 404]:
                raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'tls') and self.want.tls is not None:
            for attribute in ['certificate', 'key']:
                uri = f'{base_uri}/f5-openconfig-system-logging:tls/{attribute}'
                response = self.client.delete(uri)

                if response['code'] not in [200, 204, 404]:
                    raise F5ModuleError(response['contents'])

        if hasattr(self.want, 'ca_bundles') and self.want.ca_bundles is not None:
            for bundle in self.want.ca_bundles:
                uri = f'{base_uri}/f5-openconfig-system-logging:tls/ca-bundles/ca-bundle={bundle["name"]}'
                response = self.client.delete(uri)

                if response['code'] not in [200, 204, 404]:
                    raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        params = dict()
        base_uri = '/openconfig-system:system/logging'

        # Servers
        if hasattr(self.want, 'servers') and self.want.servers is not None:
            params['servers'] = list()
            for server in self.want.servers:
                uri = f'{base_uri}/remote-servers/remote-server="{server["address"]}"'
                server_response = self.client.get(uri)
                if server_response['code'] == 404:
                    continue
                elif server_response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(server_response['contents']['openconfig-system:remote-server'])
                else:
                    params['servers'] = params['servers'] + (server_response['contents']['openconfig-system:remote-server'])

        # include hostname
        if hasattr(self.want, 'include_hostname') and self.want.include_hostname is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:config'
            response = self.client.get(uri)

            if response['code'] not in [200, 404]:
                raise F5ModuleError(response['contents'])
            if response['code'] == 200:
                params['include_hostname'] = response['contents']['f5-openconfig-system-logging:config']['include-hostname']

        # Remote Forwarding
        if hasattr(self.want, 'remote_forwarding') and self.want.remote_forwarding is not None:
            uri = f'{base_uri}/f5-openconfig-system-logging:host-logs'
            response = self.client.get(uri)

            if response['code'] != 200:
                raise F5ModuleError(response['contents'])
            else:
                params['remote_forwarding'] = response['contents']['f5-openconfig-system-logging:host-logs']['config']

        # TLS Cert, Key and CA bundles
        if (hasattr(self.want, 'tls') and self.want.tls is not None) or \
                (hasattr(self.want, 'ca_bundles') and self.want.ca_bundles is not None):
            uri = f'{base_uri}/f5-openconfig-system-logging:tls'
            response = self.client.get(uri)

            if response['code'] != 200:
                raise F5ModuleError(response['contents'])

            content = response['contents']['f5-openconfig-system-logging:tls']
            if 'certificate' in content or 'key' in content:
                tls = content.copy()
                del tls['ca-bundles']
                params['tls'] = tls
            if 'ca-bundles' in content:
                ca_bundles = content['ca-bundles']['ca-bundle']
                params['ca_bundles'] = ca_bundles

        return ApiParameters(params=params)


class ArgumentSpec(object):
    severities = ['debug', 'informational', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency']

    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            servers=dict(
                type='list',
                elements='dict',
                options=dict(
                    address=dict(type='str'),
                    port=dict(type='int'),
                    protocol=dict(
                        type='str',
                        choices=['tcp', 'udp']
                    ),
                    authentication=dict(type='bool'),
                    logs=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            facility=dict(type='str'),
                            severity=dict(
                                type='str',
                                choices=ArgumentSpec.severities
                            )
                        )
                    )
                )
            ),
            remote_forwarding=dict(
                type='dict',
                options=dict(
                    enabled=dict(type='bool'),
                    logs=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            facility=dict(type='str'),
                            severity=dict(
                                type='str',
                                choices=ArgumentSpec.severities
                            )
                        )
                    ),
                    files=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            name=dict(type='str')
                        )
                    )
                )
            ),
            include_hostname=dict(
                type='bool'
            ),
            tls=dict(
                type='dict',
                options=dict(
                    certificate=dict(type='str'),
                    key=dict(
                        type='str',
                        no_log=True
                    )
                )
            ),
            ca_bundles=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str'),
                    content=dict(type='str')
                )
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
