#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_dns
short_description: Manage DNS on F5OS Devices
description:
  - Manage DNS Resolver Config Domains and Servers
version_added: "1.8.0"
options:
  dns_servers:
    description:
      - Specifies List of the DNS servers that the resolver should query.
      - This parameter is required when creating a resource.
    required: True
    type: list
    elements: str
  dns_domains:
    description:
      - An ordered list of domains to search when resolving a host name.
    type: list
    elements: str
  state:
    description:
      - The sytem controller DNS config state.
      - If C(present), creates the specified DNS Servers and Domains if it does not exist.
      - If C(absent), deletes the VLAN if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy (@chinthalapalli)
notes:
  - This Modules will only make patch calls to add the DNS servers and domains.
  - It does not support the deletion of difference DNS servers and domains from the existing list while updating,it just adds new entries.
  - When state is C(absent) it will B(delete) the DNS servers and domains from the user provided list.
'''

EXAMPLES = r'''
- name: Create DNS Resolver config on controller
  f5os_dns:
    dns_servers:
      - "10.10.10.10"
      - "10.10.10.11"
      - "10.10.10.12"
    dns_domains:
      - "test-domain1.com"
      - "test-domain2.com"
      - "test-domain3.com"

- name: Delete DNS Resolver config on controller
  f5os_dns:
    dns_servers:
      - "10.10.10.10"
      - "10.10.10.11"
      - "10.10.10.12"
    dns_domains:
      - "test-domain1.com"
      - "test-domain2.com"
      - "test-domain3.com"
    state: absent
'''

RETURN = r'''
dns_servers:
  description: List of the DNS servers that the resolver should query.
  returned: changed
  type: list
  sample: ["10.10.10.13","10.10.10.14"]
dns_domains:
  description: The ID of the VLAN.
  returned: changed
  type: list
  sample: ["test-domain2.com"]
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

    api_attributes = [
        'dns_config'
    ]

    returnables = [
        'dns_servers',
        'dns_domains',
    ]

    updatables = [
        'dns_servers',
        'dns_domains',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def dns_servers(self):
        result = self._values['dns_servers']
        if result is None:
            return None
        if isinstance(result, list):
            return result
        if isinstance(result, str):
            return [result]
        return result

    @property
    def dns_domains(self):
        if self._values['dns_domains'] is None:
            return None
        result = self._values['dns_domains']
        if isinstance(result, list):
            return result
        if isinstance(result, str):
            return [result]
        return result


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
    @property
    def dns_config(self):
        if self._values['dns_servers'] is None:
            return None
        dns_server_config = dict()
        dns_domain_config = dict()
        if isinstance(self._values['dns_servers'], list):
            dns_servers_list = []
            for server in self._values['dns_servers']:
                dns_servers = dict()
                dns_servers["address"] = server
                dns_servers_list.append(dns_servers)
            dns_server_config['server'] = dns_servers_list
        if isinstance(self._values['dns_domains'], list):
            dns_domain_config["search"] = self._values["dns_domains"]
        dns_config = {'openconfig-system:dns': {'servers': dns_server_config, 'config': dns_domain_config}}
        return dns_config


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

    def _update_changed_options(self):  # pragma: no cover
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
        if not self.exists():
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
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
        if self.want.dns_servers is None and self.want.dns_domains is None:
            return False
        if self.want.dns_servers is not None:
            for server in self.want.dns_servers:
                uri = f"/openconfig-system:system/dns/servers/server={server}"
                response = self.client.get(uri)
                if response['code'] == 404:
                    return False
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        if self.want.dns_domains is not None:
            for domains in self.want.dns_domains:
                uri = f"/openconfig-system:system/dns/config/search={domains}"
                response = self.client.get(uri)
                if response['code'] == 404:
                    return False
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        # we use name parameter separately in UsableChanges
        uri = "/openconfig-system:system/dns"
        response = self.client.patch(uri, data=params['dns_config'])
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        for server in self.want.dns_servers:
            uri = f"/openconfig-system:system/dns/servers/server={server}"
            response = self.client.delete(uri)
            if response['code'] == 404:
                return False
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
        for domains in self.want.dns_domains:
            uri = f"/openconfig-system:system/dns/config/search={domains}"
            response = self.client.delete(uri)
            if response['code'] == 404:
                return False
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            dns_servers=dict(type='list', elements='str', required=True),
            dns_domains=dict(type='list', elements='str'),
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
