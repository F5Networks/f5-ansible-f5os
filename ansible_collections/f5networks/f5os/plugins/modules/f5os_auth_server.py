#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_auth_server
short_description: Manage Auth Server Groups and Server inside it.
description:
  - Manage  Auth Server Groups and Server inside it on F5OS based systems.
version_added: "1.15.0"
options:
  name:
    description:
      - Name of the Server Group.
    type: str
    required: true
  provider_type:
    description:
      - Name of the Provider Type.
    type: str
    required: true
    choices:
      - tacacs
      - radius
      - ldap
      - ocsp
  server:
    description:
      - Server
    type: list
    elements: dict
    suboptions:
        server_ip:
            description:
                - Server IP/Address.
            type: str
        port:
            description:
                - Port number to be used for Server.
            type: int
        type:
            description:
                - Options are LDAP over TCP or LDAP over SSL (requires SSL certificate) depending on which protocol the LDAP server uses.
            type : str
            choices:
                - ldap over tcp
                - ldap over ssl
        secret:
            description:
                - Secret key is the shared secret used to access the server.
            type : str
        timeout:
            description:
                - Timeout specifies seconds to wait for a response from the server.
            type : int
  force_update:
    description:
        - If C(true), Update will be triggered forcefully irrespective of any changes.
    type: bool
    default: false
  state:
    description:
      - Server Group and Servers state of F5OS system.
      - If C(present), Specified Server Groups and Server will be pushed to F5OS system.
      - If C(absent), deletes the Server Group and Servers if they exists.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - Server IP, Secret, Port and Timeout are required for Radius Server Group.
  - Server IP, Secret, Port are required for Tacacs Server Group.
  - Changes in Secret Key for Radius and Tacacs Server Group are not detected, so we need to force update in that case.
  - Server IP, Port and Type are required for LDAP Server Group.
  - User needs to specify which all servers are to be kept, rest will be deleted.
  - If not servers are specified, then all the servers would be deleted.
author:
  - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''
- name: Create Radius Server Group and Servers inside it
  f5os_auth_server:
    name: "test_server"
    provider_type: "radius"
    server:
      - server_ip: "1.1.1.1"
        port: 1000
        secret: "test"
        timeout: 5

- name: Create Tacacs Server Group and Servers inside it
  f5os_auth_server:
    name: "test_server"
    provider_type: "radius"
    server:
      - server_ip: "1.1.1.1"
        port: 1000
        secret: "test"

- name: Create Ldap Server Group and Servers inside it
  f5os_auth_server:
    name: "test_server"
    provider_type: "ldap"
    server:
      - server_ip: "1.1.1.1"
        port: 1000
        type: "ldap over tcp"

- name: Create Ocsp Server Group and Servers inside it
  f5os_auth_server:
    name: "test_server"
    provider_type: "ocsp"
    server:
      - server_ip: "1.1.1.1"
        port: 1000

- name: Delete Ocsp Server Group and Servers inside it
  f5os_auth_server:
    name: "test_server"
    provider_type: "ocsp"
    server:
      - server_ip: "1.1.1.1"
        port: 1000
    state: "absent"
'''

RETURN = r'''
name:
  description: Name of the Server Group.
  returned: changed
  type: str
provider_type:
  description: Name of the Provider Type.
  returned: changed
  type: str
server:
  description: Server to added for the Server Group
  returned: changed
  type: list
'''

import datetime
import copy

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
        'name',
        'provider_type',
        'server'
    ]

    returnables = [
        'name',
        'provider_type',
        'server'
    ]

    updatables = [
        'server'
    ]


class ApiParameters(Parameters):
    @property
    def server(self):
        result_server = []
        if 'server' in self._values:
            for x in self._values['server']:
                result_server.append(x)
        return result_server


class ModuleParameters(Parameters):
    @property
    def server(self):
        value = self._values.get('server')
        if value and isinstance(value, dict):
            return [value]
        return value

    # def server(self):
    #     if self._values.server is None:
    #         return []
    #     return self._values["server"]


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
        if hasattr(self, param):
            return getattr(self, param)
        else:
            return self.__default(param)

    def __default(self, param):
        want = getattr(self.want, param)
        if hasattr(self.have, param):
            have = getattr(self.have, param)
            if want != have:
                return want
        else:
            return want

    @property
    def server(self):
        if (self.want.server is None or len(self.want.server) == 0) and (self.have.server is None or len(self.have.server) == 0):
            return None
        if (self.want.server is None or len(self.want.server) == 0) and len(self.have.server) > 0:
            return {"server": []}
        if len(self.want.server) != len(self.have.server):
            return self.want.server

        for wserver in self.want.server:
            match = False
            for hserver in self.have.server:
                if wserver['server_ip'] == hserver['address']:
                    if self.want.provider_type == "radius":
                        if (hserver["radius"]["config"]["auth-port"] == wserver["port"] and
                                hserver["radius"]["config"]["f5-openconfig-aaa-radius:timeout"] == wserver["timeout"]):
                            match = True
                            break
                    elif self.want.provider_type == "tacacs":
                        if hserver["tacacs"]["config"]["port"] == wserver["port"]:
                            match = True
                            break
                    elif self.want.provider_type == "ldap":
                        if hserver["f5-openconfig-aaa-ldap:ldap"]["config"]["auth-port"] == wserver["port"]:
                            if hserver["f5-openconfig-aaa-ldap:ldap"]["config"]["type"] == "f5-openconfig-aaa-ldap:ldap" and wserver["type"] == "ldap over tcp":
                                match = True
                                break
                            elif (hserver["f5-openconfig-aaa-ldap:ldap"]["config"]["type"] == "f5-openconfig-aaa-ldap:ldaps" and
                                    wserver["type"] == "ldap over ssl"):
                                match = True
                                break
            if not match:
                return self.want.server

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
        '''Wrapper for creation/update'''
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        '''Wrapper for removal'''
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self) -> bool:
        '''Update object on F5OS system'''
        self.have = self.read_current_from_device()
        if not self.should_update() and not self.want.force_update:
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self) -> bool:
        '''Remove object from F5OS system'''
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")  # pragma: no cover
        return True

    def create(self) -> bool:
        '''Create object on F5OS system'''
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self) -> bool:
        '''Check object existance on F5OS system'''
        uri = f'/openconfig-system:system/aaa/server-groups/server-group="{self.want.name}"'
        response = self.client.get(uri)

        if response['code'] == 200:
            if self.want.provider_type not in response["contents"]["openconfig-system:server-group"][0]["config"]["type"].lower():  # pragma: no cover
                existing_provider_type = response["contents"]["openconfig-system:server-group"][0]["config"]["type"]
                raise F5ModuleError(response['Server Group Already exists with provider type ' + existing_provider_type])  # pragma: no cover
            return True

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:  # pragma: no cover
            raise F5ModuleError(response['contents'])  # pragma: no cover

        return False

    def create_on_device(self):
        '''API communication to actually create the objects on the F5OS system'''
        params = self.changes.api_params()
        #  Post Server Groups
        base_uri = "/openconfig-system:system/aaa/server-groups"
        payload = {"openconfig-system:server-group": {}}

        config = {}
        config["name"] = params["name"]
        if params["provider_type"] == "radius":
            config["type"] = "openconfig-aaa:RADIUS"
        elif params["provider_type"] == "tacacs":
            config["type"] = "openconfig-aaa:TACACS"
        elif params["provider_type"] == "ldap":
            config["type"] = "f5-openconfig-aaa-ldap:LDAP"

        payload["openconfig-system:server-group"]["name"] = params["name"]
        payload["openconfig-system:server-group"]["config"] = config
        response = self.client.post(base_uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:  # pragma: no cover
            raise F5ModuleError(response['contents'])  # pragma: no cover

        # Post Servers
        if "server" in params:
            self.update_servers(params)

        return True

    def update_on_device(self):
        '''API communication to actually update the objects on the F5OS system'''
        params = self.changes.api_params()
        if "server" in params:
            self.update_servers(params)
        return True

    def update_servers(self, params):
        base_uri = "/openconfig-system:system/aaa/server-groups"
        payload = {"openconfig-system:servers": {"server": []}}
        servers = []

        for server in params["server"]:
            server_object = {}
            if self.want.provider_type == "radius":
                if server['port'] is None or server['secret'] is None or server['timeout'] is None:
                    raise F5ModuleError("Port, Secret and Timeout are required for Provider Type Radius")  # pragma: no cover
                radius = {
                    "config": {
                        "auth-port": server["port"],
                        "secret-key": server["secret"],
                        "f5-openconfig-aaa-radius:timeout": server["timeout"]
                    }
                }
                server_object["radius"] = radius
                server_object["address"] = server["server_ip"]
                server_object["config"] = {"address": server["server_ip"]}
            elif self.want.provider_type == "tacacs":
                if server['port'] is None or server['secret'] is None:
                    raise F5ModuleError("Port and Secret are required for Provider Type Tacacs")  # pragma: no cover
                tacacs = {
                    "config": {
                        "port": server["port"],
                        "secret-key": server["secret"]
                    }
                }
                server_object["tacacs"] = tacacs
                server_object["address"] = server["server_ip"]
                server_object["config"] = {"address": server["server_ip"]}
            elif self.want.provider_type == "ldap":
                if server['port'] is None or server['type'] is None:
                    raise F5ModuleError("Port and Type are required for Provider Type LDAP")  # pragma: no cover
                ldap = {
                    "config": {
                        "auth-port": server["port"],
                    }
                }
                if server["type"] == "ldap over ssl":
                    ldap["config"]["type"] = "f5-openconfig-aaa-ldap:ldaps"
                else:
                    ldap["config"]["type"] = "f5-openconfig-aaa-ldap:ldap"
                server_object["f5-openconfig-aaa-ldap:ldap"] = ldap
                server_object["address"] = server["server_ip"]
                server_object["config"] = {"address": server["server_ip"]}
            servers.append(copy.deepcopy(server_object))

        payload["openconfig-system:servers"]["server"] = servers
        uri = f"{base_uri}/server-group={self.want.name}/servers/"
        response = self.client.put(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        '''API communication to actually remove the objects on the F5OS system'''
        base_uri = "/openconfig-system:system/aaa/server-groups"
        uri = f"{base_uri}/server-group={self.want.name}"

        response = self.client.delete(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])  # pragma: no cover
        return True

    def read_current_from_device(self):
        '''API communication to read the objects on the F5OS system'''
        uri = "/openconfig-system:system/aaa/server-groups/server-group=" + self.want.name + "/servers/"

        response = self.client.get(uri)
        if 'openconfig-system:servers' in response['contents']:
            return_object = response['contents']['openconfig-system:servers']
        else:
            return_object = None

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])  # pragma: no cover
        return ApiParameters(params=return_object)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(type='str', required=True),
            force_update=dict(
                type='bool',
                default=False),
            provider_type=dict(
                type='str',
                required=True,
                choices=['ldap', 'ocsp', 'radius', 'tacacs']),
            server=dict(
                type='list',
                elements='dict',
                options=dict(
                    server_ip=dict(type='str'),
                    port=dict(type='int'),
                    secret=dict(type='str', no_log=True),
                    type=dict(
                        type='str',
                        choices=['ldap over tcp', 'ldap over ssl']
                    ),
                    timeout=dict(type='int')
                ),
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = []
        self.required_one_of = []


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_one_of=spec.required_one_of,
        mutually_exclusive=spec.mutually_exclusive
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
