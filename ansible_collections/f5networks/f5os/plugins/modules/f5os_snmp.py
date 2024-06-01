#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_snmp
short_description: Manage SNMP Communities, Users, and Targets using openAPI on F5OS based systems
description:
  - Manage SNMP Communities, Users, and Targets using openAPI on F5OS based systems.
version_added: "1.9.0"
options:
  snmp_community:
    description:
      - Specifies SNMP Community options to be configured on system
      - This parameter is required when creating a resource.
      - It is List of community options to be configured
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - Unique name for snmp community
            type: str
            required: true
        security_model:
            description:
                - Short description of the rule's purpose.
            type: list
            elements: str
  snmp_target:
    description:
      - Specifies SNMP targets options to be configured on system
      - It is List of community options to be configured
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - Unique name for snmp target
            type: str
            required: true
        security_model:
            description:
                - Security model to be configure on snmp target
            type: str
            required: true
        community:
            description:
                - SNMP community name to be configure on snmp target
            type: str
            required: true
        ipv4_address:
            description:
                - IPv4 address to be configured on SNMP target config
            type: str
        ipv6_address:
            description:
                - IPv6 address to be configured on SNMP target config
            type: str
        port:
            description:
                - Port number to used for snmp taget config ipv4/ipv6 address
            type: int
            required: true
  state:
    description:
      - snmp configuration state of F5OS system
      - If C(present), Specified snmp configuration will be pushed to F5OS system.
      - If C(absent), deletes the snmp configuration if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''
- name: Create SNMP Config
  f5os_snmp:
    snmp_community:
      - name: test2_com
        security_model: ['v1', 'v2c']
    snmp_target:
      - name: v1_target
        security_model: v1
        ipv4_address: 10.144.140.17
        port: 5045
        community: test2_com

- name: Update SNMP Config
  f5os_snmp:
    snmp_community:
      - name: test2_com
        security_model: ['v1', 'v2c']
      - name: test3_com
        security_model: ['v1', 'v2c']
    snmp_target:
      - name: v1_target
        security_model: v1
        ipv4_address: 10.144.140.17
        port: 5045
        community: test2_com

- name: Delete SNMP Config
  f5os_snmp:
    snmp_community:
      - name: test2_com
        security_model: ['v1', 'v2c']
      - name: test3_com
        security_model: ['v1', 'v2c']
    snmp_target:
      - name: v1_target
        security_model: v1
        ipv4_address: 10.144.140.17
        port: 5045
        community: test2_com
    state: absent
'''

RETURN = r'''
snmp_community:
  description: Specifies SNMP Community options to be configured on system.
  returned: changed
  type: list
snmp_target:
  description: Specifies SNMP targets options to be configured on system.
  returned: changed
  type: list
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
    api_map = {
    }

    api_attributes = [
        'snmp_user',
        'snmp_target',
        'snmp_community',
    ]

    returnables = [
        'snmp_user',
        'snmp_target',
        'snmp_community',
    ]

    updatables = [
        'snmp_user',
        'snmp_target',
        'snmp_community',
    ]


class ApiParameters(Parameters):
    @property
    def snmp_community(self):
        if 'communities' in self._values:
            result_community = []
            for x in self._values['communities']['community']:
                result_community.append(x['config'])
            return result_community

    @property
    def snmp_target(self):
        if 'targets' in self._values:
            result = {}
            result_targets = []
            for x in self._values['targets']['target']:
                result_targets.append(x['config'])
            return result_targets


class ModuleParameters(Parameters):
    @property
    def snmp_community(self):
        if self._values['snmp_community'] is None:
            return None
        return self._values['snmp_community']

    @property
    def snmp_target(self):
        if self._values['snmp_target'] is None:
            return None
        return self._values['snmp_target']


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
    def snmp_community(self):
        if self._values['snmp_community'] is None:
            return None
        snmp_community = []
        for val in self._values['snmp_community']:
            if val['security_model'] is None:
                val['security_model'] = "v1"
            result = {
                'name': val['name'],
                'config': {
                    'security-model': val['security_model'],
                    'name': val['name'],
                }
            }
            snmp_community.append(result)
        return snmp_community

    @property
    def snmp_target(self):
        if self._values['snmp_target'] is None:
            return None
        snmp_targets = []
        snmp_target = dict()
        for val in self._values['snmp_target']:
            if val['security_model'] is None:
                val['security_model'] = "v1"
            target_config = dict()
            target_config['name'] = val['name']
            target_config['security-model'] = val['security_model']
            target_config['community'] = val['community']
            if val['ipv4_address'] is not None:
                ipv4_dict = {
                    'address': val['ipv4_address'],
                    'port': val['port'],
                }
                target_config['ipv4'] = ipv4_dict
            snmp_target['config'] = target_config
            snmp_target['name'] = val['name']
            snmp_targets.append(snmp_target)
        return snmp_targets


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

    @property
    def snmp_community(self):
        for index in range(len(self.want.snmp_community)):
            if self.want.snmp_community[index]['security_model'] == self.have.snmp_community[index]['security-model']:
                return None
            return self.want.snmp_community[index]['security_model']


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

        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
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
        if self.exists():
            return self.update()
        else:
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
        for val in self.want.snmp_community:
            uri = f"/openconfig-system:system/f5-system-snmp:snmp/communities/community={val['name']}"
            response = self.client.get(uri)
            if response['code'] == 404:
                return False
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

        if self.want.snmp_target is not None:
            for val in self.want.snmp_target:
                uri = f"/openconfig-system:system/f5-system-snmp:snmp/targets/target={val['name']}"
                response = self.client.get(uri)
                if response['code'] == 404:
                    return False
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        # Adding SNMP Community config
        snmpconfig = dict()
        if 'snmp_community' in params and params['snmp_community'] is not None:
            communityparams = {'community': params['snmp_community']}
            snmpconfig['communities'] = communityparams
        if 'snmp_target' in params and params['snmp_target'] is not None:
            targetparams = {'target': params['snmp_target']}
            snmpconfig['targets'] = targetparams
        payload = {"f5-system-snmp:snmp": snmpconfig}
        uri = "/openconfig-system:system/f5-system-snmp:snmp"
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        # if 'snmp_community' in params and params['snmp_community'] is not None:
        #     communityparams = {'community': params['snmp_community']}
        #     snmpconfig['communities']=communityparams
        # payload = {"f5-system-snmp:snmp": snmpconfig}
        # q("payload:{}".format(payload))
        # uri = "/openconfig-system:system/f5-system-snmp:snmp"
        # response = self.client.patch(uri, data=payload)
        # if response['code'] not in [200, 201, 202, 204]:
        #     raise F5ModuleError(response['contents'])
        # # Adding SNMP targets config
        # snmpconfig = dict()
        # if 'snmp_target' in params and params['snmp_target'] is not None:
        #     targetparams = {'target': params['snmp_target']}
        #     snmpconfig['targets']=targetparams
        #     payload = {"f5-system-snmp:snmp": snmpconfig}
        #     q("payload:{}".format(payload))
        #     uri = "/openconfig-system:system/f5-system-snmp:snmp"
        #     response = self.client.patch(uri, data=payload)
        #     if response['code'] not in [200, 201, 202, 204]:
        #         raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        snmpconfig = dict()
        if 'snmp_community' in params and params['snmp_community'] is not None:
            communityparams = {'community': params['snmp_community']}
            snmpconfig['communities'] = communityparams
        if 'snmp_target' in params and params['snmp_target'] is not None:
            targetparams = {'target': params['snmp_target']}
            snmpconfig['targets'] = targetparams
        payload = {"f5-system-snmp:snmp": snmpconfig}
        uri = "/openconfig-system:system/f5-system-snmp:snmp"
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        if self.want.snmp_target is not None:
            for val in self.want.snmp_target:
                uri = f"/openconfig-system:system/f5-system-snmp:snmp/targets/target={val['name']}"
                response = self.client.delete(uri)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(response['contents'])
        for val in self.want.snmp_community:
            uri = f"/openconfig-system:system/f5-system-snmp:snmp/communities/community={val['name']}"
            response = self.client.delete(uri)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        uri = "/openconfig-system:system/f5-system-snmp:snmp"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents']['f5-system-snmp:snmp'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            # snmp_user=dict(
            #     type='list',
            #     elements='dict',
            #     options=dict(
            #         name=dict(required=True),
            #         auth_proto=dict(type='str'),
            #         auth_passwd=dict(type='str'),
            #         privacy_proto=dict(type='str'),
            #         privacy_passwd=dict(type='str'),
            #     )
            # ),
            snmp_community=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    security_model=dict(type='list',
                                        elements='str'),
                )
            ),
            snmp_target=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    security_model=dict(type='str',
                                        required=True),
                    community=dict(type='str',
                                   required=True),
                    ipv4_address=dict(type='str'),
                    port=dict(type='int',
                              required=True),
                    ipv6_address=dict(type='str'),
                )
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_one_of = [('snmp_community', 'snmp_target')]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
