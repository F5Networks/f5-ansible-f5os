#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: f5os_facts
short_description: Collect facts from F5OS devices
description:
  - Collects facts from F5OS devices via the REST API.
  - This module is invoked automatically during the C(Gathering Facts) play task
    when C(ansible_network_os) is set to C(f5networks.f5os.f5os).
version_added: "1.14.0"
options:
  gather_subset:
    description:
      - Restricts the facts collected to a given subset.
      - Use C(min) or C(default) for basic platform and version info.
      - Use C(all) to collect all available facts.
    type: list
    elements: str
    default:
      - default
author:
  - F5 Networks (@f5networks)
notes:
  - Tested against F5OS-A and F5OS-C.
'''

EXAMPLES = r'''
- name: Gather default facts
  f5networks.f5os.f5os_facts:

- name: Gather all facts
  f5networks.f5os.f5os_facts:
    gather_subset:
      - all
'''

RETURN = r'''
ansible_net_platform:
  description: Platform type of the F5OS device.
  returned: always
  type: str
  sample: rSeries Platform
ansible_net_version:
  description: Software version running on the device.
  returned: when available
  type: str
  sample: 1.8.0-13846
ansible_net_gather_subset:
  description: The list of fact subsets collected from the device.
  returned: always
  type: list
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.f5networks.f5os.plugins.module_utils.client import F5Client
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)

    def exec_module(self):
        facts = {}
        gather_subset = self.module.params['gather_subset']

        facts['gather_subset'] = gather_subset

        platform = self.client.platform
        if platform:
            facts['platform'] = platform

        try:
            version = self.client.software_version
            if version:
                facts['version'] = version
        except (AttributeError, KeyError):
            self.module.warn('Unable to retrieve software version from device')

        ansible_facts = {}
        for key, value in facts.items():
            ansible_facts['ansible_net_%s' % key] = value

        return ansible_facts


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            gather_subset=dict(
                type='list',
                elements='str',
                default=['default'],
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
        ansible_facts = mm.exec_module()
        module.exit_json(ansible_facts=ansible_facts)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
