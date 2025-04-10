#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_license
short_description: Manage F5OS license activation and deactivation.
description:
  - Manage F5OS license activation and deactivation.
version_added: "1.10.0"
options:
  registration_key:
    description:
      - Specifies Base registration key from a license server for the device license activation.
      - This parameter is required when activating a device license.
    required: True
    type: str
  addon_keys:
    description:
      - Specifies additional registration keys from a license server for the device license activation.
      - This parameter is optional when activating a device license.
    type: list
    elements: str
  license_server:
    description:
      - Specifies the license server URL.
    type: str
    default: activate.f5.com
  state:
    description:
      - F5OS license activation state.
      - If C(present), Specified F5OS license activation with the provided registration key.
      - If C(absent), Deactivate the F5OS license, but it is B(not supported for F5OS devices).
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - License deactivation/Revokation is not supported for F5OS devices/not supported in this module.
  - This module supports only automatic license activation using the registration key.
  - license can't be installed on Standby
author:
  - Ravinder Reddy (@chinthalapalli)
'''

EXAMPLES = r'''

- name: License activation with registration key on F5OS device
  f5os_license:
    registration_key: xxxxx-1xxx5-3xxx4-0xxx8-4xxxxx7
    state: present

- name: License activation with registration key and addon keys on F5OS device
  f5os_license:
    registration_key: xxxxx-1xxx5-3xxx4-0xxx8-4xxxxx7
    addon_keys:
      - xxxxx-1xxx5
      - xxxxx-2xxx5
'''

RETURN = r'''
registration_key:
  description: Specifies Base registration key from a license server for the device license activation
  returned: changed
  type: str
  sample: "xxxxx-1xxx5-3xxx4-0xxx8-4xxxxx7"
addon_keys:
  description: Specifies additional registration keys from a license server for the device license activation
  returned: changed
  type: list
  sample: ["xxxxx-1xxx5", "xxxxx-1xxx5"]
'''

import datetime
import re

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
        'registration_key',
        'addon_keys'
    ]

    returnables = [
        'registration_key',
        'addon_keys'
    ]

    updatables = [
        'registration_key',
        'addon_keys'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def registration_key(self):
        result = self._values['registration_key']
        if result is None:
            return None
        return result

    @property
    def addon_keys(self):
        if self._values['registration_key'] is None:
            return None
        if self._values['addon_keys'] is None or len(self._values['addon_keys']) == 0:
            return None
        result = self._values['addon_keys']
        return result

    @property
    def license_options(self):
        result = dict(
            eula=self.eula or '',
            email=self.email or '',
            first_name=self.first_name or '',
            last_name=self.last_name or '',
            company=self.company or '',
            phone=self.phone or '',
            job_title=self.job_title or '',
            address=self.address or '',
            city=self.city or '',
            state=self.state or '',
            postal_code=self.postal_code or '',
            country=self.country or ''
        )
        return result

    @property
    def license_url(self):
        result = 'https://{0}/license/services/urn:com.f5.license.v5b.ActivationService'.format(self.license_server)
        return result

    @property
    def license_envelope(self):
        result = """<?xml version="1.0" encoding="UTF-8"?>
        <SOAP-ENV:Envelope xmlns:ns3="http://www.w3.org/2001/XMLSchema"
                           xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                           xmlns:ns0="http://schemas.xmlsoap.org/soap/encoding/"
                           xmlns:ns1="https://{0}/license/services/urn:com.f5.license.v5b.ActivationService"
                           xmlns:ns2="http://schemas.xmlsoap.org/soap/envelope/"
                           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                           xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                           SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
          <SOAP-ENV:Header/>
          <ns2:Body>
            <ns1:getLicense>
              <dossier xsi:type="ns3:string">{1}</dossier>
              <eula xsi:type="ns3:string">{eula}</eula>
              <email xsi:type="ns3:string">{email}</email>
              <firstName xsi:type="ns3:string">{first_name}</firstName>
              <lastName xsi:type="ns3:string">{last_name}</lastName>
              <companyName xsi:type="ns3:string">{company}</companyName>
              <phone xsi:type="ns3:string">{phone}</phone>
              <jobTitle xsi:type="ns3:string">{job_title}</jobTitle>
              <address xsi:type="ns3:string">{address}</address>
              <city xsi:type="ns3:string">{city}</city>
              <stateProvince xsi:type="ns3:string">{state}</stateProvince>
              <postalCode xsi:type="ns3:string">{postal_code}</postalCode>
              <country xsi:type="ns3:string">{country}</country>
            </ns1:getLicense>
          </ns2:Body>
        </SOAP-ENV:Envelope>"""
        result = result.format(self.license_server, self.dossier, **self.license_options)
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
        pass
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
        self.deactivate_license()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        return self.create_on_device()

    def exists(self):
        if self.want.registration_key is None:
            return False
        uri = "/openconfig-system:system/f5-system-licensing:licensing"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if 'registration-key' not in response['contents']['f5-system-licensing:licensing']['state']:
            return False
        if response['contents']['f5-system-licensing:licensing']['state']['registration-key']['base'] != self.want.registration_key:
            return False
        # Define a regex pattern to capture the License end date
        pattern = r"License end\s+(\d{4}/\d{2}/\d{2})"
        # Use re.search to find the License end date
        match = re.search(pattern, response['contents']['f5-system-licensing:licensing']['state']['license'])
        license_end_date = match.group(1) if match else None
        # Check if the License end date is found
        if license_end_date:
            # Convert the license end date to datetime object
            license_end = datetime.datetime.strptime(license_end_date, "%Y/%m/%d")
            # Get the current date
            current_date = datetime.datetime.now().date()
            # Check if the license has expired
            if license_end.date() < current_date:
                return False
            else:
                return True
        else:
            return True

    def get_dossier_device(self):
        uri = "/openconfig-system:system/f5-system-licensing:licensing/f5-system-licensing-install:get-dossier"
        dossier_payload = {
            "f5-system-licensing-install:registration-key": self.want.registration_key
        }
        response = self.client.post(uri, dossier_payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-licensing-install:output']['system-dossier']

    def get_eula(self):
        '''get the eula from the license server'''
        uri = "/openconfig-system:system/f5-system-licensing:licensing/f5-system-licensing-install:get-eula"
        license_payload = {
            "f5-system-licensing-install:registration-key": self.want.registration_key,
        }
        if self.want.addon_keys is not None:
            license_payload["f5-system-licensing-install:add-on-keys"] = self.want.addon_keys
        response = self.client.post(uri, license_payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if response['contents']['f5-system-licensing-install:output']['status'] == "eula-accepted":
            return True
        return False

    def create_on_device(self):
        '''Install the license on the device'''
        self.get_eula()
        uri = "/openconfig-system:system/f5-system-licensing:licensing/f5-system-licensing-install:install"
        license_payload = {
            "f5-system-licensing-install:registration-key": self.want.registration_key,
        }
        if self.want.addon_keys is not None:
            license_payload["f5-system-licensing-install:add-on-keys"] = self.want.addon_keys
        response = self.client.post(uri, license_payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if "License server has returned an exception" in response['contents']['f5-system-licensing-install:output']['result']:
            raise F5ModuleError(response['contents']['f5-system-licensing-install:output']['result'])
        if response['contents']['f5-system-licensing-install:output']['result'] != "License installed successfully.":
            raise F5ModuleError(response['contents']['f5-system-licensing-install:output']['result'])
        return self.exists()

    def update_on_device(self):
        uri = "/openconfig-system:system/f5-system-licensing:licensing/f5-system-licensing:config"
        license_payload = {
            "f5-system-licensing:registration-key": {
                "f5-system-licensing:base": self.want.registration_key
            },
            "f5-system-licensing:dossier": self.want.dossier,
            "f5-system-licensing:license": self.want.license
        }
        response = self.client.patch(uri, license_payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def deactivate_license(self):
        """Deactivate the license on the device"""
        pass


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            registration_key=dict(type='str', required=True, no_log=True),
            addon_keys=dict(
                type='list',
                elements='str',
                no_log=True
            ),
            license_server=dict(
                default='activate.f5.com'
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
