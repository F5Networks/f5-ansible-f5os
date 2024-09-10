#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_tls_cert_key
short_description: Manage TLS certificate and key on F5OS devices.
description:
  - Manage TLS certificate and key on F5OS devices.
version_added: 1.11.0
options:
  name:
    description:
      - This specifies the common name of the certificate.
    type: str
    required: True
  subject_alternative_name:
    description:
      - This specifies the subject alternative name of the certificate.
      - This parameter is reuiqred for rSeries Platform.
    type: str
  email:
    description:
      - This specifies the email address of the certificate holder.
    type: str
  city:
    description:
      - This specifies the residing city of the certificate holder.
    type: str
  province:
    description:
      - This specifies the province or state of the certificate holder.
    type: str
  country:
    description:
      - This specifies the country of the certificate holder.
    type: str
  organization:
    description:
      - This specifies the organization of the certificate holder.
    type: str
  unit:
    description:
      - This specifies the organizational unit of the certificate holder.
    type: str
  version:
    description:
      - This specifies the version of the certificate.
    type: int
  days_valid:
    description:
      - This specifies the number of days the certificate is valid.
    type: int
  key_type:
    description:
      - This specifies the type of the key.
    type: str
    choices:
      - rsa
      - encrypted rsa
      - ecdsa
      - encrypted ecdsa
  key_size:
    description:
      - This specifies the length of the key.
      - This parameter is required when C(key_type) is C(rsa) or C(encrypted rsa).
    type: int
    choices:
      - 2048
      - 3072
      - 4096
  key_curve:
    description:
      - This specifies the specific elliptic curve used in ECC.
      - This parameter is required when C(key_type) is C(ecdsa) or C(encrypted ecdsa).
    type: str
    choices:
      - prime256v1
      - secp384r1
  key_passphrase:
    description:
      - This specifies the passphrase for the key.
    type: str
  confirm_key_passphrase:
    description:
      - This specifies the confirmation of the passphrase for the key.
      - The value should be the same as C(key_passphrase).
    type: str
  store_tls:
    description:
      - This specifies whether to store the certificate and key on the device.
    type: bool
  state:
    description:
      - The certificate state. If C(absent), deletes the certificate if it exists.
      - If C(present), the certificate is created.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Rohit Upadhyay (@rupadhyay)
'''

EXAMPLES = r'''
- name: Create tls cert and key on velos
  f5os_tls_cert_key:
    name: "test_cert"
    email: "name@company.com"
    city: Telangana
    province: Hyderabad
    country: IN
    organization: FZ
    unit: IT
    version: 1
    days_valid: 365
    key_type: "rsa"
    key_size: 2048
    store_tls: true
'''

RETURN = r'''
name:
  description: The common name of the certificate.
  returned: changed
  type: str
  sample: test_cert
subject_alternative_name:
  description: The subject alternative name of the certificate.
  returned: changed
  type: str
  sample: DNS:example.com
email:
  description: The email address of the certificate holder.
  returned: changed
  type: str
  sample: name@company.com
city:
  description: The residing city of the certificate holder.
  returned: changed
  type: str
  sample: Delhi
province:
  description: The province or state of the certificate holder.
  returned: changed
  type: str
  sample: Telangana
country:
  description: The country of the certificate holder.
  returned: changed
  type: str
  sample: IN
organization:
  description: The organization of the certificate holder.
  returned: changed
  type: str
  sample: FZ
unit:
  description: The organizational unit of the certificate holder.
  returned: changed
  type: str
  sample: IT
version:
  description: The version of the certificate.
  returned: changed
  type: int
  sample: 1
days_valid:
  description: The number of days the certificate is valid.
  returned: changed
  type: int
  sample: 365
key_type:
  description: The type of the key.
  returned: changed
  type: str
  sample: rsa
key_size:
  description: The length of the key.
  returned: changed
  type: int
  sample: 2048
key_curve:
  description: The specific elliptic curve used in ECC.
  returned: changed
  type: str
  sample: prime256v1
'''

import datetime
import traceback

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
except ImportError:
    CRYPTOGRAPHY_INSTALLED = False
    PACKAGING_IMPORT_ERROR = traceback.format_exc()
else:
    CRYPTOGRAPHY_INSTALLED = True
    PACKAGING_IMPORT_ERROR = None

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        "f5-openconfig-aaa-tls:name": "name",
        "f5-openconfig-aaa-tls:san": "subject_alternative_name",
        "f5-openconfig-aaa-tls:email": "email",
        "f5-openconfig-aaa-tls:city": "city",
        "f5-openconfig-aaa-tls:region": "province",
        "f5-openconfig-aaa-tls:country": "country",
        "f5-openconfig-aaa-tls:organization": "organization",
        "f5-openconfig-aaa-tls:unit": "unit",
        "f5-openconfig-aaa-tls:version": "version",
        "f5-openconfig-aaa-tls:days-valid": "days_valid",
        "f5-openconfig-aaa-tls:key-type": "key_type",
        "f5-openconfig-aaa-tls:key-size": "key_size",
        "f5-openconfig-aaa-tls:curve-name": "key_curve",
        "f5-openconfig-aaa-tls:key-passphrase": "key_passphrase",
        "f5-openconfig-aaa-tls:confirm-key-passphrase": "confirm_key_passphrase",
        "f5-openconfig-aaa-tls:store-tls": "store_tls",
    }

    api_attributes = [
        "f5-openconfig-aaa-tls:name",
        "f5-openconfig-aaa-tls:san",
        "f5-openconfig-aaa-tls:email",
        "f5-openconfig-aaa-tls:city",
        "f5-openconfig-aaa-tls:region",
        "f5-openconfig-aaa-tls:country",
        "f5-openconfig-aaa-tls:organization",
        "f5-openconfig-aaa-tls:unit",
        "f5-openconfig-aaa-tls:version",
        "f5-openconfig-aaa-tls:days-valid",
        "f5-openconfig-aaa-tls:key-type",
        "f5-openconfig-aaa-tls:key-size",
        "f5-openconfig-aaa-tls:curve-name",
        "f5-openconfig-aaa-tls:key-passphrase",
        "f5-openconfig-aaa-tls:confirm-key-passphrase",
        "f5-openconfig-aaa-tls:store-tls",
    ]

    returnables = [
        "name",
        "subject_alternative_name",
        "email",
        "city",
        "province",
        "country",
        "organization",
        "unit",
        "version",
        "days_valid",
        "key_type",
        "key_size",
        "key_curve",
        "key_passphrase",
        "confirm_key_passphrase",
        "store_tls",
    ]

    updatables = [
        "name",
        "email",
        "city",
        "province",
        "country",
        "organization",
        "unit",
        "days_valid",
    ]


class ApiParameters(Parameters):
    @property
    def name(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    @property
    def email(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value

    @property
    def city(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value

    @property
    def province(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value

    @property
    def country(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value

    @property
    def organization(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value

    @property
    def unit(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value

    @property
    def version(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.version.value

    @property
    def valid_from(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.not_valid_before_utc

    @property
    def valid_until(self):
        if "cert" not in self._values:
            return None
        cert = self._values["cert"]
        return cert.not_valid_after_utc

    @property
    def days_valid(self):
        if "cert" not in self._values:
            return None
        return (self.valid_until - self.valid_from).days

    @property
    def password(self):
        return None


class ModuleParameters(Parameters):
    @property
    def subject_alternative_name(self):
        rseries = self.client.platform == "rSeries Platform"
        if not self._values["subject_alternative_name"] and rseries:
            raise F5ModuleError(
                "The 'subject_alternative_name' parameter is required for rSeries Platform."
            )

        return self._values["subject_alternative_name"]


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
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
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
                if isinstance(change, dict):
                    changed.update(change)  # pragma: no cover
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
        self.create_on_device()
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
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        config = response['contents']['f5-openconfig-aaa-tls:tls']['config']
        if 'certificate' not in config or 'key' not in config:
            return False

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params["f5-openconfig-aaa-tls:name"] = self.want.name
        params["f5-openconfig-aaa-tls:store-tls"] = True

        if self.client.platform == "rSeries Platform":
            if self.want.subject_alternative_name is None:
                raise F5ModuleError(
                    "The 'subject_alternative_name' parameter is required for rSeries Platform."
                )
            params["f5-openconfig-aaa-tls:san"] = self.want.subject_alternative_name

        params = self.add_defaults(params)

        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/f5-openconfig-aaa-tls:create-self-signed-cert"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        return True

    def add_defaults(self, params):
        if "f5-openconfig-aaa-tls:email" not in params:
            params["f5-openconfig-aaa-tls:email"] = self.want.email if self.want.email else self.have.email
        if "f5-openconfig-aaa-tls:city" not in params:
            params["f5-openconfig-aaa-tls:city"] = self.want.city if self.want.city else self.have.city
        if "f5-openconfig-aaa-tls:region" not in params:
            params["f5-openconfig-aaa-tls:region"] = self.want.province if self.want.province else self.have.province
        if "f5-openconfig-aaa-tls:country" not in params:
            params["f5-openconfig-aaa-tls:country"] = self.want.country if self.want.country else self.have.country
        if "f5-openconfig-aaa-tls:organization" not in params:
            params["f5-openconfig-aaa-tls:organization"] = self.want.organization if self.want.organization else self.have.organization
        if "f5-openconfig-aaa-tls:unit" not in params:
            params["f5-openconfig-aaa-tls:unit"] = self.want.unit if self.want.unit else self.have.unit
        if "f5-openconfig-aaa-tls:version" not in params:
            params["f5-openconfig-aaa-tls:version"] = self.want.version if self.want.version else self.have.version
        if "f5-openconfig-aaa-tls:days-valid" not in params:
            params["f5-openconfig-aaa-tls:days-valid"] = self.want.days_valid if self.want.days_valid else self.have.days_valid
        if "f5-openconfig-aaa-tls:key-type" not in params:
            params["f5-openconfig-aaa-tls:key-type"] = self.want.key_type if self.want.key_type else self.have.key_type

        if "f5-openconfig-aaa-tls:key-size" not in params and params["f5-openconfig-aaa-tls:key-type"] in ["encrypted rsa", "rsa"]:
            params["f5-openconfig-aaa-tls:key-size"] = self.want.key_size if self.want.key_size else self.have.key_size
        if "f5-openconfig-aaa-tls:curve-name" not in params and params["f5-openconfig-aaa-tls:key-type"] in ["encrypted ecdsa", "ecdsa"]:
            params["f5-openconfig-aaa-tls:curve-name"] = self.want.key_curve if self.want.key_curve else self.have.key_curve

        return params

    def remove_from_device(self):
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls/config"
        params = {
            "f5-openconfig-aaa-tls:config": {
                "verify-client": False,
                "verify-client-depth": 1
            }
        }

        response = self.client.put(uri, params)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = "/openconfig-system:system/aaa/f5-openconfig-aaa-tls:tls"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        cert_string = response['contents']['f5-openconfig-aaa-tls:tls']['config']['certificate']
        cert = x509.load_pem_x509_certificate(cert_string.encode("utf-8"), default_backend())

        return ApiParameters(params={"cert": cert})


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            subject_alternative_name=dict(),
            email=dict(),
            city=dict(),
            province=dict(),
            country=dict(),
            organization=dict(),
            unit=dict(),
            version=dict(type="int"),
            days_valid=dict(type="int"),
            key_type=dict(
                choices=[
                    "rsa",
                    "encrypted rsa",
                    "ecdsa",
                    "encrypted ecdsa",
                ]
            ),
            key_size=dict(
                type='int',
                choices=[2048, 3072, 4096]
            ),
            key_curve=dict(
                choices=["prime256v1", "secp384r1"]
            ),
            key_passphrase=dict(
                no_log=True
            ),
            confirm_key_passphrase=dict(
                no_log=True
            ),
            store_tls=dict(
                type="bool"
            ),
            state=dict(
                default="present",
                choices=["present", "absent"]
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)

        self.required_if = [
            ("key_type", "rsa", ["key_size"]),
            ("key_type", "ecdsa", ["key_curve"]),
            ("key_type", "encrypted rsa", ["key_size", "key_passphrase", "confirm_key_passphrase"]),
            ("key_type", "encrypted ecdsa", ["key_curve", "key_passphrase", "confirm_key_passphrase"]),
        ]

        self.mutually_exclusive = [
            ["key_size", "key_curve"],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    if not CRYPTOGRAPHY_INSTALLED:
        module.fail_json(
            msg=missing_required_lib("cryptography"),
            exception=PACKAGING_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
