#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_system
short_description: Manage generic system settings
description:
  - Manage generic system settings
version_added: 1.10.0
options:
  hostname:
    description:
      - Specifies the system hostname
    type: str
  motd:
    description:
      - Specifies the message of the day
    type: str
  login_banner:
    description:
      - Specifies the Login Banner
    type: str
  timezone:
    description:
      - Specifies the timezone for the system per TZ database name
    type: str
  cli_timeout:
    description:
      - Specifies the CLI idle timeout
    type: int
  httpd_ciphersuite:
    description:
      - Specifies the httpd ciphersuite in OpenSSL format
    type: str
  sshd_idle_timeout:
    description:
      - Specifies the SSHD idle timeout
    type: str
  sshd_ciphers:
    description:
      - Specifies the sshd ciphers in OpenSSH format
    type: list
    elements: str
  sshd_kex_alg:
    description:
      - Specifies the sshd key exchange algorithems in OpenSSH format
    type: list
    elements: str
  sshd_mac_alg:
    description:
      - Specifies the sshd MAC algorithems in OpenSSH format
    type: list
    elements: str
  sshd_hkey_alg:
    description:
      - Specifies the sshd host key algorithems in OpenSSH format
    type: list
    elements: str
  gui_advisory:
    description:
      - Specify the GUI advisory banner
    type: dict
    suboptions:
      color:
        description:
          - Specify the color of the advisory banner
        type: str
        choices:
          - blue
          - green
          - orange
          - red
          - yellow
      text:
        description:
          - Specify the text for the advisory banner
        type: str
  state:
    description:
      - State for the settings.
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
- name: Set system settings
  f5os_system:
    hostname: system.example.net
    motd: Todays weather is great!
    login_banner: With great power comes great responsibility
    timezone: UTC
    cli_timeout: 3600
    sshd_idle_timeout: 1800
    httpd_ciphersuite: ECDHE-RSA-AES256-GCM-SHA384
    sshd_ciphers:
      - aes256-ctr
      - aes256-gcm@openssh.com
    sshd_kex_alg:
      - ecdh-sha2-nistp384
      - ecdh-sha2-nistp521
    sshd_mac_alg:
      - hmac-sha1
      - hmac-sha1-96
    sshd_hkey_alg:
      - ssh-rsa

- name: Unset MAC / Host Key algorithms
  f5os_system:
    sshd_hkey_alg:
      - ssh-rsa
    sshd_mac_alg:
      - hmac-sha1
      - hmac-sha1-96
    state: absent
'''

RETURN = r'''
hostname:
  description: Specifies the system hostname
  returned: changed
  type: str
motd:
  description: Specifies the message of the day
  returned: changed
  type: str
login_banner:
  description: Specifies the Login Banner
  returned: changed
  type: str
timezone:
  description: Specifies the timezone for the system per TZ database name
  returned: changed
  type: str
cli_timeout:
  description: Specifies the CLI idle timeout
  returned: changed
  type: str
httpd_ciphersuite:
  description: Specifies the httpd ciphersuite in OpenSSL format
  returned: changed
  type: str
sshd_idle_timeout:
  description: Specifies the SSHD idle timeout
  returned: changed
  type: str
sshd_ciphers:
  description: Specifies the sshd ciphers in OpenSSH format
  returned: changed
  type: list
sshd_kex_alg:
  description: Specifies the sshd key exchange algorithems in OpenSSH format
  returned: changed
  type: list
sshd_mac_alg:
  description: Specifies the sshd MAC algorithems in OpenSSH format
  returned: changed
  type: list
sshd_hkey_alg:
  description: Specifies the sshd host key algorithems in OpenSSH format
  returned: changed
  type: list
gui_advisory:
  description: Specifies GUI advisory banner
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
        'timezone',
        'motd',
        'login_banner',
        'hostname',
        'cli_timeout',
        'sshd_idle_timeout',
        'httpd_ciphersuite',
        'sshd_ciphers',
        'sshd_kex_alg',
        'sshd_mac_alg',
        'sshd_hkey_alg',
        'gui_advisory'
    ]

    returnables = [
        'timezone',
        'motd',
        'login_banner',
        'hostname',
        'cli_timeout',
        'sshd_idle_timeout',
        'httpd_ciphersuite',
        'sshd_ciphers',
        'sshd_kex_alg',
        'sshd_mac_alg',
        'sshd_hkey_alg',
        'gui_advisory'
    ]

    updatables = [
        'timezone',
        'motd',
        'login_banner',
        'hostname',
        'cli_timeout',
        'sshd_idle_timeout',
        'httpd_ciphersuite',
        'sshd_ciphers',
        'sshd_kex_alg',
        'sshd_mac_alg',
        'sshd_hkey_alg',
        'gui_advisory'
    ]


class ApiParameters(Parameters):
    @property
    def timezone(self):
        try:
            return self._values['clock']['config']['timezone-name']
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def motd(self):
        try:
            return self._values['config']['motd-banner']
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def login_banner(self):
        try:
            return self._values['config']['login-banner']
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def hostname(self):
        try:
            return self._values['config']['hostname']
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def cli_timeout(self):
        try:
            return int(self._values['settings']['config']['idle-timeout'])
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def sshd_idle_timeout(self):
        try:
            return self._values['settings']['config']['sshd-idle-timeout']
        except (TypeError, ValueError, KeyError):
            return None

    @property
    def httpd_ciphersuite(self):
        try:
            for service in self._values['ciphers']:
                if service['name'] == 'httpd':
                    return service['config']['ssl-ciphersuite']
            return None
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def sshd_ciphers(self):
        try:
            for service in self._values['ciphers']:
                if service['name'] == 'sshd':
                    sorted_ciphers = service['config']['ciphers']
                    sorted_ciphers.sort()
                    return sorted_ciphers
            return None
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def sshd_kex_alg(self):
        try:
            for service in self._values['ciphers']:
                if service['name'] == 'sshd':
                    sorted_kex = service['config']['kexalgorithms']
                    sorted_kex.sort()
                    return sorted_kex
            return None
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def sshd_mac_alg(self):
        try:
            for service in self._values['ciphers']:
                if service['name'] == 'sshd':
                    sorted_macs = service['config']['macs']
                    sorted_macs.sort()
                    return sorted_macs
            return None
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def sshd_hkey_alg(self):
        try:
            for service in self._values['ciphers']:
                if service['name'] == 'sshd':
                    sorted_hkey_algs = service['config']['host-key-algorithms']
                    sorted_hkey_algs.sort()
                    return sorted_hkey_algs
            return None
        except (TypeError, ValueError):
            return None
        except (KeyError):
            return []

    @property
    def gui_advisory(self):
        try:
            config = self._values['settings']['f5-gui-advisory:gui']['advisory']['config']
            result = {
                'color': config['color'],
                'text': config['text']
            }
            return result
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
        conf_attr = {
            'login_banner': 'login-banner',
            'motd': 'motd-banner',
            'hostname': 'hostname'
        }
        for attr in conf_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                uri = f'/openconfig-system:system/config/{conf_attr[attr]}'
                response = self.client.get(uri)

                if response['code'] == 200:
                    if query in ['any', 'still']:
                        return True

                if response['code'] not in [200, 201, 202, 404]:
                    raise F5ModuleError(response['contents'])

        clock_attr = {
            'timezone': 'timezone-name'
        }
        for attr in clock_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                uri = f'/openconfig-system:system/clock/config/{clock_attr[attr]}'
                response = self.client.get(uri)

                if response['code'] == 200:
                    if query in ['any', 'still']:
                        return True

                if response['code'] not in [200, 201, 202, 404]:
                    raise F5ModuleError(response['contents'])

        settings_attr = {
            'cli_timeout': 'idle-timeout',
            'sshd_idle_timeout': 'sshd-idle-timeout',
            'gui_advisory': 'f5-gui-advisory:gui'
        }
        for attr in settings_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                uri = f'/openconfig-system:system/f5-system-settings:settings/{settings_attr[attr]}'
                response = self.client.get(uri)

                if response['code'] == 200:
                    if query in ['any', 'still']:
                        return True

                if response['code'] not in [200, 201, 202, 404]:
                    raise F5ModuleError(response['contents'])

        ciphers_attr = {
            'httpd_ciphersuite': 'ssl-cipher-suite',
            'sshd_ciphers': 'ciphers',
            'sshd_kex_alg': 'kexalgorithms',
            'sshd_mac_alg': 'macs',
            'sshd_hkey_alg': 'host-key-algorithms'
        }
        for attr in ciphers_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                if attr == 'httpd_ciphersuite':
                    uri = '/openconfig-system:system/f5-security-ciphers:security/services/service="httpd"/config/ssl-ciphersuite'
                    response = self.client.get(uri)

                    if response['code'] == 200:
                        if query in ['any', 'still']:
                            return True

                    if response['code'] not in [200, 201, 202, 404]:
                        raise F5ModuleError(response['contents'])
                else:
                    uri = f'/openconfig-system:system/f5-security-ciphers:security/services/service="sshd"/config/{ciphers_attr[attr]}'
                    response = self.client.get(uri)

                    if response['code'] == 200:
                        if query in ['any', 'still']:
                            return True

                    if response['code'] not in [200, 201, 202, 404]:
                        raise F5ModuleError(response['contents'])

        if query in ['any', 'still']:
            return False
        return True

    def create_on_device(self):
        # not applicable for system parameters,
        pass

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "/openconfig-system:system"
        payload = {
            'openconfig-system:system': {
                'config': dict()
            }
        }
        system = payload['openconfig-system:system']
        config = system['config']
        if 'hostname' in params:
            config['hostname'] = params['hostname']
        if 'timezone' in params:
            # Clock is nested
            system['clock'] = {
                'config': {
                    'timezone-name': params['timezone']
                }
            }
        if 'motd' in params:
            config['motd-banner'] = params['motd']
        if 'login_banner' in params:
            config['login-banner'] = params['login_banner']

        # Settings use a different API endpoint
        if any(attr in ['cli_timeout', 'sshd_idle_timeout', 'gui_advisory'] for attr in params):
            settings_uri = '/openconfig-system:system/f5-system-settings:settings'
            settings_payload = {
                'settings': {
                    'config': dict()
                }
            }

            settings_config = settings_payload['settings']['config']
            if 'cli_timeout' in params:
                settings_config['idle-timeout'] = params['cli_timeout']
            if 'sshd_idle_timeout' in params:
                settings_config['sshd-idle-timeout'] = params['sshd_idle_timeout']
            if 'gui_advisory' in params:
                settings_payload['settings']['f5-gui-advisory:gui'] = {
                    'advisory': {
                        'config': {
                            'color': params['gui_advisory']['color'],
                            'text': params['gui_advisory']['text'],
                            'enabled': True
                        }
                    }
                }

            settings_response = self.client.patch(settings_uri, data=settings_payload)
            if settings_response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(settings_response['contents'])

        # Ciphers + Key Exchange use a different API endpoint
        if 'httpd_ciphersuite' in params:
            httpd_uri = '/openconfig-system:system/f5-security-ciphers:security/services/service="httpd"/config'
            httpd_payload = {
                'config': {
                    'name': 'httpd',
                    'ssl-ciphersuite': params['httpd_ciphersuite']
                }
            }
            httpd_response = self.client.put(httpd_uri, data=httpd_payload)
            if httpd_response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(httpd_response['contents'])

        if any(attr in ['sshd_ciphers', 'sshd_kex_alg', 'sshd_mac_alg', 'sshd_hkey_alg'] for attr in params):
            sshd_uri = '/openconfig-system:system/f5-security-ciphers:security/services/service="sshd"/config'

            attributes = {}

            if hasattr(self.want, 'sshd_ciphers') and self.want.sshd_ciphers is not None:
                attributes['ciphers'] = {'ciphers': self.want.sshd_ciphers}
            if hasattr(self.want, 'sshd_kex_alg') and self.want.sshd_kex_alg is not None:
                attributes['kexalgorithms'] = {'kexalgorithms': self.want.sshd_kex_alg}
            if hasattr(self.want, 'sshd_mac_alg') and self.want.sshd_mac_alg is not None:
                attributes['macs'] = {'macs': self.want.sshd_mac_alg}
            if hasattr(self.want, 'sshd_hkey_alg') and self.want.sshd_hkey_alg is not None:
                attributes['host-key-algorithms'] = {'host-key-algorithms': self.want.sshd_hkey_alg}

            for attr in attributes:
                sshd_response = self.client.put(sshd_uri + "/" + attr, data=attributes[attr])
                if sshd_response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(sshd_response['contents'])

        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        conf_attr = {
            'login_banner': 'login-banner',
            'motd': 'motd-banner',
            'hostname': 'hostname'
        }
        for attr in conf_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                uri = f'/openconfig-system:system/config/{conf_attr[attr]}'
                response = self.client.delete(uri)

                if response['code'] == 204:
                    # Deleted
                    continue
                elif response['code'] == 404:
                    # Not Found
                    continue
                else:
                    raise F5ModuleError(response['contents'])

        clock_attr = {
            'timezone': 'timezone-name'
        }
        for attr in clock_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                uri = f'/openconfig-system:system/clock/config/{clock_attr[attr]}'
                response = self.client.delete(uri)

                if response['code'] == 204:
                    # Deleted
                    continue
                elif response['code'] == 404:
                    # Not Found
                    continue
                else:
                    raise F5ModuleError(response['contents'])

        settings_attr = {
            'cli_timeout': 'idle-timeout',
            'sshd_idle_timeout': 'sshd-idle-timeout'
        }
        for attr in settings_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                uri = f'/openconfig-system:system/f5-system-settings:settings/{settings_attr[attr]}'
                response = self.client.delete(uri)

                if response['code'] == 204:
                    # Deleted
                    continue
                elif response['code'] == 404:
                    # Not Found
                    continue
                else:
                    raise F5ModuleError(response['contents'])

        ciphers_attr = {
            'httpd_ciphersuite': 'ssl-cipher-suite',
            'sshd_ciphers': 'ciphers',
            'sshd_kex_alg': 'kexalgorithms',
            'sshd_mac_alg': 'macs',
            'sshd_hkey_alg': 'host-key-algorithms'
        }
        for attr in ciphers_attr:
            if hasattr(self.want, attr) and getattr(self.want, attr) is not None:
                if attr == 'httpd_ciphersuite':
                    uri = '/openconfig-system:system/f5-security-ciphers:security/services/service="httpd"/config/ssl-ciphersuite'
                    response = self.client.delete(uri)

                    if response['code'] == 204:
                        # Deleted
                        continue
                    elif response['code'] == 404:
                        # Not Found
                        continue
                    else:
                        raise F5ModuleError(response['contents'])

                else:
                    uri = f'/openconfig-system:system/f5-security-ciphers:security/services/service="sshd"/config/{ciphers_attr[attr]}'
                    response = self.client.delete(uri)

                    if response['code'] == 204:
                        # Deleted
                        continue
                    elif response['code'] == 404:
                        # Not Found
                        continue
                    else:
                        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        params = dict()

        # Motd, login_banner, hostname
        uri = "/openconfig-system:system/config"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents']['openconfig-system:config'])

        # Clock
        clock_uri = "/openconfig-system:system/clock"
        clock_response = self.client.get(clock_uri)
        if clock_response['code'] not in [200, 201, 202]:
            raise F5ModuleError(clock_response['contents']['openconfig-system:clock'])

        # Ciphers
        ciphers_uri = '/openconfig-system:system/f5-security-ciphers:security/services/service'
        ciphers_response = self.client.get(ciphers_uri)
        if ciphers_response['code'] not in [200, 201, 202]:
            raise F5ModuleError(ciphers_response['contents']['f5-security-ciphers:service'])

        # Settings
        settings_uri = '/openconfig-system:system/f5-system-settings:settings'
        settings_response = self.client.get(settings_uri)
        if settings_response['code'] not in [200, 201, 202]:
            raise F5ModuleError(settings_response['contents']['f5-system-settings:settings'])

        params['config'] = response['contents']['openconfig-system:config']
        params['clock'] = clock_response['contents']['openconfig-system:clock']
        params['ciphers'] = ciphers_response['contents']['f5-security-ciphers:service']
        params['settings'] = settings_response['contents']['f5-system-settings:settings']
        return ApiParameters(params=params)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            hostname=dict(type='str'),
            login_banner=dict(type='str'),
            motd=dict(type='str'),
            timezone=dict(type='str'),
            gui_advisory=dict(
                type='dict',
                options=dict(
                    color=dict(
                        type='str',
                        choices=[
                            'blue',
                            'green',
                            'orange',
                            'red',
                            'yellow'
                        ]
                    ),
                    text=dict(type='str')
                )
            ),
            cli_timeout=dict(type='int'),
            httpd_ciphersuite=dict(type='str'),
            sshd_idle_timeout=dict(type='str'),
            sshd_ciphers=dict(
                type='list',
                elements='str'
            ),
            sshd_kex_alg=dict(
                type='list',
                elements='str'
            ),
            sshd_mac_alg=dict(
                type='list',
                elements='str'
            ),
            sshd_hkey_alg=dict(
                type='list',
                elements='str'
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
