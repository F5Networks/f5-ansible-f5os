# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
httpapi: f5os
short_description: HttpApi Plugin for F5OS devices
description:
  - This HttpApi plugin provides methods to connect to F5OS devices over a HTTP(S)-based API.
options:
  send_telemetry:
    description:
      - If C(yes) anonymous telemetry data is sent to F5
    default: True
    ini:
    - section: defaults
      key: f5_telemetry
    env:
      - name: F5_TELEMETRY_OFF
    vars:
      - name: f5_telemetry
version_added: "1.0.0"
author:
  - Wojciech Wypior <w.wypior@f5.com>
'''

import io
import json

from ansible.module_utils.basic import to_text
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.errors import AnsibleConnectionFailure

from ansible_collections.f5networks.f5os.plugins.module_utils.constants import (
    LOGIN, BASE_HEADERS, ROOT
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        self.access_token = None
        self.platform_type = None

    def login(self, username, password):
        using_default_creds = (username == "admin") and (password == "admin")
        if username and password:
            response = self.send_request(path=LOGIN, method='GET', headers=BASE_HEADERS)
        else:
            raise AnsibleConnectionFailure('Username and password are required for login.')

        if response['code'] == 200 and 'X-Auth-Token' in response['headers'].keys():
            self.access_token = response['headers'].get('X-Auth-Token', None)
            if self.access_token:
                self.connection._auth = {'X-Auth-Token': self.access_token}
                if not using_default_creds:
                    self._set_platform_type()
            else:
                raise AnsibleConnectionFailure('Server returned invalid response during connection authentication.')
        else:
            raise AnsibleConnectionFailure('Authentication process failed, server returned: {0}'.format(
                response['contents'])
            )

    def logout(self):
        # token removal to be added to F5OS, for now this is a placeholder
        pass

    def handle_httperror(self, exc):
        if exc.code == 401:
            if self.connection._auth is not None:
                # only attempt to refresh token if we were connected before not when we get 401 on first attempt
                self.connection._auth = None
                return True
        return False

    def send_request(self, **kwargs):
        url = kwargs.pop('path', '/')
        body = kwargs.pop('payload', None)
        method = kwargs.pop('method', None)
        # allow for empty json to be passed as payload, useful for some endpoints
        data = json.dumps(body) if body or body == {} else None
        try:
            self._display_request(method, url, body)
            response, response_data = self.connection.send(url, data, method=method, **kwargs)
            response_value = self._get_response_value(response_data)
            return dict(
                code=response.getcode(),
                contents=self._response_to_json(response_value),
                headers=dict(response.getheaders())
            )
        except HTTPError as e:
            return dict(code=e.code, contents=handle_errors(e))

    def _display_request(self, method, url, data=None):
        if data:
            self._display_message(
                'F5OS API Call: {0} to {1} with data {2}'.format(method, url, data)
            )
        else:
            self._display_message(
                'F5OS API Call: {0} to {1}'.format(method, url)
            )

    def _display_message(self, msg):
        self.connection._log_messages(msg)

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise F5ModuleError('Invalid JSON response: %s' % response_text)

    def telemetry(self):
        return self.get_option('send_telemetry')

    def _set_platform_type(self):
        velos_uri = ROOT + "/openconfig-platform:components/component=platform/state/description"
        response = self.send_request(path=velos_uri, method='GET', headers=BASE_HEADERS)
        if response['code'] == 404:
            velos_part_uri = ROOT + "/openconfig-vlan:vlans"
            response = self.send_request(path=velos_part_uri, method='GET', headers=BASE_HEADERS)
            if response['code'] == 404:
                if response['contents'].get('ietf-restconf:errors', None):
                    if response['contents']['ietf-restconf:errors']['error'][0]['error-message'] == \
                            'uri keypath not found':
                        self.platform_type = 'Velos Controller'
                    else:
                        raise F5ModuleError(response['contents'])
                else:
                    raise F5ModuleError(response['contents'])
            elif response['code'] in [200, 204]:
                self.platform_type = 'Velos Partition'
            else:
                raise F5ModuleError(response['contents'])
        elif response['code'] == 200:
            self.platform_type = 'rSeries Platform'
        else:
            raise F5ModuleError(response['contents'])

    def get_platform_type(self):
        return self.platform_type


def _check_seek_raising(error):
    # small helper function to catch seek unsupported operation
    # a temporary workaround for an intermittent problem
    try:
        error.seek(0)
        return False
    except io.UnsupportedOperation:
        return True


def handle_errors(error):
    if isinstance(error, bytes):
        return to_text(error)
    try:
        error_data = json.loads(error.read())
    except json.JSONDecodeError:
        if _check_seek_raising(error):
            # seek is raised as unsupported operation on http errors that contain no body payload, for some
            # reason they are reproduced during integration tests, and completely avoidable during our unit testing
            # for now we placed a temp workaround until we figure this out
            return to_text(error.read())
        else:
            # for non-empty, non-json responses in body
            error.seek(0)
            return to_text(error.read())

    if error_data:
        if "errors" in error_data:
            errors = error_data["errors"]["error"]
            error_text = "\n".join(
                (error["error-message"] for error in errors)
            )
        else:
            error_text = error_data
        return error_text
