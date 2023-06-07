# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import io
import json
import os
from unittest.mock import Mock, patch
from unittest import TestCase

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six import StringIO
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader


from ansible_collections.f5networks.f5os.tests.utils.common import connection_response
from ansible_collections.f5networks.f5os.plugins.module_utils.constants import BASE_HEADERS
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5os.plugins.httpapi.f5os import HttpApi, handle_errors

fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)

    if path in fixture_data:
        return fixture_data[path]

    with open(path) as f:
        data = f.read()

    try:
        data = json.loads(data)
    except Exception:
        pass

    fixture_data[path] = data
    return data


class TestF5OSHttpapi(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5os.f5os"
        self.connection = connection_loader.get("ansible.netcommon.httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send

    def test_login_raises_exception_when_username_and_password_are_not_provided(self):
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login(None, None)
        assert 'Username and password are required for login.' in str(res.exception)

    def test_login_raises_exception_when_invalid_token_response(self):
        self.connection.send.side_effect = HTTPError(
            'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )

        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        assert "Authentication process failed, server returned: {'errorMessage': 'ERROR'}" in str(res.exception)

    def test_login_returns_auth_exception(self):
        xheader = {'X-Auth-Token': None}
        xheader.update(BASE_HEADERS)
        self.connection.send.return_value = connection_response(
            {'errorMessage': 'ERROR'}, 200, xheader
        )
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        assert "Server returned invalid response during connection authentication." in str(res.exception)

    def test_login_success_properties_populated(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.return_value = connection_response(
            load_fixture('f5os_auth.json'), 200, xheader
        )
        with patch.object(HttpApi, '_set_platform_type') as mock_platform:
            mock_platform.return_value = True
            self.connection.httpapi.login('foo', 'bar')

        assert self.connection.httpapi.access_token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        assert self.connection._auth == {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}

    def test_set_platform_type_rseries_set(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({'GOOD': 'RESPONSE'}, 200, xheader)
        ]
        self.connection.httpapi.login('foo', 'bar')
        platform = self.connection.httpapi.get_platform_type()

        assert platform == 'rSeries Platform'
        assert self.connection.send.call_count == 2

    def test_set_platform_type_controller_set(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response(load_fixture('f5os_vlctrl.json'), 404, xheader),
        ]
        self.connection.httpapi.login('foo', 'bar')
        platform = self.connection.httpapi.get_platform_type()

        assert platform == 'Velos Controller'
        assert self.connection.send.call_count == 3

    def test_set_platform_type_partition_set(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response({'GOOD': 'RESPONSE'}, 200, xheader),
        ]
        self.connection.httpapi.login('foo', 'bar')
        platform = self.connection.httpapi.get_platform_type()

        assert platform == 'Velos Partition'
        assert self.connection.send.call_count == 3

    def test_set_platform_type_raises_empty_response(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response({}, 404, xheader)
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.connection.httpapi.login('foo', 'bar')

        assert '{}' in str(ex.exception)
        assert self.connection.send.call_count == 3

    def test_set_platform_type_raises_different_error(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response(load_fixture('f5os_differr.json'), 404, xheader),
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.connection.httpapi.login('foo', 'bar')

        assert 'This is a different error type' in str(ex.exception)
        assert self.connection.send.call_count == 3

    def test_set_platform_type_raises_first(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response({'Error': 'Something went wrong first time'}, 401, xheader)
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.connection.httpapi.login('foo', 'bar')

        assert 'Something went wrong first time' in str(ex.exception)
        assert self.connection.send.call_count == 3

    def test_set_platform_type_raises_second(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({'Error': 'Something went wrong second time'}, 401, xheader)
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.connection.httpapi.login('foo', 'bar')

        assert 'Something went wrong second time' in str(ex.exception)
        assert self.connection.send.call_count == 2

    def test_get_telemetry(self):
        mock_response = Mock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.return_value = False

        assert self.connection.httpapi.telemetry() is False

    def test_handle_httperror(self):
        self.connection._auth = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        exc1 = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"errorMessage": "not allowed"}'))
        res1 = self.connection.httpapi.handle_httperror(exc1)
        assert res1 is True
        assert self.connection._auth is None

        exc1 = HTTPError('http://bigip.local', 404, '', {}, StringIO('{"errorMessage": "not found"}'))
        res1 = self.connection.httpapi.handle_httperror(exc1)
        assert res1 is False

    def test_resonse_to_json_raises(self):
        with self.assertRaises(F5ModuleError) as err:
            self.connection.httpapi._response_to_json('invalid json}')
        assert 'Invalid JSON response: invalid json}' in str(err.exception)

    def test_display_message_and_logout(self):
        with patch.object(HttpApi, '_display_message') as mock_msg:
            mock_msg.return_value = True
            self.connection.httpapi._display_request('POST', 'foo/url', data='some data')

        mock_msg.assert_called_with('F5OS API Call: POST to foo/url with data some data')
        # just to cover pass statement
        self.connection.httpapi.logout()

    def test_handle_errors(self):
        b1 = b"""{
            "errors": {
                "error": [
                    {
                        "error-type": "application",
                        "error-tag": "invalid-value",
                        "error-message": "uri keypath not found"
                    }
                ]
            }
        }"""
        nested_error = HTTPError('foo', 404, 'not found', None, io.BytesIO(b1))
        result1 = handle_errors(nested_error)
        assert result1 == 'uri keypath not found'

        non_json_error = HTTPError('foo', 404, 'not found', None, io.BytesIO(b'this is an error message not a json'))
        result2 = handle_errors(non_json_error)
        assert result2 == 'this is an error message not a json'

        empty_payload_error = HTTPError('foo', 404, 'not found', None, io.BytesIO(b''))
        result3 = handle_errors(empty_payload_error)
        assert result3 == ''
