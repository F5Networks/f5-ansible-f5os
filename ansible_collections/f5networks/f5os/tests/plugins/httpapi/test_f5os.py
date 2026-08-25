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


from ansible_collections.f5networks.f5os.tests.utils.common import (
    connection_response, mock_httpapi_connection
)
from ansible_collections.f5networks.f5os.plugins.module_utils.constants import BASE_HEADERS
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.f5os.plugins.httpapi.f5os import HttpApi, handle_errors, _check_seek_raising

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
        self.connection = mock_httpapi_connection()
        self.mock_send = self.connection.send
        # Alias used by tests
        self.mock_connection = self.connection
        # Expose the plugin instance for direct calls
        self.httpapi = self.connection.httpapi

    def test_login_raises_exception_when_username_and_password_are_not_provided(self):
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.httpapi.login(None, None)
        assert 'Username and password are required for login.' in str(res.exception)

    def test_login_raises_exception_when_invalid_token_response(self):
        self.mock_connection.send.side_effect = HTTPError(
            'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )

        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.httpapi.login('foo', 'bar')

        assert "Authentication process failed, server returned: {'errorMessage': 'ERROR'}" in str(res.exception)

    def test_login_returns_auth_exception(self):
        xheader = {'X-Auth-Token': None}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.return_value = connection_response(
            {'errorMessage': 'ERROR'}, 200, xheader
        )
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.httpapi.login('foo', 'bar')

        assert "Server returned invalid response during connection authentication." in str(res.exception)

    def test_login_success_properties_populated(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.return_value = connection_response(
            load_fixture('f5os_auth.json'), 200, xheader
        )
        with patch.object(HttpApi, '_set_platform_type') as mock_platform:
            mock_platform.return_value = True
            with patch.object(HttpApi, '_set_software_version'):
                self.httpapi.login('foo', 'bar')

        assert self.httpapi.access_token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        assert self.mock_connection._auth == {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}

    def test_login_with_default_creds_skips_platform_detection(self):
        xheader = {'X-Auth-Token': 'token123'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.return_value = connection_response(
            load_fixture('f5os_auth.json'), 200, xheader
        )
        with patch.object(HttpApi, '_set_platform_type') as mock_platform:
            with patch.object(HttpApi, '_set_software_version') as mock_version:
                self.httpapi.login('admin', 'admin')

        mock_platform.assert_not_called()
        mock_version.assert_not_called()
        assert self.httpapi.access_token == 'token123'

    def test_set_platform_type_rseries_set(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.httpapi._set_software_version = Mock()
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({'GOOD': 'RESPONSE'}, 200, xheader)
        ]
        self.httpapi.login('foo', 'bar')
        platform = self.httpapi.get_platform_type()

        assert platform == 'rSeries Platform'
        assert self.mock_connection.send.call_count == 2

    def test_set_platform_type_controller_set(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response(load_fixture('f5os_vlctrl.json'), 404, xheader),
        ]
        self.httpapi.login('foo', 'bar')
        platform = self.httpapi.get_platform_type()

        assert platform == 'Velos Controller'
        assert self.mock_connection.send.call_count == 3

    def test_set_platform_type_partition_set(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.httpapi._set_software_version = Mock()
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response({'GOOD': 'RESPONSE'}, 200, xheader),
        ]
        self.httpapi.login('foo', 'bar')
        platform = self.httpapi.get_platform_type()

        assert platform == 'Velos Partition'
        assert self.mock_connection.send.call_count == 3

    def test_set_platform_type_raises_empty_response(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response({}, 404, xheader)
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.httpapi.login('foo', 'bar')

        assert '{}' in str(ex.exception)
        assert self.mock_connection.send.call_count == 3

    def test_set_platform_type_raises_different_error(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response(load_fixture('f5os_differr.json'), 404, xheader),
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.httpapi.login('foo', 'bar')

        assert 'This is a different error type' in str(ex.exception)
        assert self.mock_connection.send.call_count == 3

    def test_set_platform_type_raises_first(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({}, 404, xheader),
            connection_response({'Error': 'Something went wrong first time'}, 401, xheader)
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.httpapi.login('foo', 'bar')

        assert 'Something went wrong first time' in str(ex.exception)
        assert self.mock_connection.send.call_count == 3

    def test_set_platform_type_raises_second(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.mock_connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response({'Error': 'Something went wrong second time'}, 401, xheader)
        ]
        with self.assertRaises(F5ModuleError) as ex:
            self.httpapi.login('foo', 'bar')

        assert 'Something went wrong second time' in str(ex.exception)
        assert self.mock_connection.send.call_count == 2

    def test_get_telemetry(self):
        self.httpapi.get_option = Mock(return_value=False)
        assert self.httpapi.telemetry() is False

    def test_handle_httperror(self):
        self.mock_connection._auth = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        exc1 = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"errorMessage": "not allowed"}'))
        res1 = self.httpapi.handle_httperror(exc1)
        assert res1 is True
        assert self.mock_connection._auth is None

        exc1 = HTTPError('http://bigip.local', 404, '', {}, StringIO('{"errorMessage": "not found"}'))
        res1 = self.httpapi.handle_httperror(exc1)
        assert res1 is False

    def test_resonse_to_json_raises(self):
        with self.assertRaises(F5ModuleError) as err:
            self.httpapi._response_to_json('invalid json}')
        assert 'Invalid JSON response: invalid json}' in str(err.exception)

    def test_display_message_and_logout(self):
        with patch.object(HttpApi, '_display_message') as mock_msg:
            mock_msg.return_value = True
            self.httpapi._display_request('POST', 'foo/url', data='some data')

        mock_msg.assert_called_with('F5OS API Call: POST to foo/url with data some data')
        # just to cover pass statement
        self.httpapi.logout()

    def test_display_request_without_data(self):
        with patch.object(HttpApi, '_display_message') as mock_msg:
            self.httpapi._display_request('GET', '/api/test')

        mock_msg.assert_called_with('F5OS API Call: GET to /api/test')

    def test_get_forward_proxy_headers_returns_dict(self):
        self.httpapi.get_option = Mock(return_value={'X-Custom': 'value', 'X-Trace-Id': '12345'})

        result = self.httpapi.get_forward_proxy_headers()
        assert result == {'X-Custom': 'value', 'X-Trace-Id': '12345'}

    def test_get_forward_proxy_headers_returns_empty_when_none(self):
        self.httpapi.get_option = Mock(return_value=None)

        result = self.httpapi.get_forward_proxy_headers()
        assert result == {}

    def test_get_forward_proxy_headers_returns_empty_when_not_dict(self):
        self.httpapi.get_option = Mock(return_value='not-a-dict')

        result = self.httpapi.get_forward_proxy_headers()
        assert result == {}

    def test_get_forward_proxy_headers_returns_empty_dict_when_empty(self):
        self.httpapi.get_option = Mock(return_value={})

        result = self.httpapi.get_forward_proxy_headers()
        assert result == {}

    def test_send_request_merges_forward_proxy_headers(self):
        proxy_headers = {'X-Proxy-Auth': 'token123', 'X-Request-Id': 'abc'}
        self.httpapi.get_option = Mock(return_value=proxy_headers)
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(
            path='/restconf/data/test', method='GET', headers=BASE_HEADERS
        )

        call_kwargs = self.mock_connection.send.call_args
        sent_headers = call_kwargs[1]['headers']
        assert sent_headers['X-Proxy-Auth'] == 'token123'
        assert sent_headers['X-Request-Id'] == 'abc'
        assert sent_headers['Content-Type'] == 'application/yang-data+json'

    def test_send_request_proxy_headers_do_not_override_explicit_headers(self):
        proxy_headers = {'Content-Type': 'should-not-win', 'X-Custom': 'proxy-value'}
        self.httpapi.get_option = Mock(return_value=proxy_headers)
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(
            path='/restconf/data/test', method='GET', headers={'Content-Type': 'application/json'}
        )

        call_kwargs = self.mock_connection.send.call_args
        sent_headers = call_kwargs[1]['headers']
        # Explicit headers take precedence over proxy headers
        assert sent_headers['Content-Type'] == 'application/json'
        assert sent_headers['X-Custom'] == 'proxy-value'

    def test_send_request_no_proxy_headers_passes_through(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(
            path='/restconf/data/test', method='GET', headers=BASE_HEADERS
        )

        call_kwargs = self.mock_connection.send.call_args
        sent_headers = call_kwargs[1]['headers']
        assert sent_headers == BASE_HEADERS

    def test_send_request_merges_proxy_headers_when_explicit_headers_is_none(self):
        proxy_headers = {'X-Proxy-Auth': 'token123'}
        self.httpapi.get_option = Mock(return_value=proxy_headers)
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(
            path='/restconf/data/test', method='GET', headers=None
        )

        call_kwargs = self.mock_connection.send.call_args
        sent_headers = call_kwargs[1]['headers']
        assert sent_headers['X-Proxy-Auth'] == 'token123'

    def test_send_request_url_rewrite_port_443_restconf_data(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=443)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(path='/restconf/data/some/resource', method='GET')

        call_args = self.mock_connection.send.call_args
        assert call_args[0][0] == '/api/data/some/resource'

    def test_send_request_url_rewrite_port_443_restconf_operations(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=443)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(path='/restconf/operations/some/action', method='POST')

        call_args = self.mock_connection.send.call_args
        assert call_args[0][0] == '/api/operations/some/action'

    def test_send_request_no_url_rewrite_port_8888(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(path='/restconf/data/some/resource', method='GET')

        call_args = self.mock_connection.send.call_args
        assert call_args[0][0] == '/restconf/data/some/resource'

    def test_send_request_with_payload(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        payload = {'key': 'value', 'nested': {'a': 1}}
        self.httpapi.send_request(path='/restconf/data/test', method='POST', payload=payload)

        call_args = self.mock_connection.send.call_args
        assert call_args[0][1] == json.dumps(payload)

    def test_send_request_with_empty_dict_payload(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(path='/restconf/data/test', method='POST', payload={})

        call_args = self.mock_connection.send.call_args
        assert call_args[0][1] == '{}'

    def test_send_request_with_none_payload(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'result': 'ok'}, 200)

        self.httpapi.send_request(path='/restconf/data/test', method='GET')

        call_args = self.mock_connection.send.call_args
        assert call_args[0][1] is None

    @patch('ansible_collections.f5networks.f5os.plugins.httpapi.f5os.time.sleep')
    def test_send_request_retries_on_connection_failure(self, mock_sleep):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.side_effect = AnsibleConnectionFailure('connection reset')

        with self.assertRaises(F5ModuleError) as ex:
            self.httpapi.send_request(path='/restconf/data/test', method='GET')

        assert self.mock_connection.send.call_count == 3
        assert mock_sleep.call_count == 3
        assert 'connection reset' in str(ex.exception)

    @patch('ansible_collections.f5networks.f5os.plugins.httpapi.f5os.time.sleep')
    def test_send_request_retry_succeeds_on_second_attempt(self, mock_sleep):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.side_effect = [
            AnsibleConnectionFailure('connection reset'),
            connection_response({'result': 'ok'}, 200)
        ]

        result = self.httpapi.send_request(path='/restconf/data/test', method='GET')

        assert result['code'] == 200
        assert self.mock_connection.send.call_count == 2
        assert mock_sleep.call_count == 1

    def test_send_request_returns_httperror_contents(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        error_body = b'{"errors": {"error": [{"error-message": "not found"}]}}'
        self.mock_connection.send.side_effect = HTTPError(
            'http://bigip.local', 404, 'Not Found', {}, io.BytesIO(error_body)
        )

        result = self.httpapi.send_request(path='/restconf/data/test', method='GET')

        assert result['code'] == 404
        assert result['contents'] == 'not found'

    def test_rseries_software_version_success(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        version_response = {
            'f5-system-image:install': {
                'install-os-version': '1.5.1-10781'
            }
        }
        self.mock_connection.send.return_value = connection_response(version_response, 200)

        result = self.httpapi._rseries_software_version()
        assert result == '1.5.1-10781'

    def test_rseries_software_version_error(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'error': 'fail'}, 500)

        with self.assertRaises(F5ModuleError):
            self.httpapi._rseries_software_version()

    def test_velos_software_version_success(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        version_response = {
            'openconfig-platform:component': [{
                'f5-platform:software': {
                    'state': {
                        'software-components': {
                            'software-component': [{
                                'state': {
                                    'version': '1.6.0-12345'
                                }
                            }]
                        }
                    }
                }
            }]
        }
        self.mock_connection.send.return_value = connection_response(version_response, 200)

        result = self.httpapi._velos_software_version()
        assert result == '1.6.0-12345'

    def test_velos_software_version_error(self):
        self.httpapi.get_option = Mock(return_value={})
        self.mock_connection.get_option = Mock(return_value=8888)
        self.mock_connection.send.return_value = connection_response({'error': 'fail'}, 500)

        with self.assertRaises(F5ModuleError):
            self.httpapi._velos_software_version()

    def test_set_software_version_velos_partition(self):
        self.httpapi.platform_type = 'Velos Partition'
        self.httpapi._velos_software_version = Mock(return_value='1.6.0-12345')

        self.httpapi._set_software_version()

        assert self.httpapi.software_version == '1.6.0-12345'

    def test_set_software_version_rseries(self):
        self.httpapi.platform_type = 'rSeries Platform'
        self.httpapi._rseries_software_version = Mock(return_value='1.5.1-10781')

        self.httpapi._set_software_version()

        assert self.httpapi.software_version == '1.5.1-10781'

    def test_set_software_version_velos_controller_does_nothing(self):
        self.httpapi.platform_type = 'Velos Controller'

        self.httpapi._set_software_version()

        assert self.httpapi.software_version is None

    def test_get_software_version(self):
        self.httpapi.software_version = '1.5.1-10781'
        assert self.httpapi.get_software_version() == '1.5.1-10781'

    def test_get_capabilities(self):
        self.httpapi.platform_type = 'rSeries Platform'
        self.httpapi.software_version = '1.5.1-10781'

        result = json.loads(self.httpapi.get_capabilities())

        assert result['platform'] == 'rSeries Platform'
        assert result['software_version'] == '1.5.1-10781'
        assert result['network_os'] == 'f5networks.f5os.f5os'
        assert 'f5networks.f5os.f5os_facts' in result['network_api_capabilities']['supported_modules']

    def test_get_capabilities_empty_platform(self):
        result = json.loads(self.httpapi.get_capabilities())

        assert result['platform'] == ''
        assert result['software_version'] == ''

    def test_response_to_json_empty_string(self):
        result = self.httpapi._response_to_json('')
        assert result == {}

    def test_response_to_json_valid(self):
        result = self.httpapi._response_to_json('{"key": "value"}')
        assert result == {'key': 'value'}

    def test_handle_httperror_non_401(self):
        exc = HTTPError('http://bigip.local', 500, '', {}, StringIO('{"error": "server error"}'))
        result = self.httpapi.handle_httperror(exc)
        assert result is False

    def test_handle_httperror_401_without_prior_auth(self):
        self.mock_connection._auth = None
        exc = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"error": "unauthorized"}'))
        result = self.httpapi.handle_httperror(exc)
        assert result is False

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

    def test_handle_errors_bytes_input(self):
        result = handle_errors(b'raw error message')
        assert result == 'raw error message'

    def test_handle_errors_json_without_errors_key(self):
        body = b'{"some_key": "some_value"}'
        error = HTTPError('foo', 400, 'bad request', None, io.BytesIO(body))
        result = handle_errors(error)
        assert result == {'some_key': 'some_value'}

    def test_handle_errors_seek_unsupported(self):
        error_mock = Mock()
        error_mock.read.side_effect = [json.JSONDecodeError('test', '', 0), b'fallback']
        error_mock.seek.side_effect = io.UnsupportedOperation('seek')
        result = handle_errors(error_mock)
        assert 'fallback' in str(result)

    def test_check_seek_raising_false(self):
        error_mock = Mock()
        error_mock.seek.return_value = None
        assert _check_seek_raising(error_mock) is False

    def test_check_seek_raising_true(self):
        error_mock = Mock()
        error_mock.seek.side_effect = io.UnsupportedOperation('seek')
        assert _check_seek_raising(error_mock) is True
