# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest.mock import Mock, patch
from unittest import TestCase

from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.f5os.plugins.module_utils.constants import (
    BASE_HEADERS, ROOT
)
from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)

from ansible_collections.f5networks.f5os.tests.utils.common import connection_response


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


class TestF5osClient(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.f5os.f5os"
        self.connection = connection_loader.get("ansible.netcommon.httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_GET_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='GET', headers=expected_header
        )

    def test_GET_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink')
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='GET', headers=BASE_HEADERS
        )

    def test_POST_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_POST_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='POST'
        )

    def test_PUT_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PUT_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PUT'
        )

    def test_PATCH_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_PATCH_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload)
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PATCH'
        )

    def test_DELETE_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='DELETE', headers=expected_header
        )

    def test_DELETE_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink')
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='DELETE', headers=BASE_HEADERS
        )

    def test_different_scope_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'}, scope='openconfig/different/scope')
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            'openconfig/different/scope/testlink', None, method='GET', headers=expected_header
        )

    def test_different_scope_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'}, scope='openconfig/different/scope')
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.connection.send.assert_called_once_with(
            'openconfig/different/scope/testlink', None, method='GET', headers=expected_header
        )

    def test_get_platform_rseries(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response(load_fixture('f5os_platform_response.json'), 200, xheader),
            connection_response(load_fixture('rseries_software_version.json'), 200, xheader),
        ]
        self.connection.httpapi.login('foo', 'bar')
        platform = self.client.platform

        assert platform == 'rSeries Platform'

    def test_get_platform_velos_controller(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response(dict(), 404, xheader),
            connection_response(load_fixture('f5os_controller_response.json'), 404, xheader)
        ]
        self.connection.httpapi.login('foo', 'bar')
        platform = self.client.platform

        assert platform == 'Velos Controller'

    def test_get_platform_velos_partition(self):
        xheader = {'X-Auth-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}
        xheader.update(BASE_HEADERS)
        self.connection.send.side_effect = [
            connection_response(load_fixture('f5os_auth.json'), 200, xheader),
            connection_response(dict(), 404, xheader),
            connection_response(dict(), 200, xheader),
            connection_response(load_fixture('velos_partition_version.json'), 200, xheader),
        ]
        self.connection.httpapi.login('foo', 'bar')
        platform = self.client.platform

        assert platform == 'Velos Partition'

    def test_send_teem(self):
        mock_response = Mock()
        self.connection.httpapi.get_option = mock_response
        self.connection.httpapi.get_option.side_effect = [True, False]

        with patch('ansible_collections.f5networks.f5os.plugins.module_utils.client.TeemClient') as patched:
            send_teem(self.client, 12345)
            result = send_teem(self.client, 12345)

        patched.assert_called_once()
        patched.return_value.send.assert_called_once()
        assert result is False

    def test_ansible_version_module_name(self):
        fake_module = Mock()
        fake_module._name = 'fake_module'
        fake_module.ansible_version = '3.10'
        f5_client = F5Client(module=fake_module)

        assert f5_client.module_name == 'fake_module'
        assert f5_client.ansible_version == '3.10'
