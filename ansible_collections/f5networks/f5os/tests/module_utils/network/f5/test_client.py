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

from ansible_collections.f5networks.f5os.plugins.module_utils.constants import (
    BASE_HEADERS, ROOT
)
from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)


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
        self.mock_send = Mock()
        self.connection = Mock()
        self.connection.send = self.mock_send
        self.connection.httpapi = Mock()
        self.connection.httpapi.send_request = self.mock_send
        self.connection.httpapi.get_platform_type = Mock(return_value='rSeries Platform')
        self.connection.httpapi.get_software_version = Mock(return_value='1.5.0')
        self.connection.httpapi.telemetry = Mock(return_value=False)
        self.client = F5Client(client=self.connection.httpapi)

    def test_GET_header_update_with_additional_headers(self):
        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', method='GET', headers=expected_header
        )

    def test_GET_header_update_without_additional_headers(self):
        self.client.get('/testlink')
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', method='GET', headers=BASE_HEADERS
        )

    def test_POST_header_update_with_additional_headers(self):
        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', payload=payload, method='POST', headers=expected_header
        )

    def test_POST_header_update_without_additional_headers(self):
        payload = {'Test': 'Payload'}

        self.client.post('/testlink', data=payload)
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', payload=payload, method='POST', headers=BASE_HEADERS
        )

    def test_PUT_header_update_with_additional_headers(self):
        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', payload=payload, method='PUT', headers=expected_header
        )

    def test_PUT_header_update_without_additional_headers(self):
        payload = {'Test': 'Payload'}

        self.client.put('/testlink', data=payload)
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', payload=payload, method='PUT', headers=BASE_HEADERS
        )

    def test_PATCH_header_update_with_additional_headers(self):
        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', payload=payload, method='PATCH', headers=expected_header
        )

    def test_PATCH_header_update_without_additional_headers(self):
        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', data=payload)
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', payload=payload, method='PATCH', headers=BASE_HEADERS
        )

    def test_DELETE_header_update_with_additional_headers(self):
        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', method='DELETE', headers=expected_header
        )

    def test_DELETE_header_update_without_additional_headers(self):
        self.client.delete('/testlink')
        self.mock_send.assert_called_once_with(
            path=ROOT + '/testlink', method='DELETE', headers=BASE_HEADERS
        )

    def test_different_scope_without_additional_headers(self):
        self.client.get('/testlink', scope='openconfig/different/scope')
        self.mock_send.assert_called_once_with(
            path='openconfig/different/scope/testlink', method='GET', headers=BASE_HEADERS
        )

    def test_different_scope_with_additional_headers(self):
        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'}, scope='openconfig/different/scope')
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/yang-data+json'}
        self.mock_send.assert_called_once_with(
            path='openconfig/different/scope/testlink', method='GET', headers=expected_header
        )

    def test_get_platform_rseries(self):
        self.connection.httpapi.get_platform_type.return_value = 'rSeries Platform'
        platform = self.client.platform

        assert platform == 'rSeries Platform'

    def test_get_platform_velos_controller(self):
        self.connection.httpapi.get_platform_type.return_value = 'Velos Controller'
        platform = self.client.platform

        assert platform == 'Velos Controller'

    def test_get_platform_velos_partition(self):
        self.connection.httpapi.get_platform_type.return_value = 'Velos Partition'
        platform = self.client.platform

        assert platform == 'Velos Partition'

    def test_send_teem(self):
        self.connection.httpapi.telemetry.side_effect = [True, False]

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

    def test_software_version(self):
        self.connection.httpapi.get_software_version.return_value = '1.5.0'
        assert self.client.software_version == '1.5.0'
