# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules.f5os_vlan import (
    ModuleParameters, ArgumentSpec, ModuleManager
)
from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5os.tests.modules.utils import set_module_args

from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError


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


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            vlan_id=1234,
            name='foobar'
        )

        p = ModuleParameters(params=args)
        assert p.vlan_id == 1234
        assert p.name == "foobar"

    def test_module_parameters_invalid_vlan(self):
        args = dict(
            vlan_id=99999
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.vlan_id()

        assert "Valid 'vlan_id' must be in range 0 - 4095." in str(err.exception)

    def test_module_parameters_name_invalid_chars(self):
        args = dict(
            name='Services&_%$'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        assert 'Invalid characters detected in name parameter,' \
               ' check documentation for rules regarding naming.' in str(err.exception)

    def test_module_parameters_name_not_starting_with_letter(self):
        args = dict(
            name='5ervices.foo.bar'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        assert 'The name parameter must begin with a letter.' in str(err.exception)

    def test_module_parameters_name_exceed_length(self):
        args = dict(
            name='this.is.a.very.long.name.to.cause.errors.or_give_you_a_headache_just_from_looking_at_it'
        )

        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.name()

        assert 'The name parameter must not exceed 58 characters.' in str(err.exception)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_vlan.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_vlan.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_vlan_create(self, *args):
        set_module_args(dict(
            name="foobar",
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        expected = {'openconfig-vlan:vlans': {'vlan': [{'vlan-id': 1234, 'config': {'vlan-id': 1234, 'name': 'foobar'}}]}}
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=201, contents={}))

        results = mm.exec_module()
        assert results['changed'] is True
        assert mm.client.patch.call_args[1]['data'] == expected

    def test_vlan_update_name(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            name="new_name",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.platform = 'rSeries Platform'
        mm.client.patch = Mock(return_value=dict(code=204, contents=""))
        mm.client.get = Mock(return_value=dict(code=200, contents=load_fixture("load_velos_vlan_config.json")))

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.patch.assert_called_once_with(
            '/openconfig-vlan:vlans/vlan=3333/config/name', data=dict(name='new_name')
        )

    def test_vlan_delete(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.platform = 'rSeries Platform'
        mm.client.delete = Mock(return_value=dict(code=204, contents=""))

        results = mm.exec_module()

        assert results['changed'] is True
        mm.client.delete.assert_called_once_with('/openconfig-vlan:vlans/vlan=3333')

    def test_velos_controller_raises(self, *args):
        set_module_args(dict(
            vlan_id=3333,
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        assert 'Target device is a VELOS controller, aborting.' in str(err.exception)

    def test_vlan_create_name_missing_raises(self, *args):
        set_module_args(dict(
            vlan_id=1234,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)
        mm.client.platform = 'rSeries Platform'

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        assert 'Name parameter is required when creating new resource.' in str(err.exception)
