# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_install import (
    ArgumentSpec, ModuleManager, ModuleParameters
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.f5os.tests.compat import unittest
from ansible_collections.f5networks.f5os.tests.compat.mock import Mock, patch
from ansible_collections.f5networks.f5os.tests.modules.utils import (
    set_module_args, exit_json, fail_json
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


class TestModuleParameters(unittest.TestCase):
    def test_timeout_valid(self):
        args = dict(timeout=300, image_version='1.8.0-14139', partition_name=None, state='install')
        p = ModuleParameters(params=args)
        delay, divisor = p.timeout
        self.assertEqual(divisor, 100)
        self.assertEqual(delay, 3.0)

    def test_timeout_too_low(self):
        args = dict(timeout=100, image_version='1.8.0-14139', partition_name=None, state='install')
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.timeout
        self.assertIn("Timeout value must be between 150 and 3600 seconds", str(err.exception))

    def test_timeout_too_high(self):
        args = dict(timeout=4000, image_version='1.8.0-14139', partition_name=None, state='install')
        p = ModuleParameters(params=args)
        with self.assertRaises(F5ModuleError) as err:
            p.timeout
        self.assertIn("Timeout value must be between 150 and 3600 seconds", str(err.exception))

    def test_image_version(self):
        args = dict(timeout=300, image_version='1.8.0-14139', partition_name=None, state='install')
        p = ModuleParameters(params=args)
        self.assertEqual(p.image_version, '1.8.0-14139')

    def test_image_version_none(self):
        args = dict(timeout=300, image_version=None, partition_name=None, state='install')
        p = ModuleParameters(params=args)
        self.assertIsNone(p.image_version)


@patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_install.time.sleep', Mock())
class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()
        self.p1 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_install.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = Mock()
        self.p2 = patch('ansible_collections.f5networks.f5os.plugins.modules.f5os_system_image_install.send_teem')
        self.m2 = self.p2.start()
        self.m2.return_value = True

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    # --- rSeries Platform tests ---

    def test_rseries_image_already_installed(self):
        """Test install state when image version already installed on rSeries (idempotent)."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {
            "f5-system-image:install": {
                "install-os-version": "1.8.0-14139",
                "install-service-version": "1.8.0-14139",
                "install-status": "success"
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': get_data})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_rseries_install_image(self):
        """Test install on rSeries when version not installed."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        # exists() returns False - different version installed
        get_data = {
            "f5-system-image:install": {
                "install-os-version": "1.7.0-11111",
                "install-service-version": "1.7.0-11111",
                "install-status": "success"
            }
        }
        post_data = {
            'f5-system-image:output': {
                'response': 'System ISO version has been set.\nEstimated time: 11 minutes\nReboot(s): 1'
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': get_data})
        mm.client.post = Mock(return_value={'code': 200, 'contents': post_data})
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_rseries_install_image_post_error(self):
        """Test install on rSeries when post returns error."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {
            "f5-system-image:install": {
                "install-os-version": "1.7.0-11111",
                "install-service-version": "1.7.0-11111",
                "install-status": "success"
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': get_data})
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'server error'})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to install system image", str(err.exception))

    def test_rseries_install_file_import_in_progress(self):
        """Test install on rSeries when file import is in progress."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {
            "f5-system-image:install": {
                "install-os-version": "1.7.0-11111",
                "install-service-version": "1.7.0-11111",
                "install-status": "success"
            }
        }
        post_data = {
            'f5-system-image:output': {
                'response': 'File import with same local file name is in progress'
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': get_data})
        mm.client.post = Mock(return_value={'code': 200, 'contents': post_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("File import with same local file name is in progress", str(err.exception))

    def test_rseries_install_no_output_key(self):
        """Test install on rSeries when response has no output key."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        get_data = {
            "f5-system-image:install": {
                "install-os-version": "1.7.0-11111",
                "install-service-version": "1.7.0-11111",
                "install-status": "success"
            }
        }
        # Response without f5-system-image:output key
        post_data = {'some-other-key': 'value'}
        mm.client.get = Mock(return_value={'code': 200, 'contents': get_data})
        mm.client.post = Mock(return_value={'code': 200, 'contents': post_data})
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_rseries_exists_404(self):
        """Test exists() returns False on 404 for rSeries."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 404, 'contents': {}})
        mm.client.post = Mock(return_value={'code': 200, 'contents': {'f5-system-image:output': {'response': 'System ISO version has been set.'}}})
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_rseries_exists_unexpected_error(self):
        """Test exists() raises on unexpected error code."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'server error'})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Unexpected", str(err.exception))

    # --- Velos Controller tests ---

    def test_velos_controller_install_image(self):
        """Test install on Velos Controller."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        # exists() - 404 on first URI, then controller check doesn't find version
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.7.0-11111"}
                ]}}
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 404, 'contents': {}},
            {'code': 200, 'contents': controller_data},
        ])
        post_data = {
            'f5-system-controller-image:output': {
                'response': 'System ISO version has been set.\nEstimated time: 15 minutes'
            }
        }
        mm.client.post = Mock(return_value={'code': 200, 'contents': post_data})
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_velos_controller_image_already_installed(self):
        """Test Velos Controller when image version already installed (idempotent)."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.8.0-14139"}
                ]}}
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 404, 'contents': {}},
            {'code': 200, 'contents': controller_data},
        ])
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_velos_controller_exists_get_error(self):
        """Test Velos Controller exists() raises on API error."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        mm.client.get = Mock(side_effect=[
            {'code': 404, 'contents': {}},
            {'code': 500, 'contents': 'server error'},
        ])
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_velos_controller_install_post_error(self):
        """Test Velos Controller install post error."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.7.0-11111"}
                ]}}
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 404, 'contents': {}},
            {'code': 200, 'contents': controller_data},
        ])
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'server error'})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to install system image", str(err.exception))

    def test_velos_controller_install_file_import_in_progress(self):
        """Test Velos Controller install when file import in progress."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.7.0-11111"}
                ]}}
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 404, 'contents': {}},
            {'code': 200, 'contents': controller_data},
        ])
        post_data = {
            'f5-system-controller-image:output': {
                'response': 'File import with same local file name is in progress'
            }
        }
        mm.client.post = Mock(return_value={'code': 200, 'contents': post_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("File import with same local file name is in progress", str(err.exception))

    def test_velos_controller_install_no_output_key(self):
        """Test Velos Controller install when response has no output key."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.7.0-11111"}
                ]}}
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 404, 'contents': {}},
            {'code': 200, 'contents': controller_data},
        ])
        post_data = {'other-key': 'value'}
        mm.client.post = Mock(return_value={'code': 200, 'contents': post_data})
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    # --- Velos Partition tests ---

    def test_velos_partition_platform_raises(self):
        """Test that Velos Partition platform raises immediately."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Partition'
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Velos Partition", str(err.exception))

    # --- Partition name (set-version) tests ---

    def test_partition_install_success(self):
        """Test partition image set-version (install)."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        # check_partition: partition exists with different version
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.5.0-12345"}}
                ]
            }
        }
        # update_partition_image: image exists in partition iso list
        iso_data = {
            "f5-system-image:iso": {
                "iso": [
                    {"version": "1.6.2-30244"},
                    {"version": "1.5.0-12345"}
                ]
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': partition_data},
            {'code': 200, 'contents': iso_data},
        ])
        mm.client.post = Mock(return_value={'code': 200, 'contents': {}})
        results = mm.exec_module()
        self.assertTrue(results['changed'])

    def test_partition_already_at_version(self):
        """Test partition already at target version (idempotent)."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.6.2-30244"}}
                ]
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': partition_data})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_partition_not_found(self):
        """Test partition does not exist raises error."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='nonexistent',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "other_partition", "config": {"iso-version": "1.5.0-12345"}}
                ]
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': partition_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Partition does not exists", str(err.exception))

    def test_partition_check_api_error(self):
        """Test check_partition raises on API error."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'error'})
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_partition_image_not_available(self):
        """Test update_partition_image raises when image not in available list."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.5.0-12345"}}
                ]
            }
        }
        # No matching ISO version
        iso_data = {
            "f5-system-image:iso": {
                "iso": [
                    {"version": "1.5.0-12345"}
                ]
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': partition_data},
            {'code': 200, 'contents': iso_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("does not exists", str(err.exception))

    def test_partition_image_get_error(self):
        """Test update_partition_image raises when get ISO list fails."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.5.0-12345"}}
                ]
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': partition_data},
            {'code': 500, 'contents': 'error'},
        ])
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_partition_set_version_post_error(self):
        """Test update_partition_image raises when set-version post fails."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.5.0-12345"}}
                ]
            }
        }
        iso_data = {
            "f5-system-image:iso": {
                "iso": [{"version": "1.6.2-30244"}]
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': partition_data},
            {'code': 200, 'contents': iso_data},
        ])
        mm.client.post = Mock(return_value={'code': 500, 'contents': 'error'})
        with self.assertRaises(F5ModuleError):
            mm.exec_module()

    def test_partition_empty_partitions_list(self):
        """Test check_partition with empty partitions response."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        # Empty partitions
        partition_data = {"f5-system-partition:partitions": {"partition": []}}
        mm.client.get = Mock(return_value={'code': 200, 'contents': partition_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Partition does not exists", str(err.exception))

    # --- state=present (install_status_complete) tests ---

    def test_rseries_present_install_complete(self):
        """Test state=present on rSeries when install is already complete."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        install_data = {
            "f5-system-image:install": {
                "install-os-version": "1.8.0-14139",
                "install-service-version": "1.8.0-14139",
                "install-status": "success"
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': install_data})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_rseries_present_still_installing_then_complete(self):
        """Test state=present on rSeries polling until complete."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        in_progress = {
            "f5-system-image:install": {
                "install-os-version": "1.8.0-14139",
                "install-service-version": "1.8.0-14139",
                "install-status": "in-progress"
            }
        }
        complete = {
            "f5-system-image:install": {
                "install-os-version": "1.8.0-14139",
                "install-service-version": "1.8.0-14139",
                "install-status": "success"
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': in_progress},
            {'code': 200, 'contents': complete},
        ])
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_rseries_present_timeout(self):
        """Test state=present on rSeries that times out."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        in_progress = {
            "f5-system-image:install": {
                "install-os-version": "1.8.0-14139",
                "install-service-version": "1.8.0-14139",
                "install-status": "in-progress"
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': in_progress})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    def test_rseries_is_still_installing_api_error(self):
        """Test is_still_installing raises on API error for rSeries."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'error'})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to check the status", str(err.exception))

    def test_velos_controller_present_complete(self):
        """Test state=present on Velos Controller when install complete."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.8.0-14139"}
                ]}}
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': controller_data})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_velos_controller_present_still_installing(self):
        """Test state=present on Velos Controller still installing then complete."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        in_progress = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "in-progress", "os-version": "1.8.0-14139"}
                ]}}
            }
        }
        complete = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.8.0-14139"}
                ]}}
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': in_progress},
            {'code': 200, 'contents': complete},
        ])
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_velos_controller_present_version_not_found(self):
        """Test state=present on Velos Controller when version not in controller list."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        controller_data = {
            "f5-system-controller-image:image": {
                "state": {"controllers": {"controller": [
                    {"install-status": "success", "os-version": "1.7.0-11111"}
                ]}}
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': controller_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("not found in controller install status", str(err.exception))

    def test_velos_controller_present_api_error(self):
        """Test state=present on Velos Controller API error."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'error'})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to check the status", str(err.exception))

    def test_unsupported_platform_is_still_installing(self):
        """Test is_still_installing raises for unsupported platform."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Unknown Platform'
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Unsupported platform", str(err.exception))

    # --- Partition present (install status) tests ---

    def test_partition_present_install_complete(self):
        """Test state=present with partition_name when install is complete."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.6.2-30244"},
                     "state": {"install-status": "success"}}
                ]
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': partition_data})
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_partition_present_in_progress_then_success(self):
        """Test state=present with partition_name polling until success."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        in_progress_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.6.2-30244"},
                     "state": {"install-status": ["in-progress", "switching-role", "pending"]}}
                ]
            }
        }
        success_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.6.2-30244"},
                     "state": {"install-status": "success"}}
                ]
            }
        }
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': in_progress_data},
            {'code': 200, 'contents': success_data},
        ])
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    def test_partition_present_install_failed(self):
        """Test state=present with partition_name when install fails."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        failed_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.6.2-30244"},
                     "state": {"install-status": "failed"}}
                ]
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': failed_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Installation Failed", str(err.exception))

    def test_partition_present_api_error(self):
        """Test state=present with partition_name API error."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='present',
            timeout=300,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        mm.client.get = Mock(return_value={'code': 500, 'contents': 'error'})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Failed to check the status", str(err.exception))

    def test_partition_present_timeout(self):
        """Test state=present with partition_name times out."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='present',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        # Partition with no 'state' key - is_still_installing won't match any condition
        # so it falls through without returning, which means the loop continues
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.6.2-30244"},
                     "state": {"install-status": ["in-progress", "switching-role", "pending"]}}
                ]
            }
        }
        mm.client.get = Mock(return_value={'code': 200, 'contents': partition_data})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    # --- state=absent tests ---

    def test_absent_returns_no_change(self):
        """Test state=absent always returns no change."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='absent',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'
        results = mm.exec_module()
        self.assertFalse(results['changed'])

    # --- ConnectionError handling ---

    def test_connection_error_returns_still_installing(self):
        """Test that ConnectionError during status check returns True (still installing)."""
        set_module_args(dict(
            image_version='1.8.0-14139',
            state='present',
            timeout=150,
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'rSeries Platform'

        # Simulate ConnectionError - the module catches it and returns True
        class ConnectionError(Exception):
            pass

        conn_err = ConnectionError("connection reset")
        mm.client.get = Mock(side_effect=conn_err)
        # Since ConnectionError makes is_still_installing return True, it will timeout
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Module timeout reached", str(err.exception))

    # --- check_partition edge cases ---

    def test_check_partition_no_partitions_key(self):
        """Test check_partition when response has no f5-system-partition:partitions key."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        # Response without the expected key
        mm.client.get = Mock(return_value={'code': 200, 'contents': {}})
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("Partition does not exists", str(err.exception))

    def test_partition_iso_empty_list(self):
        """Test update_partition_image when ISO list is empty."""
        set_module_args(dict(
            image_version='1.6.2-30244',
            partition_name='test_partition',
            state='install',
        ))
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.client.platform = 'Velos Controller'
        partition_data = {
            "f5-system-partition:partitions": {
                "partition": [
                    {"name": "test_partition", "config": {"iso-version": "1.5.0-12345"}}
                ]
            }
        }
        # Empty ISO response (no f5-system-image:iso key)
        iso_data = {"other-key": "value"}
        mm.client.get = Mock(side_effect=[
            {'code': 200, 'contents': partition_data},
            {'code': 200, 'contents': iso_data},
        ])
        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn("does not exists", str(err.exception))
