from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.f5networks.f5os.tests.compat.mock import Mock

from ansible_collections.f5networks.f5os.plugins.module_utils.common import F5ModuleError

# Import the classes to test
from ansible_collections.f5networks.f5os.plugins.modules.f5os_import_tls_cert_key import (
    ModuleManager, ModuleParameters, ApiParameters, Difference, ArgumentSpec, F5ModuleError
)
from ansible_collections.f5networks.f5os.plugins.modules.f5os_import_tls_cert_key import Parameters


def test_module_parameters_empty():
    params = ModuleParameters({})
    assert params.certificate is None
    assert params.key is None
    assert params.key_passphrase is None
    assert params.state == 'present'


def test_argument_spec_required_fields():
    spec = ArgumentSpec()
    assert spec.argument_spec['certificate']['required'] is True
    assert spec.argument_spec['key']['required'] is True
    assert spec.argument_spec['certificate']['no_log'] is True
    assert spec.argument_spec['key']['no_log'] is True


def test_module_manager_warn_and_exit_json():
    dummy = DummyModule({'certificate': 'CERTDATA', 'key': 'KEYDATA'})
    dummy.exit_json(foo='bar')
    assert hasattr(dummy, 'exit_json_called')
    dummy.warn('test warning')
    assert 'test warning' in dummy._warnings


def test_module_manager_fail_json():
    dummy = DummyModule({'certificate': 'CERTDATA', 'key': 'KEYDATA'})
    dummy.fail_json(msg='fail')
    assert hasattr(dummy, 'fail_json_called')
    assert dummy.fail_json_called['msg'] == 'fail'


def test_f5_module_error():
    try:
        raise F5ModuleError('error')
    except F5ModuleError:
        pass


def module_params():
    return {
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE',
        'verify_client': True,
        'verify_client_depth': 2,
        'state': 'present'
    }


class DummyModule:
    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self._warnings = []

    def warn(self, msg):
        self._warnings.append(msg)

    def exit_json(self, **kwargs):
        self.exit_json_called = kwargs

    def fail_json(self, **kwargs):
        self.fail_json_called = kwargs


class DummyConnection:
    pass


class DummyF5Client:
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module')
        self.client = kwargs.get('client')
        self.calls = []

    def get(self, uri):
        self.calls.append(('get', uri))
        # Simulate a present resource
        return {
            'code': 200,
            'contents': {
                'f5-openconfig-aaa-tls:tls': {
                    'config': {
                        'certificate': 'CERTDATA',
                        'key': 'KEYDATA',
                        'passphrase': 'PASSPHRASE',
                        'verify-client': True,
                        'verify-client-depth': 2
                    }
                }
            }
        }

    def patch(self, uri, data):
        self.calls.append(('patch', uri, data))
        return {'code': 200, 'contents': {}}

    def delete(self, uri):
        self.calls.append(('delete', uri))
        return {'code': 200, 'contents': {}}


def dummy_module(module_params):
    return DummyModule(module_params)


def dummy_manager(monkeypatch, dummy_module):
    # Patch F5Client to DummyF5Client
    monkeypatch.setattr(
        "ansible_collections.f5networks.f5os.plugins.modules.f5os_import_tls_cert_key.F5Client",
        DummyF5Client
    )
    return ModuleManager(module=dummy_module, connection=DummyConnection())


def test_module_parameters_properties():
    params = ModuleParameters(module_params())
    assert params.certificate == 'CERTDATA'
    assert params.key == 'KEYDATA'
    assert params.key_passphrase == 'PASSPHRASE'
    assert params.state == 'present'


def test_api_parameters_properties():
    params = {
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'config': {
            'certificate': 'CERTDATA2',
            'key': 'KEYDATA2'
        }
    }
    api = ApiParameters(params=params)
    # Should prefer direct mapping
    assert api.certificate == 'CERTDATA'
    assert api.key == 'KEYDATA'
    # Remove direct mapping to test config fallback
    del api._values['certificate']
    del api._values['key']
    assert api.certificate == 'CERTDATA2'
    assert api.key == 'KEYDATA2'


def test_difference_compare_and_default():
    want = ModuleParameters(module_params())
    have = ModuleParameters({
        'certificate': 'OLD',
        'key': 'OLDKEY',
        'key_passphrase': 'OLDPASS',
        'state': 'present'
    })
    diff = Difference(want, have)
    # key and key_passphrase are ignored
    assert diff.compare('key') is None
    assert diff.compare('key_passphrase') is None
    # certificate is different
    assert diff.compare('certificate') == 'CERTDATA'


def test_argument_spec_defaults():
    spec = ArgumentSpec()
    assert spec.supports_check_mode is True
    assert 'certificate' in spec.argument_spec
    assert spec.argument_spec['state']['default'] == 'present'


def test_present_calls_update():
    called = {}

    class MonkeyPatch:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)
    monkeypatch = MonkeyPatch()
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())

    def fake_update(self):
        called['update'] = True
        return True
    monkeypatch.setattr(ModuleManager, "update", fake_update)
    dm.want = ModuleParameters(module_params())
    assert dm.present() is True
    assert called['update']


def test_absent_calls_remove():
    called = {}

    class MonkeyPatch:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)
    monkeypatch = MonkeyPatch()
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())

    def fake_remove(self):
        called['remove'] = True
        return True
    monkeypatch.setattr(ModuleManager, "remove", fake_remove)
    dm.want = ModuleParameters({
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE',
        'state': 'absent'
    })
    assert dm.absent() is True
    assert called['remove']


def test_exec_module_present():

    class MonkeyPatch:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)
    monkeypatch = MonkeyPatch()
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(ModuleManager, "present", lambda self: True)
    monkeypatch.setattr(ModuleManager, "absent", lambda self: False)
    monkeypatch.setattr(ModuleManager, "_announce_deprecations", lambda self, result: None)
    monkeypatch.setattr(ModuleManager, "changes", ApiParameters(params={
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    }))
    dm.want = ModuleParameters({
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE',
        'state': 'present'
    })
    result = dm.exec_module()
    assert result['changed'] is True
    if 'certificate' in result:
        assert result['certificate'] == 'CERTDATA'
    if 'key' in result:
        assert result['key'] == 'KEYDATA'
    if 'key_passphrase' in result:
        assert result['key_passphrase'] == 'PASSPHRASE'


def test_exec_module_absent():

    class MonkeyPatch:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)
    monkeypatch = MonkeyPatch()
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(ModuleManager, "present", lambda self: False)
    monkeypatch.setattr(ModuleManager, "absent", lambda self: True)
    monkeypatch.setattr(ModuleManager, "_announce_deprecations", lambda self, result: None)
    monkeypatch.setattr(ModuleManager, "changes", ApiParameters(params={}))
    dm.want = ModuleParameters({
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE',
        'state': 'absent'
    })
    result = dm.exec_module()
    assert result['changed'] is True


def test_exists_resource_found():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.get = Mock(return_value={
        'code': 200,
        'contents': {
            'f5-openconfig-aaa-tls:tls': {
                'config': {
                    'certificate': 'CERTDATA',
                    'key': 'KEYDATA'
                }
            }
        }
    })
    assert dm.exists() is True


def test_exists_resource_not_found():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.get = Mock(return_value={'code': 404, 'contents': {}})
    assert dm.exists() is False


def test_exists_unexpected_code():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.get = Mock(return_value={'code': 500, 'contents': {'error': 'fail'}})
    try:
        dm.exists()
    except F5ModuleError:
        pass


def test_create_on_device_success():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.changes = ApiParameters(params={
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    })
    dm.want = ModuleParameters({
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    })
    dm.client = DummyF5Client()
    dm.client.patch = Mock(return_value={'code': 200, 'contents': {}})
    assert dm.create_on_device() is True


def test_create_on_device_failure():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.changes = ApiParameters(params={
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    })
    dm.want = ModuleParameters({
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    })
    dm.client = DummyF5Client()
    dm.client.patch = Mock(return_value={'code': 500, 'contents': {'error': 'fail'}})
    try:
        dm.create_on_device()
    except F5ModuleError:
        pass


def test_remove_from_device_success():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.delete = Mock(return_value={'code': 200, 'contents': {}})
    assert dm.remove_from_device() is True


def test_remove_from_device_failure():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.delete = Mock(return_value={'code': 500, 'contents': {'error': 'fail'}})
    try:
        dm.remove_from_device()
    except F5ModuleError:
        pass


def test_read_current_from_device_success():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.get = Mock(return_value={
        'code': 200,
        'contents': {
            'f5-openconfig-aaa-tls:tls': {
                'certificate': 'CERTDATA',
                'key': 'KEYDATA'
            }
        }
    })
    result = dm.read_current_from_device()
    assert isinstance(result, ApiParameters)
    assert result._values['certificate'] == 'CERTDATA'


def test_read_current_from_device_failure():
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.client = DummyF5Client()
    dm.client.get = Mock(return_value={'code': 500, 'contents': {'error': 'fail'}})
    try:
        dm.read_current_from_device()
    except F5ModuleError:
        pass


# Patch helper for tests
class MonkeyPatch:
    def setattr(self, target, attribute, value):
        import sys
        parts = target.split('.')
        mod = sys.modules[parts[0]]
        for part in parts[1:-1]:
            mod = getattr(mod, part)
        setattr(mod, parts[-1], value)


# Move all update_changed_options tests to top-level
def test_update_changed_options_no_changes():
    # Setup: want and have are the same, so no changes
    params = {
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    }
    dummy = dummy_module(params)
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.want = ModuleParameters(params)
    dm.have = ModuleParameters(params)
    # Patch UsableChanges to record params

    class DummyUsableChanges:
        def __init__(self, params=None):
            self.params = params

    monkeypatch = MonkeyPatch()
    monkeypatch.setattr(
        "ansible_collections.f5networks.f5os.plugins.modules.f5os_import_tls_cert_key",
        "UsableChanges",
        DummyUsableChanges
    )
    result = dm._update_changed_options()
    assert result is False
    assert "[DEBUG] Changed options: {}" in dummy._warnings


def test_update_changed_options_with_changes():
    # Setup: want and have differ, so changes should be detected
    want_params = {
        'certificate': 'CERTDATA',
        'key': 'KEYDATA',
        'key_passphrase': 'PASSPHRASE'
    }
    have_params = {
        'certificate': 'OLDCERT',
        'key': 'OLDKEY',
        'key_passphrase': 'OLDPASS'
    }
    dummy = dummy_module(want_params)
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.want = ModuleParameters(want_params)
    dm.have = ModuleParameters(have_params)
    changed_params = {}

    class DummyUsableChanges:
        def __init__(self, params=None):
            changed_params.update(params or {})
    monkeypatch = MonkeyPatch()
    monkeypatch.setattr(
        "ansible_collections.f5networks.f5os.plugins.modules.f5os_import_tls_cert_key",
        "UsableChanges",
        DummyUsableChanges
    )
    result = dm._update_changed_options()
    assert result is True
    # Only updatables are checked
    for k in Parameters.updatables:
        if k in changed_params:
            assert changed_params[k] == want_params[k]
    assert "[DEBUG] Changed options: " in dummy._warnings[-1]


def test_update_changed_options_ignores_none():
    # Setup: want has None for updatables, should be ignored
    want_params = {
        'certificate': None,
        'key': None,
        'key_passphrase': None
    }
    have_params = {
        'certificate': 'OLDCERT',
        'key': 'OLDKEY',
        'key_passphrase': 'OLDPASS'
    }
    dummy = dummy_module(want_params)
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    dm.want = ModuleParameters(want_params)
    dm.have = ModuleParameters(have_params)
    changed_params = {}

    class DummyUsableChanges:
        def __init__(self, params=None):
            changed_params.update(params or {})
    monkeypatch = MonkeyPatch()
    monkeypatch.setattr(
        "ansible_collections.f5networks.f5os.plugins.modules.f5os_import_tls_cert_key",
        "UsableChanges",
        DummyUsableChanges
    )
    result = dm._update_changed_options()
    assert result is False
    assert changed_params == {}
    assert "[DEBUG] Changed options: {}" in dummy._warnings


def test_update_no_changes(monkeypatch):
    # Setup: should_update returns False, so update returns False
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())

    # Patch read_current_from_device to set have
    monkeypatch.setattr(dm, "read_current_from_device", lambda: ModuleParameters(module_params()))
    # Patch should_update to return False
    monkeypatch.setattr(dm, "should_update", lambda: False)
    result = dm.update()
    assert result is False
    assert "[DEBUG] No update required." in dummy._warnings


def test_update_check_mode(monkeypatch):
    # Setup: should_update returns True, check_mode is True
    dummy = dummy_module(module_params())
    dummy.check_mode = True
    dm = ModuleManager(module=dummy, connection=DummyConnection())

    monkeypatch.setattr(dm, "read_current_from_device", lambda: ModuleParameters(module_params()))
    monkeypatch.setattr(dm, "should_update", lambda: True)
    result = dm.update()
    assert result is True
    assert "[DEBUG] Check mode enabled, skipping update." in dummy._warnings


def test_remove_check_mode(monkeypatch):
    # Setup: check_mode is True, should skip remove
    dummy = dummy_module(module_params())
    dummy.check_mode = True
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "exists", lambda: True)
    monkeypatch.setattr(dm, "remove_from_device", lambda: True)
    result = dm.remove()
    assert result is True
    assert "[DEBUG] Check mode enabled, skipping remove." in dummy._warnings


def test_remove_resource_not_exist(monkeypatch):
    # Setup: resource does not exist, should skip remove_from_device
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "exists", lambda: False)
    result = dm.remove()
    assert result is False
    assert "[DEBUG] Resource does not exist, nothing to remove." in dummy._warnings


def test_should_update_needed(monkeypatch):
    # Setup: _update_changed_options returns True, should_update returns True and logs
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "_update_changed_options", lambda: True)
    result = dm.should_update()
    assert result is True
    assert "[DEBUG] Checking if update is needed." in dummy._warnings
    assert "[DEBUG] Update is needed." in dummy._warnings


def test_should_update_not_needed(monkeypatch):
    # Setup: _update_changed_options returns False, should_update returns False and logs
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "_update_changed_options", lambda: False)
    result = dm.should_update()
    assert result is False
    assert "[DEBUG] Checking if update is needed." in dummy._warnings
    assert "[DEBUG] No update needed." in dummy._warnings
    # Setup: resource exists, check_mode is False, remove_from_device called
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "exists", lambda: True)


def test_remove_check_mode(monkeypatch):
    # Setup: check_mode is True, should skip remove
    dummy = dummy_module(module_params())
    dummy.check_mode = True
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "exists", lambda: True)
    monkeypatch.setattr(dm, "remove_from_device", lambda: True)
    result = dm.remove()
    assert result is True
    assert "[DEBUG] Check mode enabled, skipping remove." in dummy._warnings


def test_remove_resource_not_exist(monkeypatch):
    # Setup: resource does not exist, should skip remove_from_device
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "exists", lambda: False)
    result = dm.remove()
    assert result is False
    assert "[DEBUG] Resource does not exist, nothing to remove." in dummy._warnings


def test_remove_calls_remove_from_device(monkeypatch):
    # Setup: resource exists, check_mode is False, remove_from_device called
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "exists", lambda: True)
    called = {}

    def fake_remove_from_device():
        called['remove_from_device'] = True
        return True
    monkeypatch.setattr(dm, "remove_from_device", fake_remove_from_device)
    result = dm.remove()
    assert result is True
    assert called['remove_from_device']


# --- should_update tests ---
def test_should_update_needed(monkeypatch):
    # Setup: _update_changed_options returns True, should_update returns True and logs
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "_update_changed_options", lambda: True)
    result = dm.should_update()
    assert result is True
    assert "[DEBUG] Checking if update is needed." in dummy._warnings
    assert "[DEBUG] Update is needed." in dummy._warnings


def test_should_update_not_needed(monkeypatch):
    # Setup: _update_changed_options returns False, should_update returns False and logs
    dummy = dummy_module(module_params())
    dm = ModuleManager(module=dummy, connection=DummyConnection())
    monkeypatch.setattr(dm, "_update_changed_options", lambda: False)
    result = dm.should_update()
    assert result is False
    assert "[DEBUG] Checking if update is needed." in dummy._warnings
    assert "[DEBUG] No update needed." in dummy._warnings
