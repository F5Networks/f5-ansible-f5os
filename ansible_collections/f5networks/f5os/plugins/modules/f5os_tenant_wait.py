#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: f5os_tenant_wait
short_description: Wait for a F5OS tenant condition before continuing
description:
  - Wait for a F5OS tenant to be C(configured), C(provisioned), or C(deployed).
version_added: "1.0.0"
options:
  name:
    description:
      - Name of the tenant.
    type: str
    required: True
  state:
    description:
      - The condition for which the system is waiting.
      - Defaults to C(configured), which verifies the specified tenant has been created on
        the partition and is in the configured run-state.
      - C(provisioned) waits for the tenant running-state and status "provisioned".
      - C(deployed) waits for the tenant running-state "deployed", status "running", and phase "running".
      - C(ssh-ready) waits for a deployed tenant to be reachable via SSH.
      - C(api-ready) waits for a deployed tenant to be reachable via the REST API.
    type: str
    default: configured
    choices:
      - configured
      - provisioned
      - deployed
      - ssh-ready
      - api-ready
  timeout:
    description:
      - Maximum number of seconds to wait for the desired state.
    type: int
    default: 600
  delay:
    description:
      - Number of seconds to wait before starting to poll.
    type: int
    default: 0
  sleep:
    description:
      - Number of seconds to sleep between checks.
    type: int
    default: 1
  msg:
    description:
      - This overrides the normal error message from a failure to meet the required conditions.
    type: str
author:
  - Ravinder Reddy (@chinthalapalli)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Wait for the specified tenant to be in the configured state.
  f5os_tenant_wait:
    name: bigip_tenant1

- name: Wait a maximum of 300 seconds specified tenant to be in the provisioned state.
  f5os_tenant_wait:
    name: bigip_tenant1
    state: provisioned
    timeout: 300

- name: Wait 30 seconds before verifying the specified tenant to be in the deployed state.
  f5os_tenant_wait:
    name: bigip_tenant1
    state: deployed
    delay: 30

- name: Wait 30 seconds before verifying the specified tenant to be reachable via the REST API.
  f5os_tenant_wait:
    name: bigip_tenant1
    state: api-ready
    delay: 30

- name: Create tenant 'ansible-tenant01'
  f5os_tenant:
    name: ansible-tenant01
    image_name: BIGIP-17.5.0-0.0.15.ALL-F5OS.qcow2.zip.bundle
    nodes:
      - 1
    mgmt_ip: 10.xxx.xxx.xx
    mgmt_prefix: 24
    mgmt_gateway: 10.xxx.xxx.xxx
    cryptos: disabled
    virtual_disk_size: 85
    running_state: deployed
    state: present

- name: Wait for tenant to be deployed
  f5os_tenant_wait:
    name: ansible-tenant01
    state: deployed
    sleep: 30
    timeout: 300

- name: Wait for tenant to be api-ready
  f5os_tenant_wait:
    name: ansible-tenant01
    state: api-ready
    sleep: 30
    timeout: 300
'''

RETURN = r'''
elapsed:
  description: Seconds spent waiting for the requested state.
  returned: always
  type: int
  example: 600
tenant_state:
  description: State data for the specified tenant.
  returned: always
  type: complex
  contains:
    name:
      description: Name of the tenant.
      returned: always
      type: str
      example: 'defaultbip'
    type:
      description: Tenant type.
      returned: always
      type: str
      example: 'BIG-IP'
    blades:
      description: Blades allocated to tenant.
      returned: always
      type: int
      example: 1
    cryptos:
      description: Tenant crypto state. Enabled or Disabled.
      returned: always
      type: str
      example: 'disabled'
    cpu-cores:
      description: CPU Cores allocated to the tenant.
      returned: always
      type: str
      example: '1'
    memory:
      description: Memory allocated to the tenant.
      returned: always
      type: str
      example: '4092'
    running-state:
      description: Tenant running state.
      returned: always
      type: str
      example: 'defaultbip'
    mac-data:
      description: Tenant MAC pool details.
      returned: always
      type: dict
      example: hash/dictionary of values
    status:
      description: Tenant Running state.
      returned: always
      type: str
      example: 'Running'
    instances:
      description: Tenant instance details.
      returned: always
      type: dict
      example: hash/dictionary of values
'''

import datetime
import logging
import signal
import time
import traceback
from urllib.error import HTTPError, URLError
import threading

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None
    PARAMIKO_IMPORT_ERROR = traceback.format_exc()
    HAS_PARAMIKO = False
else:
    HAS_PARAMIKO = True
    PARAMIKO_IMPORT_ERROR = None

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
from ansible.module_utils.connection import (
    Connection, ConnectionError as AnsibleConnectionError
)
from ansible.module_utils.urls import open_url
from ansible_collections.f5networks.f5os.plugins.module_utils.client import (
    F5Client, send_teem
)
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)

# paramiko.transport is too chatty - it logs exceptions raised while attempting
# to connect to ssh servers before they are ready.
paramiko_logger = logging.getLogger("paramiko.transport")
setattr(paramiko_logger, 'disabled', True)


def hard_timeout(module, want, start):  # pragma: no cover
    elapsed = datetime.datetime.utcnow() - start
    module.fail_json(
        msg=want.msg or "Timeout when waiting for F5OS Tenant", elapsed=elapsed.seconds
    )


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [

    ]

    returnables = [
        'elapsed',
        'tenant_state'
    ]

    updatables = [

    ]

    def to_return(self):  # pragma: no cover
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = Parameters(params=self.module.params)
        self.changes = Parameters()
        self.have = None

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        if self.client.platform == 'Velos Controller':
            raise F5ModuleError("Target device is a VELOS controller, aborting.")
        start = datetime.datetime.now().isoformat()
        result = dict()

        changed = self.execute()

        changes = self.changes.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def execute(self):
        if self.want.delay >= self.want.timeout:
            raise F5ModuleError(
                "The delay should not be greater than or equal to the timeout."
            )
        if self.want.delay + self.want.sleep >= self.want.timeout:
            raise F5ModuleError(
                "The combined delay and sleep should not be greater than or equal to the timeout."
            )
        signal.signal(
            signal.SIGALRM,
            lambda sig, frame: hard_timeout(self.module, self.want, start)
        )
        start = datetime.datetime.now(datetime.timezone.utc)
        if self.want.delay:
            time.sleep(float(self.want.delay))
        end = start + datetime.timedelta(seconds=int(self.want.timeout))

        tenant_state = self.wait_for_tenant(start, end)
        elapsed = datetime.datetime.now(datetime.timezone.utc) - start
        self.changes.update({'elapsed': elapsed.seconds,
                             'tenant_state': tenant_state})
        return False

    def wait_for_tenant(self, start, end):
        api_ready_flag = {'ready': False}
        stop_event = threading.Event()
        connection_error_count = 0
        max_connection_errors = 5  # You can adjust this threshold as needed

        def api_check_thread(flag, stop_event):
            # logging.debug('api_check_thread started, will poll /api until ready or stop_event is set')
            while datetime.datetime.now(datetime.timezone.utc) < end and not stop_event.is_set():
                try:
                    result = self.api_root_ready()
                    # logging.debug('api_check_thread polled /api, result: %s', result)
                    if result:
                        flag['ready'] = True
                        # logging.info('api_check_thread: /api is ready, setting flag and exiting thread')
                        # time.sleep(int(10))
                        # continue
                except Exception as exc:
                    # logging.error('api_check_thread: Exception while polling /api: %s', exc)
                    pass
                time.sleep(int(10))
        api_thread = threading.Thread(target=api_check_thread, args=(api_ready_flag, stop_event))
        api_thread.daemon = True
        api_thread.start()

        tenant_state = {}
        while datetime.datetime.now(datetime.timezone.utc) < end:
            try:
                # logging.debug('Iteration started at %s', datetime.datetime.now(datetime.timezone.utc))
                if not self.tenant_exists():
                    tenant_state.update(status='Tenant Not Found')
                    # logging.debug('Tenant not found, sleeping for %s seconds', self.want.sleep)
                    time.sleep(int(self.want.sleep))
                    continue

                tenant_data = self.read_tenant_from_device()
                # logging.debug('Polled tenant data: %s', tenant_data)
                tenant_state = tenant_data.get('state', {})
                # logging.debug('Polled tenant state: %s', tenant_state)

                if self.want.state == 'configured' and self.tenant_is_configured(tenant_state):
                    # logging.info('Tenant reached configured state.')
                    break

                elif self.want.state == 'provisioned' and self.tenant_is_provisioned(tenant_state):
                    # logging.info('Tenant reached provisioned state.')
                    break

                elif self.want.state == 'deployed' and self.tenant_is_deployed(tenant_state):
                    # logging.info('Tenant reached deployed state.')
                    break

                elif self.want.state == 'ssh-ready' and self.tenant_ssh_ready(tenant_data):
                    # logging.info('Tenant SSH is ready.')
                    break

                elif self.want.state == 'api-ready' and self.tenant_api_ready(tenant_data):
                    # logging.info('Tenant API is ready.')
                    break

                # logging.debug('Desired state not reached, sleeping for %s seconds', self.want.sleep)
                time.sleep(int(self.want.sleep))

            except AnsibleConnectionError as ex:  # pragma: no cover
                connection_error_count += 1
                # logging.warning('AnsibleConnectionError occurred %d times (max %d): %s', connection_error_count, max_connection_errors, ex)
                if connection_error_count > max_connection_errors:
                    stop_event.set()
                    api_thread.join(timeout=1)
                    raise F5ModuleError(ex.args[0])
                time.sleep(int(self.want.sleep))
                continue

            except Exception as exc:  # pragma: no cover
                # logging.error('Exception in wait_for_tenant loop: %s', exc)
                time.sleep(int(self.want.sleep))
                continue
        else:
            elapsed = datetime.datetime.now(datetime.timezone.utc) - start
            stop_event.set()
            api_thread.join(timeout=1)
            self.module.fail_json(
                msg=self.want.msg or "Timeout waiting for desired tenant state", elapsed=elapsed.seconds,
                tenant_state=tenant_state
            )
        stop_event.set()
        api_thread.join(timeout=1)
        return tenant_state

    def tenant_exists(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def read_tenant_from_device(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-tenants:tenant'][0]

    def tenant_is_configured(self, tenant_state):
        # example tenant_data when tenant is configured.
        #  {
        #   "name": "defaultbip",
        #   "type": "BIG-IP",
        #   "mgmt-ip": "10.146.97.29",
        #   "prefix-length": 19,
        #   "gateway": "10.146.127.254",
        #   "mac-ndi-set": [
        #     {
        #       "ndi": "default",
        #       "mac": "00:94:a1:8e:7c:0b"
        #     }
        #   ],
        #   "vlans": [
        #     104
        #   ],
        #   "cryptos": "disabled",
        #   "vcpu-cores-per-node": "2",
        #   "memory": "8192",
        #   "running-state": "configured",
        #   "mac-data": {
        #     "mgmt-mac": "00:94:a1:8e:7c:09",
        #     "base-mac": "00:94:a1:8e:7c:0a",
        #     "mac-pool-size": 1
        #   },
        #   "appliance-mode": {
        #     "enabled": false
        #   },
        #   "status": "Configured"
        # }
        run_state = tenant_state.get('running-state', '').lower() == 'configured'
        if tenant_state.get('status') is not None:
            return all([run_state, tenant_state.get('status')])
        return run_state

    def tenant_is_provisioned(self, tenant_state):
        # example tenant_data when tenant is provisioned.
        #  {
        #   "name": "defaultbip",
        #   "type": "BIG-IP",
        #   "mgmt-ip": "10.146.97.29",
        #   "prefix-length": 19,
        #   "gateway": "10.146.127.254",
        #   "mac-ndi-set": [
        #     {
        #       "ndi": "default",
        #       "mac": "00:94:a1:8e:7c:0b"
        #     }
        #   ],
        #   "vlans": [
        #     104
        #   ],
        #   "cryptos": "disabled",
        #   "vcpu-cores-per-node": "2",
        #   "memory": "8192",
        #   "running-state": "provisioned",
        #   "mac-data": {
        #     "mgmt-mac": "00:94:a1:8e:7c:09",
        #     "base-mac": "00:94:a1:8e:7c:0a",
        #     "mac-pool-size": 1
        #   },
        #   "appliance-mode": {
        #     "enabled": false
        #   },
        #   "status": "Provisioned",
        #   "primary-slot": 1,
        #   "image-version": "BIG-IP 14.1.2.8 0.0.477",
        #   "instances": {
        #     "instance": [
        #       {
        #         "node": 1,
        #         "instance-id": 1,
        #         "phase": "Ready to deploy",
        #         "image-name": "BIGIP-bigip14.1.x-miro-14.1.2.8-0.0.477.ALL-VELOS.qcow2.zip.bundle",
        #         "creation-time": "",
        #         "ready-time": "",
        #         "status": " "
        #       }
        #     ]
        #   }
        # }
        run_state = tenant_state.get('running-state', '').lower() == 'provisioned'
        run_status = tenant_state.get('status', '').lower() == 'provisioned'
        is_provisioned = all([run_state, run_status])
        return is_provisioned

    def tenant_is_deployed(self, tenant_state):
        # example tenant_data when tenant is deployed.
        # {
        #   "name": "defaultbip",
        #   "type": "BIG-IP",
        #   "mgmt-ip": "10.146.97.29",
        #   "prefix-length": 19,
        #   "gateway": "10.146.127.254",
        #   "mac-ndi-set": [
        #     {
        #       "ndi": "default",
        #       "mac": "00:94:a1:8e:7c:0b"
        #     }
        #   ],
        #   "vlans": [
        #     104
        #   ],
        #   "cryptos": "disabled",
        #   "vcpu-cores-per-node": "2",
        #   "memory": "8192",
        #   "running-state": "deployed",
        #   "mac-data": {
        #     "mgmt-mac": "00:94:a1:8e:7c:09",
        #     "base-mac": "00:94:a1:8e:7c:0a",
        #     "mac-pool-size": 1
        #   },
        #   "appliance-mode": {
        #     "enabled": false
        #   },
        #   "status": "Running",
        #   "primary-slot": 1,
        #   "image-version": "BIG-IP 14.1.2.8 0.0.477",
        #   "instances": {
        #     "instance": [
        #       {
        #         "node": 1,
        #         "instance-id": 1,
        #         "phase": "Running",
        #         "image-name": "BIGIP-bigip14.1.x-miro-14.1.2.8-0.0.477.ALL-VELOS.qcow2.zip.bundle",
        #         "creation-time": "2020-10-13T18:56:40Z",
        #         "ready-time": "2020-10-13T18:56:38Z",
        #         "status": "Started tenant instance"
        #       }
        #     ]
        #   }
        # }
        run_phase = []
        for instance in tenant_state.get('instances', {}).get('instance', []):
            run_phase.append(instance.get('phase', '').lower() == 'running')

        running = all(run_phase)
        run_state = tenant_state.get('running-state', '').lower() == 'deployed'
        run_status = tenant_state.get('status', '').lower() == 'running'
        is_deployed = all([run_state, run_status, running])
        return is_deployed

    def tenant_ssh_ready(self, tenant_data):
        """ Return True if the tenant is ready to accept ssh connections.
        """
        ssh_ready = False
        host = tenant_data['config']['mgmt-ip']
        port = tenant_data['config'].get('port', 22)

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.load_system_host_keys()
            ssh_client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            # We don't expect or need these credentials to work. Just want to wait
            # for the ssh server to accept connections.
            ssh_client.connect(host, port, 'root', 'foo')
            # Successful connection?
            ssh_ready = True

        except paramiko.ssh_exception.AuthenticationException:
            # SSH Server is up.
            ssh_ready = True

        except Exception:
            # ssh server must not be ready.
            pass

        finally:
            try:
                ssh_client.close()
            except Exception:  # pragma: no cover
                pass

        return ssh_ready

    def tenant_api_ready(self, tenant_data):
        host = tenant_data['config']['mgmt-ip']
        port = tenant_data['config'].get('port', 443)

        uri = f"https://{host}:{port}/mgmt/tm/sys/available"
        try:
            open_url(uri, method='GET', timeout=10, validate_certs=False)
        except HTTPError as err:
            if err.code == 401:
                return True
            return False
        except URLError as urlerr:
            conn_refused = 'Connection refused'
            if conn_refused in urlerr.reason:
                return False
            raise

    def api_root_ready(self):
        # uri = ""
        response = self.client.get("", scope='/api')
        # raise F5ModuleError(f'response :{response}')
        # Consider API ready if we get a 200 or 401 response
        if response['code'] in [200, 401]:
            return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            state=dict(
                choices=[
                    'configured',
                    'provisioned',
                    'deployed',
                    'ssh-ready',
                    'api-ready',
                ],
                default='configured'
            ),
            timeout=dict(default=600, type='int'),
            delay=dict(default=0, type='int'),
            sleep=dict(default=1, type='int'),
            msg=dict()
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    if not HAS_PARAMIKO:
        module.fail_json(
            msg=missing_required_lib('paramiko'), exception=PARAMIKO_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
