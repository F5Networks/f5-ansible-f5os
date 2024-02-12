=============================
F5Networks.F5OS Release Notes
=============================

.. contents:: Topics

v1.6.0
======

Bugfixes
--------

- f5os_lag.py - fixed a bug related to creating lacp lag interface and added two new parameters, mode and interval

v1.5.0
======

Minor Changes
-------------

- client.py - added client property to return software version of the F5OS platform
- f5os.py - added code to fetch the software version of the F5OS platform
- teem.py - added a new field, f5SoftwareVersion to the teem data, and changed the field, F5OSPlatform to f5Platform

v1.4.0
======

Minor Changes
-------------

- f5os_device_info - add Link Aggregate Group information

Bugfixes
--------

- f5os_device_info - fixed issue with license information on F5OS 1.5.0 and above

v1.3.0
======

Minor Changes
-------------

- f5os.py - set the ROOT of url to /api/data if the port is 443
- f5os_config_backup.py - removed scp and sftp choices for protocol parameter until they are fully supported

v1.2.0
======

New Modules
-----------

- f5networks.f5os.f5os_config_backup - Manage F5OS config backups.

v1.1.1
======

Bugfixes
--------

- f5os.py - disabled checking for platform type when using the default credentials

v1.1.0
======

Minor Changes
-------------

- velos_partition_image - fixed invalid internal destination folder, changed progress check functions, added remote_host and remote_path as mandatory parameters for checking import status

v1.0.2
======

Bugfixes
--------

- f5os.py - fixed error parsing method to act on JSONDecoder errors
- f5os_device_info.py - fixed client instantiation in the module so send_teem calls are successful

v1.0.1
======

Minor Changes
-------------

- velos_partition - refactored ipv4_mgmt_address, ipv4_mgmt_gateway, ipv6_mgmt_address and ipv6_mgmt_gateway properties
- velos_partition - refactored mgmt-ip parameter parsing in update_on_device method

Bugfixes
--------

- f5os_device_info - removed legacy functions and corrected TEEM call placement
- f5os_interface - fixed invalid if statement in validate_vlan_ids function
- f5os_lag - fixed invalid if statement in validate_vlan_ids function
- velos_partition - fixed remove_slot_from_partition method throwing exception when slots parameter was none

v1.0.0
======

New Plugins
-----------

Httpapi
~~~~~~~

- f5networks.f5os.f5os - HttpApi Plugin for F5OS devices

New Modules
-----------

- f5networks.f5os.f5os_device_info - Collect information from F5OS devices
- f5networks.f5os.f5os_interface - Manage network interfaces on F5OS based systems
- f5networks.f5os.f5os_lag - Manage LAG interfaces on F5OS based systems
- f5networks.f5os.f5os_tenant - Manage F5OS tenants
- f5networks.f5os.f5os_tenant_image - Manage F5OS tenant images
- f5networks.f5os.f5os_tenant_wait - Wait for a F5OS tenant condition before continuing
- f5networks.f5os.f5os_vlan - Manage VLANs on F5OS based systems
- f5networks.f5os.velos_partition - Manage VELOS chassis partitions
- f5networks.f5os.velos_partition_change_password - Provides access to VELOS chassis partition user authentication methods
- f5networks.f5os.velos_partition_image - Manage VELOS chassis partition images
- f5networks.f5os.velos_partition_wait - Wait for a VELOS chassis partition to match a condition before continuing
