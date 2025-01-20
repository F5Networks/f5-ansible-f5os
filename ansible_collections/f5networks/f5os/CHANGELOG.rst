=============================
F5Networks.F5OS Release Notes
=============================

.. contents:: Topics

v1.14.1
=======

v1.14.0
=======

Major Changes
-------------

- f5os_snmp - allowed module to work for VELOS system controllers, added IPv6 support, fixed issues for multiple SNMP targets, community and users.

Minor Changes
-------------

- f5os_ntp_server - added support to enable/disable NTP service and NTP Authentication
- f5os_stp_config - added support for mstp
- f5os_stp_config - added support for rstp

v1.13.0
=======

Minor Changes
-------------

- f5os_ntp_server - added a new parameter, prefer, iburst

Bugfixes
--------

- f5os_system_image_import - bug fixed for importing system image in versions less than 1.7

v1.12.0
=======

Minor Changes
-------------

- f5os_tenant - added a new parameter, virtual_disk_size, to set the virtual disk size of the tenant

Bugfixes
--------

- f5os_lag - fixed a bug that used to occur while adding trunk or native vlans

v1.11.0
=======

New Modules
-----------

- f5networks.f5os.f5os_primarykey - Manage F5OS Devices Primary-key Setting.
- f5networks.f5os.f5os_system_image_import - Manage F5OS System image import.
- f5networks.f5os.f5os_system_image_install - Manage F5OS system software installation.
- f5networks.f5os.f5os_tls_cert_key - Manage TLS certificate and key on F5OS devices.

v1.10.1
=======

v1.10.0
=======

Minor Changes
-------------

- f5os_lldp_config - doc changes and fixed issue - update/add interfaces

Bugfixes
--------

- f5os_ntp_server - Fixed a bug that was causing an idempotency issue.

New Modules
-----------

- f5networks.f5os.f5os_license - Manage F5OS license activation and deactivation.
- f5networks.f5os.f5os_system - Manage generic system settings

v1.9.0
======

Major Changes
-------------

- f5os_lldp_config - Added module to Enable/Disable LLDP config.
- f5os_stp_config - Added module to Enable/Disable STP config.

Minor Changes
-------------

- f5os_device_info - Added some validations in Parameters.

New Modules
-----------

- f5networks.f5os.f5os_snmp - Manage SNMP Communities, Users, and Targets using openAPI on F5OS based systems
- f5networks.f5os.f5os_user - Manage Users and roles on F5OS based systems

v1.8.0
======

Major Changes
-------------

- f5os_qkview.py - Added module to Generate QKview file.

New Modules
-----------

- f5networks.f5os.f5os_dns - Manage DNS on F5OS Devices
- f5networks.f5os.f5os_ntp_server - Manage NTP servers on F5OS based systems

v1.7.0
======

Minor Changes
-------------

- f5os_tenant_wait.py - added code to verify whether the tenant is reachable via the API

Bugfixes
--------

- f5os_tenant_wait - fixed a bug that resulted in the module going in infinite loop whenever the delay was more than 30 seconds

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
