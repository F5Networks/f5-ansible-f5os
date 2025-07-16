# F5OS Collection for Ansible

## Description

The F5OS Ansible Collection enables automation and lifecycle management of F5OS devices, including Velos chassis and rSeries platforms. It provides resources for managing tenants, partitions, users, and device configurations via the F5OS OpenAPI. This collection is ideal for network engineers, DevOps teams, and IT administrators seeking to automate F5OS device operations, streamline deployments, and ensure consistent configuration management.

**Key Benefits:**
- Automate F5OS device onboarding, configuration, and lifecycle tasks
- Integrate with Ansible Automation Platform and Execution Environments
- Support for Velos and rSeries platforms with F5OS API access

## Requirements

- **Ansible:** >= 2.16
- **Python:** >= 3.9
- **Dependencies:**
  - [ansible.netcommon](https://galaxy.ansible.com/ansible/netcommon)
  - F5OS device with API access
- Additional prerequisites may include network connectivity and authentication credentials for F5OS devices.

## Installation

Install the collection from Ansible Galaxy:

```
ansible-galaxy collection install f5networks.f5os
```

To install the collection in a custom path (e.g., `./collections`), use the `-p` option:

```
ansible-galaxy collection install f5networks.f5os -p ./collections
```

Or via a `requirements.yml` file:

```yaml
collections:
  - name: f5networks.f5os
```

To upgrade to the latest version:

```
ansible-galaxy collection install f5networks.f5os --upgrade
```

To install a specific version (e.g., 1.0.0):

```
ansible-galaxy collection install f5networks.f5os:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

**Authentication:**
- Ensure you have valid credentials and API access to your F5OS device.
- See [f5execenv](https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/exec-env.html) for Execution Environment setup.

## Example Usage

To use a module from this collection, please refer [f5os-guide](https://clouddocs.f5.com/products/orchestration/ansible/devel/f5os/f5os.html#using-the-f5os-collection)


## Running the Collection in an Execution Environment (EE)

You can run this collection inside an Ansible Execution Environment (EE) container. This approach ensures all required package dependencies and minimum supported Python versions are installed in an isolated container, minimizing environment-related issues during runtime.

To use the collection in an EE, add it to your `requirements.yml` file. For example:

```yaml
---
collections:
  - name: ansible.netcommon
    version: ">=2.0.0"
  - name: f5networks.f5os
```

When building your EE container, include this requirements file. For more information on building and using EEs, see the [execenv]

## Use Cases

1. **User and Role Management:** Automate creation, update, and deletion of users and roles on F5OS devices.
2. **Device Onboarding:** Provision new Velos or rSeries devices with initial configuration and tenant setup.
3. **Partition and Tenant Operations:** Create, update, and remove partitions and tenants declaratively.

## Testing

- The collection is tested on Python 3.9+ and Ansible 2.16+.
- Functional and unit tests are run against Velos and rSeries platforms.

## Contributing

Contributions are welcome! Please review the [F5 Contributor License Agreement](https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/contributor.html) and submit it to Ansible_CLA@f5.com before submitting code. For guidelines, see [repoinstall](https://docs.ansible.com/ansible/latest/collections_guide/collections_installing.html#installing-a-collection-from-a-git-repository).


## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner.
If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, you can also file issues on [ansible_issues](https://github.com/F5Networks/f5-ansible-f5os/issues).

## Release Notes and Roadmap

- [Changelog](https://github.com/F5Networks/f5-ansible-f5os/releases)


## Related Information

- [F5OS Ansible Documentation](https://clouddocs.f5.com/products/orchestration/ansible/devel/f5os/F5OS-index.html)
- [Execution Environments](https://docs.ansible.com/automation-controller/latest/html/userguide/execution_environments.html)

## License Information

Published under [GPL V3](https://www.gnu.org/licenses/gpl-3.0.txt). See the LICENSE file included in the collection for details.

Copyright 2025 F5 Networks Inc.

[execenv]: https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.5/html/creating_and_using_execution_environments/index