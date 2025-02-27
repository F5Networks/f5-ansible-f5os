# F5OS Collection for Ansible

A collection focusing on managing F5 OS devices through an API. The collection includes key imperative modules for 
managing Velos chassis and rSeries platform lifecycles as well as F5OS tenant and partition management.

## Requirements

 - ansible >= 2.16

## Python Version
This collection is supported on Python 3.9 and above.

## Collections Daily Build

We offer a daily build of our most recent collection [dailybuild]. Use this Collection to test the most
recent Ansible module updates between releases. 
You can also install the development build directly from GitHub into your environment, see [repoinstall].

### Install from GitHub
```bash

ansible-galaxy collection install git+https://github.com/F5Networks/f5-ansible-f5os#ansible_collections/f5networks/f5os
```

### Install from the daily build file
```bash

    ansible-galaxy collection install <collection name> -p ./collections
    e.g.
    ansible-galaxy collection install f5networks-f5os-devel.tar.gz -p ./collections
```

> **_NOTE:_**  `-p` is the location in which the collection will be installed. This location should be defined in the path for
    Ansible to search for collections. An example of this would be adding ``collections_paths = ./collections``
    to your **ansible.cfg**

### Running latest devel in EE
We also offer a new method of running the collection inside Ansible's Execution Environment container. 
The advantage of such approach is that any required package dependencies and minimum supported Python versions are 
installed in an isolated container which minimizes any environment related issues during runtime. More information on EE
can be found here [execenv]. Use the below requirements.yml file when building EE container:

```yaml
---
collections:
  - name: ansible.netcommon
    version: ">=2.0.0"
  - name: f5networks.f5os
    source: https://github.com/F5Networks/f5-ansible-f5os#ansible_collections/f5networks/f5os
    type: git
    version: devel
```

Please see [f5execenv] documentation for further instructions how to use and build EE container with our devel branch.

## Tips

* You can leverage both this declarative collection and the previous imperative collection at the same time.
* If you are migrating from the imperative collection, you can leave the provider variables and reference them from 
  the new httpapi connection variables:

```yaml
   ansible_host: "{{ provider.server }}"
   ansible_user: "{{ provider.user }}"
   ansible_httpapi_password: "{{ provider.password }}"
   ansible_httpapi_port: "{{ provider.server_port }}"
   ansible_network_os: f5networks.f5os.f5os
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: "{{ provider.validate_certs }}"
```

## Bugs, Issues
   
Please file any bugs, questions, or enhancement requests by using [ansible_issues]. For details, see [ansiblehelp].

## Your ideas

What types of modules do you want created? If you have a use case and can sufficiently describe the behavior 
you want to see, open an issue and we will hammer out the details.

If you've got the time, consider sending an email that introduces yourself and what you do. 
We love hearing about how you're using the F5OS collection for Ansible.

**_NOTE:_** **This repository is a mirror, only issues submissions are accepted.**

- F5 Ansible Module Development Team

## Copyright

Copyright 2025 F5 Networks Inc.


## License

### GPL V3

This License does not grant permission to use the trade names, trademarks, service marks, or product names of the 
Licensor, except as required for reasonable and customary use in describing the origin of the Work.

See [License].

### Contributor License Agreement
Individuals or business entities who contribute to this project must complete and submit the 
[F5 Contributor License Agreement] to ***Ansible_CLA@f5.com*** prior to their code submission 
being included in this project.


[repoinstall]: https://docs.ansible.com/ansible/latest/collections_guide/collections_installing.html#installing-a-collection-from-a-git-repository
[dailybuild]: https://f5-ansible.s3.amazonaws.com/collections/f5networks-f5os-devel.tar.gz
[ansible_issues]: https://github.com/F5Networks/f5-ansible-f5os/issues
[License]: https://www.gnu.org/licenses/gpl-3.0.txt
[ansiblehelp]: https://clouddocs.f5.com/products/orchestration/ansible/devel/
[execenv]: https://docs.ansible.com/automation-controller/latest/html/userguide/execution_environments.html
[f5execenv]: https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/exec-env.html
[F5 Contributor License Agreement]: https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/contributor.html