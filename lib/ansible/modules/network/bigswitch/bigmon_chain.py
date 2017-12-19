#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to manage Big Monitoring Fabric service chains
# (c) 2016, Ted Elhourani <ted@bigswitch.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: bigmon_chain
author: "Ted (@tedelhourani)"
short_description: Create and remove a bigmon inline service chain.
description:
    - Create and remove a bigmon inline service chain.
version_added: "2.3"
options:
  name:
    description:
     - The name of the chain.
    required: true
  switch:
    description:
     - The mac address of the switch
  endpoint1:
    description:
     - The first endpoint of the chain
  endpoint2:
    description:
     - The second endpoint of the chain
  state:
    description:
     - Whether the service chain should be present or absent.
    default: present
    choices: ['present', 'absent']
  controller:
    description:
     - The controller IP address.
    required: true
  validate_certs:
    description:
      - If C(false), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: true
    choices: [true, false]
  access_token:
    description:
     - Bigmon access token. If this isn't set, the environment variable C(BIGSWITCH_ACCESS_TOKEN) is used.
'''


EXAMPLES = '''
- name: bigmon inline service chain
  bigmon_chain:
    name: MyChain
    endpoint1: ethernet1
    endpoint2: ethernet2
    controller: '{{ inventory_hostname }}'
    state: present
    validate_certs: false
'''


RETURN = ''' # '''

import os
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.bigswitch_utils import Rest
from ansible.module_utils._text import to_native


def chain(module):
    try:
        access_token = module.params['access_token'] or os.environ['BIGSWITCH_ACCESS_TOKEN']
    except KeyError as e:
        module.fail_json(msg='Unable to load %s' % e.message, exception=traceback.format_exc())

    name = module.params['name']
    state = module.params['state']
    switch = module.params['switch']
    endpoint1 = module.params['endpoint1']
    endpoint2 = module.params['endpoint2']
    controller = module.params['controller']

    rest = Rest(module,
                {'content-type': 'application/json', 'Cookie': 'session_cookie='+access_token},
                'https://'+controller+':8443/api/v1/data/controller/applications/bigchain')

    if None in (name, state, controller):
        module.fail_json(msg='parameter `name` is missing')

    response = rest.get('chain?config=true', data={})
    if response.status_code != 200:
        module.fail_json(msg="failed to obtain existing chain config: {}".format(response.json['description']))

    config_present = False
    matching = [chain for chain in response.json if chain['name'] == name]
    target_chain = {'endpoint1': endpoint1,
                    'endpoint2': endpoint2,
                    'switch': '00:00:'+switch}
    if matching:
        matching_chain = matching[0]
        if not cmp(target_chain,
                   matching_chain['endpoint-pair']):
            config_present = True

    if state in ('present') and config_present:
        module.exit_json(changed=False)

    if state in ('absent') and not config_present:
        module.exit_json(changed=False)

    if state in ('present'):
        response = rest.put('chain[name="%s"]' % name, data={'name': name})
        if response.status_code != 204:
            module.fail_json(msg="error creating chain '{}': {}".format(name, response.json['description']))

        #PATCH http://127.0.0.1:8082/api/v1/data/controller/applications/bigchain/chain[name="customer1"]/endpoint-pair {"endpoint1": "ethernet1", "switch": "00:00:00:00:00:00:00:0a", "endpoint2": "ethernet2"}
        data = target_chain
        path = 'chain[name="%s"]/endpoint-pair' % name
        response = rest.patch(path, data=data)

        if response.status_code == 204:
            module.exit_json(changed=True)
        else:
            module.fail_json(msg="error creating chain '{}': {}".format(name, response.json['description']))

    if state in ('absent'):
        response = rest.delete('chain[name="%s"]' % name, data={})
        if response.status_code == 204:
            module.exit_json(changed=True)
        else:
            module.fail_json(msg="error deleting chain '{}': {}".format(name, response.json['description']))

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            switch=dict(type='str', required=True),
            endpoint1=dict(type='str', required=True),
            endpoint2=dict(type='str', required=True),
            controller=dict(type='str', required=True),
            state=dict(choices=['present', 'absent'], default='present'),
            validate_certs=dict(type='bool', default='True'),
            access_token=dict(type='str', no_log=True)
        )
    )

    try:
        chain(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
