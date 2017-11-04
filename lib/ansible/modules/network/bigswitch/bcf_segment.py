#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Ted Elhourani <ted@bigswitch.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: bcf_segment
short_description: Create and remove a bcf segment.
description:
    - Create and remove a bcf segment.
version_added: "2.3"
options:
  name:
    description:
     - The name of the segment.
    required: true
  tenant:
    description:
     - The name of the tenant to which this segment belongs.
  state:
    description:
     - Whether the segment should be present or absent.
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
     - Big Cloud Fabric access token. If this isn't set then the environment variable C(BIGSWITCH_ACCESS_TOKEN) is used.
'''


EXAMPLES = '''
- name: bcf segment
      bcf_segment:
        name: web
        interface_groups: ['R1H1:untagged','R1H2:untagged']
        tenant: 3-tier-app
        controller: '{{ inventory_hostname }}'
        state: present
'''


RETURN = '''
'''

import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.bigswitch_utils import Rest, Response
from ansible.module_utils.pycompat24 import get_exception

def segment(module):
    try:
        access_token = module.params['access_token'] or os.environ['BIGSWITCH_ACCESS_TOKEN']
    except KeyError:
        e = get_exception()
        module.fail_json(msg='Unable to load %s' % e.message )

    name = module.params['name']
    segment_id = module.params['segment_id']
    interface_groups = module.params['interface_groups']
    tenant = module.params['tenant']
    state = module.params['state']
    controller = module.params['controller']

    rest = Rest(module,
                {'Content-type': 'application/json',
                 'Cookie': 'session_cookie='+access_token},
                'https://'+controller+':8443/api/v1/data/controller/applications/bcf')

    if None in (name, state, controller):
        module.fail_json(msg='parameter `name` is missing')

    response = rest.get('tenant[name="%s"]/segment[name="%s"]?select=name&single=true' % (tenant, name), data={})
    if not response.status_code in [200, 404]:
        module.fail_json(msg="failed to lookup segment in existing config {}: {}".format(response.json))

    config_present = False
    if response.status_code == 200:
        config_present = True

    if state in ('present') and config_present:
        module.exit_json(changed=False)

    if state in ('absent') and not config_present:
        module.exit_json(changed=False)

    if state in ('present'):
        response = rest.put('tenant[name="%s"]/segment[name="%s"]' % (tenant, name), data={'name': name})
        if response.status_code != 204:
            module.fail_json(msg="error creating segment '{}': {}".format(name, response.info))

        for interface_group_vlan in interface_groups:
            interface_group, vlan = interface_group_vlan.split(':')
            vlan = -1 if vlan == 'untagged' else vlan
            data= {'interface-group': interface_group, 'vlan': vlan}
            response = rest.put('tenant[name="%s"]/segment[name="%s"]/interface-group-membership-rule[interface-group="%s"][vlan=%s]' % (tenant, name, interface_group, vlan), data=data)
            if response.status_code != 204:
                module.fail_json(msg="error creating segment membership '{}': {}".format(interface_group_vlan[0], response.info))
        module.exit_json(changed=True)

    if state in ('absent'):
        response = rest.delete('tenant[name="%s"]/segment[name="%s"]' % (tenant, name), data={})
        if response.status_code == 204:
            module.exit_json(changed=True)
        else:
            module.fail_json(msg="error deleting segment '{}': {}".format(name, response.info['msg']))

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            segment_id=dict(type='str', required=False),
            interface_groups=dict(type='list', default=[]),
            tenant=dict(type='str', required=True),
            controller=dict(type='str', required=True),
            state=dict(choices=['present', 'absent'], default='present'),
            validate_certs=dict(type='bool', default='False'),  # TO DO: change this to default='True'
            access_token=dict(type='str', no_log=True)
        )
    )

    try:
        segment(module)
    except Exception:
        e = get_exception()
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
