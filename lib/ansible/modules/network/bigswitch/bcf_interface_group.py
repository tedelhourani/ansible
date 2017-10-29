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
module: bcf_interface_group
short_description: Create and remove a bcf interface group.
description:
    - Create and remove a bcf interface group.
version_added: "2.3"
options:
  name:
    description:
     - The name of the interface group.
    required: true
  mode:
    description:
     - The name of the tenant to which this segment belongs.
     default: static
     choices: ['cdp', 'inter-pod', 'lacp', 'lldp', 'span-fabric', 'static']
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
- name: bcf interface group
      bcf_interface_group:
        name: R1H1
        members:
        controller: '{{ inventory_hostname }}'
        state: present
'''


RETURN = '''
'''

import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.bigswitch_utils import Rest, Response
from ansible.module_utils.pycompat24 import get_exception

def interface_group(module):
    try:
        access_token = module.params['access_token'] or os.environ['BIGSWITCH_ACCESS_TOKEN']
    except KeyError:
        e = get_exception()
        module.fail_json(msg='Unable to load %s' % e.message )

    name = module.params['name']
    mode = module.params['mode']
    members = module.params['members']
    state = module.params['state']
    controller = module.params['controller']


    rest = Rest(module,
                {'Content-type': 'application/json',
                 'Cookie': 'session_cookie='+access_token},
                'https://'+controller+':8443/api/v1/data/controller/applications/bcf')

    if None in (name, state, controller):
        module.fail_json(msg='parameter `name` is missing')

    response = rest.get('interface-group[name="%s"]?select=name&single=true' % name, data={})
    if not response.status_code in [200, 404]:
        module.fail_json(msg="failed to lookup interface group in existing config {}: {}".format(response.json))

    config_present = False
    if response.status_code == 200:
        config_present = True

    if state in ('absent') and not config_present:
        module.exit_json(changed=False)

    if state in ('present'):
        response = rest.get('interface-group[name="%s"]' % name, data={})
        if not response.status_code != 204:
            module.fail_json(msg="failed to lookup interface group in existing config {}: {}".format(response.json))

        changed = False
        current_members = []
        current_mode = None
        if not config_present:
            response = rest.put('interface-group[name="%s"]' % name, data={'name': name})
            changed = True
            if response.status_code != 204:
                module.fail_json(msg="error creating interface group '{}': {}".format(name, response.info))
        else:
            if 'member-interface' in response.json[0]:
                current_members = [{member['switch-name']:member['interface-name']}
                                   for member in response.json[0]['member-interface']]
            current_mode = response.json[0]['mode']


        # update members
        for member in current_members:
            if not member in members:
                changed = True
                (switch, interface) = member.items()[0]
                response = rest.delete('interface-group[name="%s"]/member-interface[switch-name="%s"][interface-name="%s"]' % (name, switch, interface), data={})
                if response.status_code != 204:
                    module.fail_json(msg="error deleting interface group member '{}': {}".format(name, response.info))
            else:
                members.remove(member)

        for member in members:
            changed = True
            (switch, interface), = member.items()
            data = {'switch-name': switch, "interface-name": interface}
            response = rest.put('interface-group[name="%s"]/member-interface[switch-name="%s"][interface-name="%s"]' % (name, switch, interface), data=data)
            if response.status_code != 204:
                module.fail_json(msg="error adding interface group member '{}': {}".format(name, response.info))

        # update mode
        if not current_mode == mode:
            changed = True
            response = rest.patch('interface-group[name="%s"]' % name, data={'mode': mode})
            if response.status_code != 204:
                module.fail_json(msg="error creating segment '{}': {}".format(name, response.info))

        module.exit_json(changed=changed)

    if state in ('absent'):
        response = rest.delete('interface-group[name="%s"]' % name, data={})
        if response.status_code == 204:
            module.exit_json(changed=True)
        else:
            module.fail_json(msg="error deleting segment '{}': {}".format(name, response.info['msg']))

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            mode=dict(choices=['cdp', 'inter-pod', 'lacp', 'lldp', 'span-fabric', 'static'], default='static'),
            members=dict(type='list', default=[]),
            controller=dict(type='str', required=True),
            state=dict(choices=['present', 'absent'], default='present'),
            validate_certs=dict(type='bool', default='False'),  # TO DO: change this to default='True'
            access_token=dict(type='str', no_log=True)
        )
    )

    try:
        interface_group(module)
    except Exception:
        e = get_exception()
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
