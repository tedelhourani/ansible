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
     - The mode of the interface group, e.g. lacp.
     default: static
     choices: ['cdp', 'inter-pod', 'lacp', 'lldp', 'span-fabric', 'static']
  members:
    description:
    - The leaf switch, host-based, or chassis-mac members of this interface group.
  state:
    description:
     - Whether the interface group should be present or absent.
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
- name: interface group
      bcf_interface_group:
        name: R1H2
        members: {'switch': {'Rack1Leaf1': ['ethernet5', 'ethernet6'],
                             'Rack1Leaf2': ['ethernet5', 'ethernet6']}}
        controller: '{{ inventory_hostname }}'
        state: present

- name: chassis interface group
      bcf_interface_group:
        name: chassis
        mode: lldp
        members: {'chassis-mac': ['13:13:08:6C:21:F4']}
        controller: '{{ inventory_hostname }}'
        state: present

- name: host interface group
      bcf_interface_group:
        name: esx-server2
        mode: lldp
        members: {'host': {'esx-server2.prod.corporate.com': ['vmnic2', 'vmnic3']}}
        controller: '{{ inventory_hostname }}'
        state: present
'''


RETURN = ''' # '''

import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.bigswitch_utils import Rest, Response
from ansible.module_utils.pycompat24 import get_exception

def path(name, member_type, member):
    if member_type == 'member-interface':
        return 'interface-group[name="%s"]/member-interface[switch-name="%s"][interface-name="%s"]' \
            % (name, member['switch-name'], member['interface-name'])
    if member_type == 'host-interface':
        return 'interface-group[name="%s"]/host-interface[host-name="%s"][interface-name="%s"]' \
            % (name, member['host-name'], member['interface-name'])
    if member_type == 'chassis-mac':
        return 'interface-group[name="%s"]/chassis-mac[mac-address="%s"]' \
            % (name, member['mac-address'])

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

    #module.exit_json(msg=members, changed=False)

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
        changed = False
        current_members = {}
        current_mode = None

        if not config_present:
            current_members['member-interface'] = []
            current_members['host-interface'] = []
            current_members['chassis-mac'] = []
            response = rest.put('interface-group[name="%s"]' % name, data={'name': name})
            changed = True
            if response.status_code != 204:
                module.fail_json(msg="error creating interface group '{}': {}".format(name, response.info))
        else:
            response = rest.get('interface-group[name="%s"]' % name, data={})
            if not response.status_code != 204:
                module.fail_json(msg="failed to lookup interface group in existing config {}: {}".format(response.json))
            #module.exit_json(msg=response.json[0], changed=False)
            if 'member-interface' in response.json[0]:
                current_members['member-interface'] =  response.json[0]['member-interface']
            if 'host-interface' in response.json[0]:
                current_members['host-interface'] = response.json[0]['host-interface']
            if 'chassis-mac' in response.json[0]:
                current_members['chassis-mac'] = response.json[0]['chassis-mac']
            current_mode = response.json[0]['mode']

        #module.exit_json(msg=current_members, changed=False)

        # update mode
        if not current_mode == mode:
            changed = True
            response = rest.patch('interface-group[name="%s"]' % name, data={'mode': mode})
            if response.status_code != 204:
                module.fail_json(msg="error creating segment '{}': {}".format(name, response.info))

        target_members = {}
        for member_type in members:
            if member_type == 'switch':
                switch_members = members['switch']
                target_members['member-interface'] = []
                for switch in switch_members:
                    target_members['member-interface'].extend([{'switch-name':switch, 'interface-name':interface}
                                                               for interface in switch_members[switch] ])
            if member_type == 'host':
                host_members = members['host']
                target_members['host-interface'] = []
                for host in host_members:
                    target_members['host-interface'] = [ {'host-name':host, 'interface-name':interface}
                                                         for interface in host_members[host] ]
            if member_type == 'chassis-mac':
                target_members['chassis-mac'] = []
                target_members['chassis-mac'] = [ {'mac-address':mac} for mac in members['chassis-mac']]

        obsolete_members = {}
        new_members = {}
        for member_type in target_members:
            obsolete_members[member_type] = [member for member in current_members.get(member_type, [])
                                             if not member in target_members.get(member_type,[])]
            new_members[member_type] = [member for member in target_members.get(member_type, [])
                                        if not member in current_members.get(member_type, [])]

        #module.exit_json(msg={'current':current_members,'target':target_members}, changed=False)
        #module.exit_json(msg={'obsolete':obsolete_members,'new':new_members}, changed=False)

        # update members
        for member_type in obsolete_members:
            for member in obsolete_members[member_type]:
                #path(name, member_type, member)
                response = rest.delete(path(name, member_type, member), data={})
                if response.status_code != 204:
                    module.fail_json(msg="error deleting interface group member '{}': {}".format(name, response.info))

        for member_type in new_members:
            for member in new_members[member_type]:
                response = rest.put(path(name, member_type, member), data=member)
                if response.status_code != 204:
                    module.fail_json(msg="error adding interface group member '{}': {}".format(name, response.info))

        if [member_type for member_type in target_members if obsolete_members[member_type] or new_members[member_type]]:
            changed = True

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
            members=dict(type='dict', default={}),
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
