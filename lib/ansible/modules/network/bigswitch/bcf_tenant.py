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
module: bcf_tenant
short_description: Create and remove a bcf tenant.
description:
    - Create and remove a bcf tenant.
version_added: "2.3"
options:
  name:
    description:
     - The name of the tenant.
    required: true
  state:
    description:
     - Whether the tenant should be present or absent.
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
vars:
    inter_segment_fw_rule:  {"seq": 10, "action": "next-hop", "segment-interface": "web", "dst": {"segment": "app", "tenant": "3-tier-app"}, "next-hop": {"next-hop-group": "ServiceNode"}}
    permit_any_to_any_rule: {"seq": 20, "action": "permit"}

- name: bcf tenant
      bcf_tenant:
        name: 3-tier-app
        logical_router_interfaces: {'web':'10.0.0.1/24', 'app':'10.0.1.1/24', 'fw-01':'10.0.5.1/24', 'system':''}
        routes: {'0.0.0.0/0':'tenant:system'}
        next_hop_groups: {'ServiceNode':'10.0.5.2'}
        policy_lists: {'Firewall': ['{{ inter_segment_fw_rule }}', '{{ permit_any_to_any_rule }}']}
        inbound_policy: Firewall
        controller: '{{ inventory_hostname }}'
        state: present
'''


RETURN = '''
'''

import json
import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.bigswitch_utils import Rest, Response
from ansible.module_utils.pycompat24 import get_exception

def diff(existing_tenants, module):
    """
    1. fill canonical tenant logical router structure with module input
    2. compare input structure with matching structure, keeping differing fields
    3. return the diff and let tenant apply only the diff
    """
    matching = [tenant for tenant in existing_tenants if tenant['name'] == module.params['name']]
    if matching:

        return True
    return {}

def tenant(module):
    try:
        access_token = module.params['access_token'] or os.environ['BIGSWITCH_ACCESS_TOKEN']
    except KeyError:
        e = get_exception()
        module.fail_json(msg='Unable to load %s' % e.message )

    name = module.params['name']
    logical_router_interfaces = module.params['logical_router_interfaces']
    logical_router_system_tenant_interface = module.params['logical_router_system_tenant_interface']
    routes = module.params['routes']
    next_hop_groups = module.params['next_hop_groups']
    policy_lists = module.params['policy_lists']
    inbound_policy = module.params['inbound_policy']
    tenant_id = module.params['tenant_id']
    state = module.params['state']
    controller = module.params['controller']

    rest = Rest(module,
                {'Content-type': 'application/json',
                 'Cookie': 'session_cookie='+access_token},
                'https://'+controller+':8443/api/v1/data/controller/applications/bcf')

    if None in (name, state, controller):
        module.fail_json(msg='parameter `name` is missing')

    response = rest.get('tenant?config=true', data={})
    if response.status_code != 200:
        module.fail_json(msg="failed to obtain existing tenant config: {}".format(response.json['description']))

    response = rest.get('tenant?select=logical-router', data={})
    if response.status_code != 200:
        module.fail_json(msg="failed to obtain existing tenant {} logical router config: {}".format(name, response.json['description']))

    config_present = False
    # TODO: implement a matching procedure here to compare existing tenant with tenant state in playbook
    if diff(response.json, module):
        config_present = True

    #if state in ('present') and config_present:
    #    module.exit_json(changed=False)

    #if state in ('absent') and not config_present:
    #    module.exit_json(changed=False)

    if state in ('present'):
        # TODO: implement tenant config matching
        if not config_present:
            response = rest.put('tenant[name="%s"]' % name, data={'name': name})
            if response.status_code != 204:
                module.fail_json(msg="error creating tenant '{}': {}".format(name, response.info['msg']))

        for logical_router_interface in logical_router_interfaces:
            if logical_router_interfaces[logical_router_interface]:
                subnet = logical_router_interfaces[logical_router_interface]
            else:
                subnet = None

            data = {"segment": logical_router_interface}
            path = 'tenant[name="%s"]/logical-router/segment-interface[segment="%s"]' %( name, logical_router_interface )
            response = rest.put(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error adding segment interface to router '{}': {}".format(name, response.info))

            if subnet:
                data = {"ip-cidr": subnet}
                path += '/ip-subnet[ip-cidr="\'%s\'"]' % subnet
                response = rest.put(path, data=data)
                if response.status_code != 204:
                    module.fail_json(msg="error configuring ip subnet to router interface '{}': {}".format(name, response.info))

        if logical_router_system_tenant_interface['state'] == 'present':
            data = {"remote-tenant": "system"}
            path = 'tenant[name="%s"]/logical-router/tenant-interface[remote-tenant="system"]' % name
            response = rest.put(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error adding system tenant interface to router '{}': {}".format(name, response.info))

        for destination_subnet in routes:
            try:
                next_hop_type, next_hop_value = routes[destination_subnet].split(':')
            except ValueError:
                module.fail_json(msg="malformed route to '{}' for tenant '{}': {}".format(destination_subnet, name, response.info))
            data = {'next-hop': {next_hop_type: next_hop_value}, "dst-ip-subnet": destination_subnet}
            path = 'tenant[name="%s"]/logical-router/static-route[dst-ip-subnet="\'%s\'"]' %( name, destination_subnet)
            response = rest.put(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error configuring route for destination subnet '{}': {}".format(destination_subnet, response.info))

        for next_hop_group in next_hop_groups:
            ip = next_hop_groups[next_hop_group]

            data = {'name': next_hop_group}
            path = 'tenant[name="%s"]/logical-router/next-hop-group[name="%s"]' %( name, next_hop_group)
            response = rest.put(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error configuring next-hop-group '{}': {}".format(next_hop_group, response.info))

            data = {'ip-address': ip}
            path = 'tenant[name="%s"]/logical-router/next-hop-group[name="%s"]/ip-address[ip-address="\'%s\'"]' %( name, next_hop_group, ip)
            response = rest.put(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error configuring next-hop-group '{}': {}".format(next_hop_group, response.info))

        for policy_list in policy_lists:
            rules = policy_lists[policy_list]
            if not isinstance(rules, list):
                module.fail_json(msg="policy list '{}' must be a list of rules: {}".format(policy_list, response.info))
            data = {'name': policy_list}
            path = 'tenant[name="%s"]/logical-router/policy-list[name="%s"]' % (name, policy_list)
            response = rest.put(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error configuring policy list '{}': {}".format(policy_list, response.info))
            for rule in rules:
                data = rule
                if data['action'] == 'next-hop':
                    path = 'tenant[name="%s"]/logical-router/policy-list[name="%s"]/rule[next-hop/next-hop-group="%s"][seq=%s][segment-interface="%s"][dst/segment="%s"][dst/tenant="%s"][action="%s"]' % (name, policy_list, data["next-hop"]["next-hop-group"], data["seq"], data["segment-interface"], data["dst"]["segment"], data["dst"]["tenant"], data["action"])
                else:
                    path = 'tenant[name="%s"]/logical-router/policy-list[name="%s"]/rule[seq=%s][action="%s"]' % (name, policy_list, data["seq"], data["action"])
                response = rest.put(path, data=data)
                if response.status_code != 204:
                    module.fail_json(msg="error configuring policy list '{}': {}".format(policy_list, response.info))

        if inbound_policy:
            data = {'inbound-policy': inbound_policy}
            path = 'tenant[name="%s"]/logical-router' % name
            response = rest.patch(path, data=data)
            if response.status_code != 204:
                module.fail_json(msg="error applying policy list to tenant '{}': {}".format(name, response.info))

        module.exit_json(changed=True)

    if state in ('absent'):
        response = rest.delete('tenant[name="%s"]' % name, data={})
        if response.status_code == 204:
            module.exit_json(changed=True)
        else:
            module.fail_json(msg="error deleting tenant '{}': {}".format(name, response.info['msg']))

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            tenant_id=dict(type='str', required=False),
            logical_router_interfaces=dict(type='dict', default={}),
            logical_router_system_tenant_interface=dict(type='dict', default={'state':'absent'}),
            routes=dict(type='dict', default={}),
            next_hop_groups=dict(type='dict', default={}),
            policy_lists=dict(type='dict', default={}),
            inbound_policy=dict(type='str', required=False),
            controller=dict(type='str', required=True),
            state=dict(choices=['present', 'absent'], default='present'),
            validate_certs=dict(type='bool', default='False'), # TO DO: change this to default = True
            access_token=dict(type='str', no_log=True)
        )
    )

    try:
        tenant(module)
    except Exception:
        e = get_exception()
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
