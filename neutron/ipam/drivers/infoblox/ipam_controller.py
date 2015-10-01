# Copyright 2014 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo.config import cfg as neutron_conf
from taskflow.patterns import linear_flow

from neutron.api.v2 import attributes
from neutron.db.infoblox import infoblox_db
from neutron.db.infoblox import models
from neutron.ipam.drivers.infoblox import config
from neutron.ipam.drivers.infoblox import dns_controller
from neutron.ipam.drivers.infoblox import ea_manager
from neutron.ipam.drivers.infoblox import exceptions
from neutron.ipam.drivers.infoblox import tasks
from neutron.ipam.drivers import neutron_db
from neutron.ipam.drivers import neutron_ipam
from oslo_log import log as logging
from neutron.openstack.common import uuidutils


OPTS = [
    neutron_conf.BoolOpt('use_host_records_for_ip_allocation',
                         default=True,
                         help=_("Use host records for IP allocation. "
                                "If False then Fixed IP + A + PTR record "
                                "are used.")),
    neutron_conf.StrOpt('dhcp_relay_management_network_view',
                        default="default",
                        help=_("NIOS network view to be used for DHCP inside "
                                "management network")),
    neutron_conf.StrOpt('dhcp_relay_management_network',
                        default=None,
                        help=_("CIDR for the management network served by "
                               "Infoblox DHCP member")),
    neutron_conf.BoolOpt('allow_admin_network_deletion',
                         default=False,
                         help=_("Allow admin network which is global, "
                                "external, or shared to be deleted")),
    neutron_conf.BoolOpt('subnet_shared_for_creation',
                         default=False,
                         help=_("Treat subnet as shared during creation. "
                                "When set to true, if network already exist "
                                "on Infoblox, it will be shared")),
    neutron_conf.BoolOpt('subnet_shared_for_deletion',
                         default=False,
                         help=_("Treat subnet as shared during deletion. "
                                "When set to true, network on Infoblox is "
                                "considered shared and therefore not deleted"))
]

neutron_conf.CONF.register_opts(OPTS)
LOG = logging.getLogger(__name__)


class InfobloxIPAMController(neutron_ipam.NeutronIPAMController):
    def __init__(self, obj_manip=None, config_finder=None, ip_allocator=None,
                 extattr_manager=None, ib_db=None, db_mgr=None):
        """IPAM backend implementation for Infoblox."""
        self.infoblox = obj_manip
        self.config_finder = config_finder
        self.ip_allocator = ip_allocator
        self.pattern_builder = config.PatternBuilder

        if extattr_manager is None:
            extattr_manager = ea_manager.InfobloxEaManager(infoblox_db)

        if db_mgr is None:
            db_mgr = neutron_db

        self.db_manager = db_mgr
        self.ea_manager = extattr_manager

        if ib_db is None:
            ib_db = infoblox_db

        self.ib_db = ib_db

    def create_subnet(self, context, s):
        subnet = super(InfobloxIPAMController, self).create_subnet(context, s)

        cfg = self.config_finder.find_config_for_subnet(context, subnet)
#        dhcp_members = []
#        if not cfg.disable_dhcp:
#            dhcp_members = cfg.reserve_dhcp_members()
        dhcp_members = cfg.reserve_dhcp_members()
        dns_members = cfg.reserve_dns_members()

        network = self._get_network(context, subnet['network_id'])
        create_infoblox_member = True

        create_subnet_flow = linear_flow.Flow('ib_create_subnet')

        if self.infoblox.network_exists(cfg.network_view, subnet['cidr']):
            create_subnet_flow.add(tasks.ChainInfobloxNetworkTask())
            create_infoblox_member = False

        if not infoblox_db.get_network_view(context, subnet['network_id']):
            infoblox_db.set_network_view(context, cfg.network_view,
                                         subnet['network_id'])

        # Neutron will sort this later so make sure infoblox copy is
        # sorted too.
        user_nameservers = sorted(dns_controller.get_nameservers(s))

        # For flat network we save member IP as a primary DNS server: to
        # the beginning of the list.
        # If this net is not flat, Member IP will later be replaced by
        # DNS relay IP.
        nameservers = [n for n in [item.ipv6 if subnet['ip_version'] == 6
                                   else item.ip for item in dns_members] if n]

        nameservers += [n for n in user_nameservers if n not in nameservers]
        nview_extattrs = self.ea_manager.get_extattrs_for_nview(context)
        network_extattrs = self.ea_manager.get_extattrs_for_network(
            context, subnet, network)
        range_extattrs = self.ea_manager.get_extattrs_for_range(
            context, network)
        method_arguments = {
            'obj_manip':        self.infoblox,
            'net_view_name':    cfg.network_view,
            'dns_view_name':    cfg.dns_view,
            'cidr':             subnet['cidr'],
            'disable_dhcp':     cfg.disable_dhcp,
            'dhcp_member':      dhcp_members,
            'gateway_ip':       subnet['gateway_ip'],
            'disable':          True,
            'nameservers':      nameservers,
            'range_extattrs':   range_extattrs,
            'network_extattrs': network_extattrs,
            'nview_extattrs':   nview_extattrs,
            'related_members':  set(cfg.dhcp_members + cfg.dns_members),
            'dhcp_trel_ip':     infoblox_db.get_management_net_ip(
                context, subnet['network_id']),
            'ip_version':       subnet['ip_version']
        }

        if subnet['ip_version'] == 6 and subnet['enable_dhcp']:
            if attributes.is_attr_set(subnet.get('ipv6_ra_mode')):
                method_arguments['ipv6_ra_mode'] = subnet['ipv6_ra_mode']
            if attributes.is_attr_set(subnet.get('ipv6_address_mode')):
                method_arguments[
                    'ipv6_address_mode'] = subnet['ipv6_address_mode']

        if cfg.require_dhcp_relay:
            for member in dhcp_members:
                dhcp_member = models.InfobloxDHCPMember(
                    server_ip=member.ip,
                    server_ipv6=member.ipv6,
                    network_id=network.id
                )
                context.session.add(dhcp_member)

            for member in dns_members:
                dns_member = models.InfobloxDNSMember(
                    server_ip=member.ip,
                    server_ipv6=member.ipv6,
                    network_id=network.id
                )
                context.session.add(dns_member)

        if cfg.requires_net_view():
            create_subnet_flow.add(tasks.CreateNetViewTask())

        if cfg.network_template:
            method_arguments['template'] = cfg.network_template
            create_subnet_flow.add(tasks.CreateNetworkFromTemplateTask())
        elif create_infoblox_member:
            create_subnet_flow.add(tasks.CreateNetworkTask())

        create_subnet_flow.add(tasks.CreateDNSViewTask())

        for ip_range in subnet['allocation_pools']:
            # context.store is a global dict of method arguments for tasks
            # in current flow, hence method arguments need to be rebound
            first = ip_range['start']
            last = ip_range['end']
            first_ip_arg = 'ip_range %s' % first
            last_ip_arg = 'ip_range %s' % last
            method_arguments[first_ip_arg] = first
            method_arguments[last_ip_arg] = last
            task_name = '-'.join([first, last])

            create_subnet_flow.add(
                tasks.CreateIPRange(name=task_name,
                                    rebind={'start_ip': first_ip_arg,
                                            'end_ip': last_ip_arg}))

        context.store.update(method_arguments)
        context.parent_flow.add(create_subnet_flow)

        return subnet

    def update_subnet(self, context, subnet_id, subnet):
        backend_subnet = self.get_subnet_by_id(context, subnet_id)
        cfg = self.config_finder.find_config_for_subnet(context,
                                                        backend_subnet)
        cfg.verify_subnet_update_is_allowed(subnet)

        ib_network = self.infoblox.get_network(cfg.network_view,
                                               subnet['cidr'])

        user_nameservers = sorted(subnet.get('dns_nameservers', []))
        updated_nameservers = user_nameservers
        if (ib_network.member_ip_addrs and
                ib_network.member_ip_addrs[0] in ib_network.dns_nameservers):
            # Flat network, primary dns is member_ip
            primary_dns = ib_network.member_ip_addrs[0]
            updated_nameservers = [primary_dns] + user_nameservers
        else:
            # Network with relays, primary dns is relay_ip
            primary_dns = self.ib_db.get_subnet_dhcp_port_address(
                context, subnet['id'])
            if primary_dns:
                updated_nameservers = [primary_dns] + user_nameservers

        ib_network.dns_nameservers = updated_nameservers

        network = self._get_network(context, subnet['network_id'])
        eas = self.ea_manager.get_extattrs_for_network(context, subnet,
                                                       network)
        self.infoblox.update_network_options(ib_network, eas)

        self.restart_services(context, subnet=subnet)
        return backend_subnet

    def delete_subnet(self, context, subnet):
        deleted_subnet = super(InfobloxIPAMController, self).delete_subnet(
            context, subnet)

        cfg = self.config_finder.find_config_for_subnet(context, subnet)
        network = self._get_network(context, subnet['network_id'])
        members_to_restart = list(set(cfg.dhcp_members + cfg.dns_members))
        is_shared = network.get('shared')
        is_external = infoblox_db.is_network_external(context,
                                                      subnet['network_id'])

        if neutron_conf.CONF.allow_admin_network_deletion or \
            not (cfg.is_global_config or is_shared or is_external or
                 neutron_conf.CONF.subnet_shared_for_deletion):
            self.infoblox.delete_network(
                cfg.network_view, cidr=subnet['cidr'])

        if self._determine_member_deletion(context,
                                           cfg.network_view_scope,
                                           subnet['id'],
                                           subnet['network_id'],
                                           subnet['tenant_id']):
            cfg.release_member(cfg.network_view)

        if cfg.require_dhcp_relay and \
            self.ib_db.is_last_subnet_in_network(context, subnet['id'],
                                                 subnet['network_id']):
                member = context.session.query(models.InfobloxDNSMember)
                member.filter_by(network_id=network.id).delete()

                member = context.session.query(models.InfobloxDHCPMember)
                member.filter_by(network_id=network.id).delete()

        preconf_dns_view = cfg._dns_view
        if (preconf_dns_view and not preconf_dns_view.startswith('default')
                and not self.infoblox.has_dns_zones(preconf_dns_view)):
            self.infoblox.delete_dns_view(preconf_dns_view)

        self.restart_services(context, members=members_to_restart)
        return deleted_subnet

    def _determine_member_deletion(self, context, network_view_scope,
                                   subnet_id, network_id, tenant_id):
        if network_view_scope == 'static':
            return self.ib_db.is_last_subnet(context, subnet_id)
        if network_view_scope == 'tenant_id':
            return self.ib_db.is_last_subnet_in_tenant(context,
                                                       subnet_id,
                                                       tenant_id)
        if network_view_scope == 'tenant_name':
            return self.ib_db.is_last_subnet_in_tenant(context,
                                                       subnet_id,
                                                       tenant_id)
        if network_view_scope == 'network_id':
            return self.ib_db.is_last_subnet_in_network(context,
                                                        subnet_id,
                                                        network_id)
        # In order to use network_name scope, a network name must be unique.
        # Openstack does not enforce this so user has to make sure that
        # each network name is unique when {network_name} pattern is used
        # for network view name. Then this is the same as network_id scope.
        if network_view_scope == 'network_name':
            return self.ib_db.is_last_subnet_in_network(context,
                                                        subnet_id,
                                                        network_id)

    def allocate_ip(self, context, subnet, port, ip=None):
        hostname = uuidutils.generate_uuid()
        mac = port['mac_address']
        extattrs = self.ea_manager.get_extattrs_for_ip(context, port)

        LOG.debug("Trying to allocate IP for %s on Infoblox NIOS" % hostname)

        cfg = self.config_finder.find_config_for_subnet(context, subnet)

        networkview_name = cfg.network_view
        dnsview_name = cfg.dns_view
        zone_auth = self.pattern_builder(cfg.domain_suffix_pattern).build(
            context, subnet)

        if ip and ip.get('ip_address', None):
            subnet_id = ip.get('subnet_id', None)
            ip_to_be_allocated = ip.get('ip_address', None)
            allocated_ip = self.ip_allocator.allocate_given_ip(
                networkview_name, dnsview_name, zone_auth, hostname, mac,
                ip_to_be_allocated, extattrs)
            allocated_ip = {'subnet_id': subnet_id,
                            'ip_address': allocated_ip}
        else:
            # Allocate next available considering IP ranges.
            ip_ranges = subnet['allocation_pools']
            # Let Infoblox try to allocate an IP from each ip_range
            # consistently, and break on the first successful allocation.
            for ip_range in ip_ranges:
                first_ip = ip_range['first_ip']
                last_ip = ip_range['last_ip']
                try:
                    allocated_ip = self.ip_allocator.allocate_ip_from_range(
                        dnsview_name, networkview_name, zone_auth, hostname,
                        mac, first_ip, last_ip, extattrs)
                    allocated_ip = {'subnet_id': subnet['id'],
                                    'ip_address': allocated_ip}

                    break
                except exceptions.InfobloxCannotAllocateIp:
                    LOG.debug("Failed to allocate IP from range (%s-%s)." %
                              (first_ip, last_ip))
                    continue
            else:
                # We went through all the ranges and Infoblox did not
                # allocated any IP.
                LOG.debug("Network %s does not have IPs "
                          "available for allocation." % subnet['cidr'])
                return None

        LOG.debug('IP address allocated on Infoblox NIOS: %s', allocated_ip)

        for member in set(cfg.dhcp_members):
            self.infoblox.restart_all_services(member)

        return allocated_ip

    def deallocate_ip(self, context, subnet, port, ip):
        cfg = self.config_finder.find_config_for_subnet(context, subnet)
        net_id = subnet['network_id']
        self.ip_allocator.deallocate_ip(cfg.network_view, cfg.dns_view, ip)
        self.ib_db.delete_ip_allocation(context, net_id, subnet, ip)

        for member in set(cfg.dhcp_members):
            self.infoblox.restart_all_services(member)

    def set_dns_nameservers(self, context, port):
        # Replace member IP in DNS nameservers by DNS relay IP.
        for ip in port['fixed_ips']:
            subnet = self._get_subnet(context, ip['subnet_id'])
            cfg = self.config_finder.find_config_for_subnet(context, subnet)
            net = self.infoblox.get_network(cfg.network_view, subnet['cidr'])
            if not net.members:
                continue
            if not net.has_dns_members():
                LOG.debug("No domain-name-servers option found, it will"
                          "not be updated to the private IPAM relay IP.")
                continue
            net.update_member_ip_in_dns_nameservers(ip['ip_address'])
            self.infoblox.update_network_options(net)

    def create_network(self, context, network):
        if not neutron_conf.CONF.dhcp_relay_management_network:
            LOG.info(_('dhcp_relay_management_network option is not set in '
                       'config. DHCP will be used for management network '
                       'interface.'))
            return network

        net_view_name = neutron_conf.CONF.dhcp_relay_management_network_view
        cidr = neutron_conf.CONF.dhcp_relay_management_network
        mac = ':'.join(['00'] * 6)

        # Note(pbondar): If IP is allocated for dhcp relay (trel interface)
        # when dhcp relay management network is set,
        # OpenStack is unware of this so no port to associate with.
        # In this case, we still need to populate EAs with default values.
        ip_extattrs = self.ea_manager.get_default_extattrs_for_ip(context)
        created_fixed_address = self.infoblox.create_fixed_address_from_cidr(
            net_view_name, mac, cidr, ip_extattrs)

        self.ib_db.add_management_ip(context,
                                     network['id'],
                                     created_fixed_address)
        return network

    def delete_network(self, context, network_id):
        subnets = self.db_manager.get_subnets_by_network(context, network_id)
        net_view = infoblox_db.get_network_view(context, network_id)

        for subnet in subnets:
            LOG.info('Removing subnet %s from network %s.' % (
                subnet.id, network_id
            ))
            self.delete_subnet(context, subnet)

        if net_view and not self.infoblox.has_networks(net_view):
            self.infoblox.delete_network_view(net_view)

        fixed_address_ref = self.ib_db.get_management_ip_ref(context,
                                                             network_id)

        if fixed_address_ref is not None:
            self.infoblox.delete_object_by_ref(fixed_address_ref)
            self.ib_db.delete_management_ip(context, network_id)

    def restart_services(self, context, members=None, subnet=None):
        if not members:
            members = []

        if subnet:
            cfg = self.config_finder.find_config_for_subnet(context, subnet)
            for member in set(cfg.dhcp_members + cfg.dns_members):
                members.append(member)

        for member in set(members):
            self.infoblox.restart_all_services(member)
