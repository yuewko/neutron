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
import operator

from taskflow import task

from neutron.ipam.drivers.infoblox import exceptions
from oslo.config import cfg as neutron_conf


class CreateNetViewTask(task.Task):
    def execute(self, obj_manip, net_view_name,
                nview_extattrs, dhcp_member, disable_dhcp):
        member = dhcp_member
        if disable_dhcp:
            member = None
        obj_manip.create_network_view(
                        net_view_name, nview_extattrs, member)

    def revert(self, obj_manip, net_view_name, **kwargs):
        if not obj_manip.has_networks(net_view_name):
            obj_manip.delete_network_view(net_view_name)


class CreateNetworkTask(task.Task):
    def execute(self, obj_manip, net_view_name, cidr, nameservers,
                dhcp_member, gateway_ip, dhcp_trel_ip, network_extattrs,
                related_members, disable_dhcp):
        if disable_dhcp:
            dhcp_member = []
        obj_manip.create_network(net_view_name, cidr, nameservers, dhcp_member,
                                 gateway_ip, dhcp_trel_ip, network_extattrs)
        for member in related_members:
            obj_manip.restart_all_services(member)

    def revert(self, obj_manip, net_view_name, related_members, cidr,
               **kwargs):
        obj_manip.delete_network(net_view_name, cidr)
        for member in related_members:
            obj_manip.restart_all_services(member)


class ChainInfobloxNetworkTask(task.Task):
    def execute(self, obj_manip, net_view_name, cidr, network_extattrs):
        ea_names = ['Is External', 'Is Shared']

        eas = operator.itemgetter(*ea_names)(network_extattrs)
        shared_or_external = any(eval(ea['value']) for ea in eas)

        if shared_or_external or neutron_conf.CONF.subnet_shared_for_creation:
            ib_network = obj_manip.get_network(net_view_name, cidr)
            obj_manip.update_network_options(ib_network, network_extattrs)
        else:
            raise exceptions.InfobloxInternalPrivateSubnetAlreadyExist()

    def revert(self, obj_manip, net_view_name, cidr, network_extattrs,
               **kwargs):
        # keep NIOS network untouched on rollback
        pass


class CreateNetworkFromTemplateTask(task.Task):
    def execute(self, obj_manip, net_view_name, cidr, template,
                network_extattrs):
        obj_manip.create_network_from_template(
            net_view_name, cidr, template, network_extattrs)

    def revert(self, obj_manip, net_view_name, cidr, **kwargs):
        obj_manip.delete_network(net_view_name, cidr)


class CreateIPRange(task.Task):
    def execute(self, obj_manip, net_view_name, start_ip, end_ip, disable,
                cidr, range_extattrs, ip_version, ipv6_ra_mode=None,
                ipv6_address_mode=None):
        obj_manip.create_ip_range(net_view_name, start_ip, end_ip,
                                  cidr, disable, range_extattrs)

    def revert(self, obj_manip, net_view_name, start_ip, end_ip,
               ip_version, ipv6_ra_mode=None, ipv6_address_mode=None,
               **kwargs):
        obj_manip.delete_ip_range(net_view_name, start_ip, end_ip)


class CreateDNSViewTask(task.Task):
    def execute(self, obj_manip, net_view_name, dns_view_name):
        obj_manip.create_dns_view(net_view_name, dns_view_name)

    def revert(self, **kwargs):
        # never delete DNS view
        pass


class CreateDNSZonesTask(task.Task):
    def execute(self, obj_manip, dnsview_name, fqdn, dns_member,
                secondary_dns_members, zone_extattrs, **kwargs):
        obj_manip.create_dns_zone(dnsview_name, fqdn, dns_member,
                                  secondary_dns_members,
                                  zone_extattrs=zone_extattrs)

    def revert(self, obj_manip, dnsview_name, fqdn, **kwargs):
        obj_manip.delete_dns_zone(dnsview_name, fqdn)


class CreateDNSZonesTaskCidr(task.Task):
    def execute(self, obj_manip, dnsview_name, cidr, dns_member, zone_format,
                secondary_dns_members, prefix, zone_extattrs, **kwargs):
        obj_manip.create_dns_zone(dnsview_name, cidr, dns_member,
                                  secondary_dns_members,
                                  prefix=prefix,
                                  zone_format=zone_format,
                                  zone_extattrs=zone_extattrs)

    def revert(self, obj_manip, dnsview_name, cidr, **kwargs):
        obj_manip.delete_dns_zone(dnsview_name, cidr)


class CreateDNSZonesFromNSGroupTask(task.Task):
    def execute(self, obj_manip, dnsview_name, fqdn, ns_group,
                zone_extattrs, **kwargs):
        obj_manip.create_dns_zone(dnsview_name, fqdn, ns_group=ns_group,
                                  zone_extattrs=zone_extattrs)

    def revert(self, obj_manip, dnsview_name, fqdn, **kwargs):
        obj_manip.delete_dns_zone(dnsview_name, fqdn)


class CreateDNSZonesCidrFromNSGroupTask(task.Task):
    def execute(self, obj_manip, dnsview_name, cidr, ns_group, zone_format,
                prefix, zone_extattrs, **kwargs):
        obj_manip.create_dns_zone(dnsview_name, cidr,
                                  ns_group=ns_group,
                                  prefix=prefix,
                                  zone_format=zone_format,
                                  zone_extattrs=zone_extattrs)

    def revert(self, obj_manip, dnsview_name, cidr, **kwargs):
        obj_manip.delete_dns_zone(dnsview_name, cidr)
