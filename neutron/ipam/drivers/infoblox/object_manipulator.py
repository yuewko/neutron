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

import netaddr

from neutron.ipam.drivers.infoblox import exceptions as exc
from neutron.ipam.drivers.infoblox import objects
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class IPBackend():
    def __init__(self, object_manipulator):
        self.obj_man = object_manipulator

    def get_network(self, net_view_name, cidr):
        net_data = {'network_view': net_view_name,
                    'network': cidr}
        net = self.obj_man._get_infoblox_object_or_none(
            self.ib_network_name, net_data,
            return_fields=['options', 'members'])
        if not net:
            raise exc.InfobloxNetworkNotAvailable(
                net_view_name=net_view_name, cidr=cidr)
        return objects.Network.from_dict(net)

    def get_all_associated_objects(self, net_view_name, ip):
        assoc_with_ip = {
            'network_view': net_view_name,
            'ip_address': ip
        }
        assoc_objects = None
        try:
            assoc_objects = self.obj_man._get_infoblox_object_or_none(
                self.ib_ipaddr_object_name, assoc_with_ip,
                return_fields=['objects'], proxy=True)
        except exc.InfobloxSearchError:
            LOG.warning("Objects associated with %s/%s cannot be deleted"
                        " because it cannot be found" %
                        (net_view_name, ip))
        if assoc_objects:
            return assoc_objects['objects']
        return []

    def network_exists(self, net_view_name, cidr):
        net_data = {'network_view': net_view_name, 'network': cidr}
        try:
            net = self.obj_man._get_infoblox_object_or_none(
                self.ib_network_name, net_data,
                return_fields=['options', 'members'])
        except exc.InfobloxSearchError:
            net = None
        return net is not None

    def delete_network(self, net_view_name, cidr):
        payload = {'network_view': net_view_name,
                   'network': cidr}
        self.obj_man._delete_infoblox_object(
            self.ib_network_name, payload)

    def delete_ip_range(self, net_view, start_ip, end_ip):
        range_data = {'start_addr': start_ip,
                      'end_addr': end_ip,
                      'network_view': net_view}
        self.obj_man._delete_infoblox_object(self.ib_range_name, range_data)

    def delete_ip_from_host_record(self, host_record, ip):
        host_record.ips.remove(ip)
        self.obj_man._update_host_record_ips(self.ib_ipaddrs_name, host_record)
        return host_record

    def delete_host_record(self, dns_view_name, ip_address):
        host_record_data = {'view': dns_view_name,
                            self.ib_ipaddr_name: ip_address}
        self.obj_man._delete_infoblox_object(
            'record:host', host_record_data)

    def delete_fixed_address(self, network_view, ip):
        fa_data = {'network_view': network_view,
                   self.ib_ipaddr_name: ip}
        self.obj_man._delete_infoblox_object(
            self.ib_fixedaddress_name, fa_data)

    def bind_name_with_host_record(self, dnsview_name, ip, name, extattrs):
        record_host = {
            self.ib_ipaddr_name: ip,
            'view': dnsview_name
        }
        update_kwargs = {'name': name, 'extattrs': extattrs}
        self.obj_man._update_infoblox_object(
            'record:host', record_host, update_kwargs)

    def update_host_record_eas(self, dns_view, ip, extattrs):
        fa_data = {'view': dns_view,
                   self.ib_ipaddr_name: ip}
        fa = self.obj_man._get_infoblox_object_or_none(
            'record:host', fa_data)
        if fa:
            self.obj_man._update_infoblox_object_by_ref(
                fa, {'extattrs': extattrs})

    def update_fixed_address_eas(self, network_view, ip, extattrs):
        fa_data = {'network_view': network_view,
                   self.ib_ipaddr_name: ip}
        fa = self.obj_man._get_infoblox_object_or_none(
            self.ib_fixedaddress_name, fa_data)
        if fa:
            self.obj_man._update_infoblox_object_by_ref(
                fa, {'extattrs': extattrs})

    def update_dns_record_eas(self, dns_view, ip, extattrs):
        fa_data = {'view': dns_view,
                   self.ib_ipaddr_name: ip}
        fa = self.obj_man._get_infoblox_object_or_none(
            'record:a', fa_data)
        if fa:
            self.obj_man._update_infoblox_object_by_ref(
                fa, {'extattrs': extattrs})

        fa = self.obj_man._get_infoblox_object_or_none(
            'record:ptr', fa_data)
        if fa:
            self.obj_man._update_infoblox_object_by_ref(
                fa, {'extattrs': extattrs})


class IPv4Backend(IPBackend):
    ib_ipaddr_name = 'ipv4addr'
    ib_ipaddrs_name = 'ipv4addrs'
    ib_ipaddr_object_name = 'ipv4address'
    ib_network_name = 'network'
    ib_fixedaddress_name = 'fixedaddress'
    ib_range_name = 'range'

    def create_network(self, net_view_name, cidr, nameservers=None,
                       members=None, gateway_ip=None, dhcp_trel_ip=None,
                       network_extattrs=None):
        # import pdb; pdb.set_trace()
        network_data = {'network_view': net_view_name,
                        'network': cidr,
                        'extattrs': network_extattrs}
        members_struct = []
        for member in members:
            members_struct.append({'ipv4addr': member.ip,
                                   '_struct': 'dhcpmember'})
        if members_struct:
            network_data['members'] = members_struct

        dhcp_options = []

        if nameservers:
            dhcp_options.append({'name': 'domain-name-servers',
                                 'value': ",".join(nameservers)})

        if gateway_ip:
            dhcp_options.append({'name': 'routers',
                                 'value': gateway_ip})

        if dhcp_trel_ip:
            dhcp_options.append({'name': 'dhcp-server-identifier',
                                 'num': 54,
                                 'value': dhcp_trel_ip})

        if dhcp_options:
            network_data['options'] = dhcp_options

        return self.obj_man._create_infoblox_object(
            self.ib_network_name, network_data, check_if_exists=False)

    def create_ip_range(self, network_view, start_ip, end_ip, network,
                        disable, range_extattrs):
        range_data = {'start_addr': start_ip,
                      'end_addr': end_ip,
                      'extattrs': range_extattrs,
                      'network_view': network_view}
        ib_object = self.obj_man._get_infoblox_object_or_none('range',
                                                              range_data)
        if not ib_object:
            range_data['disable'] = disable
            self.obj_man._create_infoblox_object(
                'range', range_data, check_if_exists=False)

    def add_ip_to_record(self, host_record, ip, mac):
        host_record.ips.append(objects.IPv4(ip, mac))
        ips = self.obj_man._update_host_record_ips('ipv4addrs', host_record)
        hr = objects.HostRecordIPv4.from_dict(ips)
        return hr

    def create_host_record(self):
        return objects.HostRecordIPv4()

    def get_host_record(self, dns_view, ip):
        data = {
            'view': dns_view,
            'ipv4addr': ip
        }

        raw_host_record = self.obj_man._get_infoblox_object_or_none(
            'record:host', data, return_fields=['ipv4addrs'])

        if raw_host_record:
            hr = objects.HostRecordIPv4.from_dict(raw_host_record)
            return hr

    def get_fixed_address(self):
        return objects.FixedAddressIPv4()

    def bind_name_with_record_a(self, dnsview_name, ip, name, bind_list,
                                extattrs):
        # Forward mapping
        if 'record:a' in bind_list:
            payload = {
                self.ib_ipaddr_name: ip,
                'view': dnsview_name
            }
            additional_create_kwargs = {
                'name': name,
                'extattrs': extattrs
            }
            self.obj_man._create_infoblox_object(
                'record:a', payload,
                additional_create_kwargs,
                update_if_exists=True)

        # Reverse mapping
        if 'record:ptr' in bind_list:
            record_ptr_data = {
                self.ib_ipaddr_name: ip,
                'view': dnsview_name
            }
            additional_create_kwargs = {
                'ptrdname': name,
                'extattrs': extattrs
            }
            self.obj_man._create_infoblox_object(
                'record:ptr', record_ptr_data,
                additional_create_kwargs,
                update_if_exists=True)

    def unbind_name_from_record_a(self, dnsview_name, ip, name, unbind_list):
        if 'record:a' in unbind_list:
            dns_record_a = {
                'name': name,
                self.ib_ipaddr_name: ip,
                'view': dnsview_name
            }
            self.obj_man._delete_infoblox_object(
                'record:a', dns_record_a)

        if 'record:ptr' in unbind_list:
            dns_record_ptr = {
                'ptrdname': name,
                'view': dnsview_name
            }
            self.obj_man._delete_infoblox_object(
                'record:ptr', dns_record_ptr)

    def find_hostname(self, dns_view, hostname):
        data = {
            'name': hostname,
            'view': dns_view
        }

        raw_host_record = self.obj_man._get_infoblox_object_or_none(
            'record:host', data, return_fields=['ipv4addrs'])

        if raw_host_record:
            hr = objects.HostRecordIPv4.from_dict(raw_host_record)
            return hr


class IPv6Backend(IPBackend):
    ib_ipaddr_name = 'ipv6addr'
    ib_ipaddrs_name = 'ipv6addrs'
    ib_ipaddr_object_name = 'ipv6address'
    ib_network_name = 'ipv6network'
    ib_fixedaddress_name = 'ipv6fixedaddress'
    ib_range_name = 'ipv6range'

    def create_network(self, net_view_name, cidr, nameservers=None,
                       members=None, gateway_ip=None, dhcp_trel_ip=None,
                       network_extattrs=None):
        network_data = {'network_view': net_view_name,
                        'network': cidr,
                        'extattrs': network_extattrs}

        # member here takes ipv4addr since pre-hellfire NIOS version does not
        # support ipv6addr (Hellfire supports ipv6addr.
        # We are using ipv4addr to suppport both versions
        # This is just to the GM know which member is used for
        # their internal communication between GM and member so
        # it has nothing to do wiht DHCP protocol.
        members_struct = []
        for member in members:
            members_struct.append(member.specifier)
        if members_struct:
            network_data['members'] = members_struct

        dhcp_options = []

        if nameservers:
            dhcp_options.append({'name': 'domain-name-servers',
                                 'value': ",".join(nameservers)})

        if dhcp_options:
            network_data['options'] = dhcp_options

        return self.obj_man._create_infoblox_object(
            self.ib_network_name, network_data, check_if_exists=False)

    def create_ip_range(self, network_view, start_ip, end_ip, network,
                        disable, range_extattrs):
        range_data = {'start_addr': start_ip,
                      'end_addr': end_ip,
                      'extattrs': range_extattrs,
                      'network': network,
                      'network_view': network_view}
        ib_object = self.obj_man._get_infoblox_object_or_none('ipv6range',
                                                              range_data)
        if not ib_object:
            range_data['disable'] = disable
            self.obj_man._create_infoblox_object(
                'ipv6range', range_data, check_if_exists=False)

    def add_ip_to_record(self, host_record, ip, mac):
        host_record.ips.append(objects.IPv6(ip, mac))
        ips = self.obj_man._update_host_record_ips('ipv6addrs', host_record)
        hr = objects.HostRecordIPv6.from_dict(ips)
        return hr

    def create_host_record(self):
        return objects.HostRecordIPv6()

    def get_host_record(self, dns_view, ip):
        data = {
            'view': dns_view,
            'ipv6addr': ip
        }

        raw_host_record = self.obj_man._get_infoblox_object_or_none(
            'record:host', data, return_fields=['ipv6addrs'])

        if raw_host_record:
            hr = objects.HostRecordIPv6.from_dict(raw_host_record)
            return hr

    def get_fixed_address(self):
        return objects.FixedAddressIPv6()

    def bind_name_with_record_a(self, dnsview_name, ip, name, bind_list,
                                extattrs):
        # Forward mapping
        if 'record:aaaa' in bind_list:
            payload = {
                self.ib_ipaddr_name: ip,
                'view': dnsview_name
            }
            additional_create_kwargs = {
                'name': name,
                'extattrs': extattrs
            }
            self.obj_man._create_infoblox_object(
                'record:aaaa', payload,
                additional_create_kwargs,
                update_if_exists=True)

        # Reverse mapping
        if 'record:ptr' in bind_list:
            record_ptr_data = {
                self.ib_ipaddr_name: ip,
                'view': dnsview_name
            }
            additional_create_kwargs = {
                'ptrdname': name,
                'extattrs': extattrs
            }
            self.obj_man._create_infoblox_object(
                'record:ptr', record_ptr_data,
                additional_create_kwargs,
                update_if_exists=True)

    def unbind_name_from_record_a(self, dnsview_name, ip, name, unbind_list):
        if 'record:aaaa' in unbind_list:
            dns_record_a = {
                'name': name,
                self.ib_ipaddr_name: ip,
                'view': dnsview_name
            }
            self.obj_man._delete_infoblox_object(
                'record:aaaa', dns_record_a)

        if 'record:ptr' in unbind_list:
            dns_record_ptr = {
                'ptrdname': name,
                'view': dnsview_name
            }
            self.obj_man._delete_infoblox_object(
                'record:ptr', dns_record_ptr)

    def find_hostname(self, dns_view, hostname):
        data = {
            'name': hostname,
            'view': dns_view
        }

        raw_host_record = self.obj_man._get_infoblox_object_or_none(
            'record:host', data, return_fields=['ipv6addrs'])

        if raw_host_record:
            hr = objects.HostRecordIPv6.from_dict(raw_host_record)
            return hr


class IPBackendFactory():
    @staticmethod
    def get_ip_version(ipaddr):
        if type(ipaddr) is dict:
            ip = ipaddr['ip_address']
        else:
            ip = ipaddr

        try:
            ip = netaddr.IPAddress(ip)
        except ValueError:
            ip = netaddr.IPNetwork(ip)
        return ip.version

    @staticmethod
    def get(obj_man, ip):
        ip = IPBackendFactory.get_ip_version(ip)
        if ip == 4:
            return IPv4Backend(obj_man)
        elif ip == 6:
            return IPv6Backend(obj_man)


class InfobloxObjectManipulator(object):
    def __init__(self, connector):
        self.connector = connector

    def create_network_view(self, netview_name, nview_extattrs, member):
        net_view_data = {'name': netview_name,
                         'extattrs': nview_extattrs}
        return self._create_infoblox_object('networkview', net_view_data,
                                            delegate_member=member)

    def delete_network_view(self, net_view_name):
        # never delete default network view
        if net_view_name == 'default':
            return

        net_view_data = {'name': net_view_name}
        self._delete_infoblox_object('networkview', net_view_data)

    def create_dns_view(self, net_view_name, dns_view_name):
        dns_view_data = {'name': dns_view_name,
                         'network_view': net_view_name}
        return self._create_infoblox_object('view', dns_view_data)

    def delete_dns_view(self, net_view_name):
        net_view_data = {'name': net_view_name}
        self._delete_infoblox_object('view', net_view_data)

    def get_network(self, net_view_name, cidr):
        ip_backend = IPBackendFactory.get(self, cidr)
        return ip_backend.get_network(net_view_name, cidr)

    def has_networks(self, network_view_name):
        net_data = {'network_view': network_view_name}
        try:
            ib_net = self._get_infoblox_object_or_none('network', net_data)
            return bool(ib_net)
        except exc.InfobloxSearchError:
            return False

    def network_exists(self, net_view_name, cidr):
        ip_backend = IPBackendFactory.get(self, cidr)
        return ip_backend.network_exists(net_view_name, cidr)

    def create_network(self, net_view_name, cidr, nameservers=None,
                       members=None, gateway_ip=None, dhcp_trel_ip=None,
                       network_extattrs=None):
        ip_backend = IPBackendFactory.get(self, cidr)
        ip_backend.create_network(net_view_name, cidr, nameservers,
                                  members, gateway_ip, dhcp_trel_ip,
                                  network_extattrs)

    def delete_network(self, net_view_name, cidr):
        ip_backend = IPBackendFactory.get(self, cidr)
        ip_backend.delete_network(net_view_name, cidr)

    def create_network_from_template(self, net_view_name, cidr, template,
                                     network_extattrs):
        network_data = {
            'network_view': net_view_name,
            'network': cidr,
            'template': template,
            'extattrs': network_extattrs
        }
        return self._create_infoblox_object('network', network_data,
                                            check_if_exists=False)

    def update_network_options(self, ib_network, extattrs=None):
        payload = {}
        if ib_network.options:
            payload['options'] = ib_network.options
        if extattrs:
            payload['extattrs'] = extattrs
        self._update_infoblox_object_by_ref(ib_network.ref, payload)

    def create_ip_range(self, network_view, start_ip, end_ip, network,
                        disable, range_extattrs):
        ip_backend = IPBackendFactory.get(self, start_ip)
        ip_backend.create_ip_range(network_view, start_ip, end_ip,
                                   network, disable, range_extattrs)

    def delete_ip_range(self, net_view, start_ip, end_ip):
        ip_backend = IPBackendFactory.get(self, start_ip)
        ip_backend.delete_ip_range(net_view, start_ip, end_ip)

    def get_host_record(self, dns_view, ip):
        ip_backend = IPBackendFactory.get(self, ip)
        return ip_backend.get_host_record(dns_view, ip)

    def find_hostname(self, dns_view, hostname, ip):
        ip_backend = IPBackendFactory.get(self, ip)
        return ip_backend.find_hostname(dns_view, hostname)

    def create_host_record_for_given_ip(self, dns_view_name, zone_auth,
                                        hostname, mac, ip, extattrs):
        ip_backend = IPBackendFactory.get(self, ip)

        hr = ip_backend.create_host_record()
        hr.ip_version = IPBackendFactory.get_ip_version(ip)
        hr.hostname = hostname
        hr.zone_auth = zone_auth
        hr.mac = mac
        hr.dns_view = dns_view_name
        hr.ip = ip
        hr.extattrs = extattrs

        created_hr = self._create_infoblox_ip_address(hr)
        return created_hr

    def create_host_record_from_range(self, dns_view_name, network_view_name,
                                      zone_auth, hostname, mac, first_ip,
                                      last_ip, extattrs):
        ip_backend = IPBackendFactory.get(self, first_ip)

        hr = ip_backend.create_host_record()
        hr.ip_version = IPBackendFactory.get_ip_version(first_ip)
        hr.hostname = hostname
        hr.zone_auth = zone_auth
        hr.mac = mac
        hr.dns_view = dns_view_name
        hr.ip = objects.IPAllocationObject.next_available_ip_from_range(
            network_view_name, first_ip, last_ip)
        hr.extattrs = extattrs

        created_hr = self._create_infoblox_ip_address(hr)
        return created_hr

    def delete_host_record(self, dns_view_name, ip_address):
        ip_backend = IPBackendFactory.get(self, ip_address)
        ip_backend.delete_host_record(dns_view_name, ip_address)

    def create_fixed_address_for_given_ip(self, network_view, mac, ip,
                                          extattrs):
        ip_backend = IPBackendFactory.get(self, ip)

        fa = ip_backend.get_fixed_address()
        fa.ip = ip
        fa.net_view = network_view
        fa.mac = mac
        fa.extattrs = extattrs

        created_fa = self._create_infoblox_ip_address(fa)
        return created_fa

    def create_fixed_address_from_range(self, network_view, mac, first_ip,
                                        last_ip, extattrs):
        ip_backend = IPBackendFactory.get(self, first_ip)

        fa = ip_backend.get_fixed_address()
        fa.ip = objects.IPAllocationObject.next_available_ip_from_range(
            network_view, first_ip, last_ip)
        fa.net_view = network_view
        fa.mac = mac
        fa.extattrs = extattrs

        created_fa = self._create_infoblox_ip_address(fa)
        return created_fa

    def create_fixed_address_from_cidr(self, network_view, mac, cidr,
                                       extattrs):
        ip_backend = IPBackendFactory.get(self, cidr)

        fa = ip_backend.get_fixed_address()
        fa.ip = objects.IPAllocationObject.next_available_ip_from_cidr(
            network_view, cidr)
        fa.mac = mac
        fa.net_view = network_view
        fa.extattrs = extattrs

        created_fa = self._create_infoblox_ip_address(fa)
        return created_fa

    def delete_fixed_address(self, network_view, ip_address):
        ip_backend = IPBackendFactory.get(self, ip_address)
        ip_backend.delete_fixed_address(network_view, ip_address)

    def add_ip_to_record(self, host_record, ip, mac):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.add_ip_to_record(host_record, ip, mac)

    def add_ip_to_host_record_from_range(self, host_record, network_view,
                                         mac, first_ip, last_ip):
        ip = objects.IPAllocationObject.next_available_ip_from_range(
            network_view, first_ip, last_ip)
        hr = self.add_ip_to_record(host_record, ip, mac)
        return hr

    def delete_ip_from_host_record(self, host_record, ip):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.delete_ip_from_host_record(host_record, ip)

    def has_dns_zones(self, dns_view):
        zone_data = {'view': dns_view}
        try:
            zone = self._get_infoblox_object_or_none('zone_auth', zone_data)
            return bool(zone)
        except exc.InfobloxSearchError:
            return False

    def create_dns_zone(self, dns_view, dns_zone_fqdn, primary_dns_member=None,
                        secondary_dns_members=None, zone_format=None,
                        ns_group=None, prefix=None, zone_extattrs={}):
        # TODO(mirantis) support IPv6
        dns_zone_data = {'fqdn': dns_zone_fqdn,
                         'view': dns_view,
                         'extattrs': zone_extattrs}
        additional_create_kwargs = {}

        if primary_dns_member:
            grid_primary = [{'name': primary_dns_member.name,
                             '_struct': 'memberserver'}]
            additional_create_kwargs['grid_primary'] = grid_primary

        if secondary_dns_members:
            grid_secondaries = [{'name': member.name,
                                 '_struct': 'memberserver'}
                                for member in secondary_dns_members]
            additional_create_kwargs['grid_secondaries'] = grid_secondaries

        if zone_format:
            additional_create_kwargs['zone_format'] = zone_format

        if ns_group:
            additional_create_kwargs['ns_group'] = ns_group

        if prefix:
            additional_create_kwargs['prefix'] = prefix

        try:
            self._create_infoblox_object(
                'zone_auth', dns_zone_data, additional_create_kwargs,
                check_if_exists=True)
        except exc.InfobloxCannotCreateObject:
            LOG.warning(
                _('Unable to create DNS zone %(dns_zone_fqdn)s '
                  'for %(dns_view)s'),
                {'dns_zone_fqdn': dns_zone_fqdn, 'dns_view': dns_view})

    def delete_dns_zone(self, dns_view, dns_zone_fqdn):
        dns_zone_data = {'fqdn': dns_zone_fqdn,
                         'view': dns_view}
        self._delete_infoblox_object('zone_auth', dns_zone_data)

    def update_host_record_eas(self, dns_view, ip, extattrs):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.update_host_record_eas(dns_view, ip, extattrs)

    def update_fixed_address_eas(self, network_view, ip, extattrs):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.update_fixed_address_eas(network_view, ip, extattrs)

    def update_dns_record_eas(self, dns_view, ip, extattrs):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.update_dns_record_eas(dns_view, ip, extattrs)

    def bind_name_with_host_record(self, dnsview_name, ip, name, extattrs):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.bind_name_with_host_record(dnsview_name, ip, name, extattrs)

    def bind_name_with_record_a(self, dnsview_name, ip, name, bind_list,
                                extattrs):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.bind_name_with_record_a(dnsview_name, ip, name, bind_list,
                                           extattrs)

    def unbind_name_from_record_a(self, dnsview_name, ip, name, unbind_list):
        ip_backend = IPBackendFactory.get(self, ip)
        ip_backend.unbind_name_from_record_a(
            dnsview_name, ip, name, unbind_list)

    def get_member(self, member):
        return self.connector.get_object('member', {'host_name': member.name})

    def restart_all_services(self, member):
        if not member:
            return

        ib_members = self.get_member(member)
        if not ib_members:
            return

        ib_member = ib_members[0]
        if not ib_member['_ref']:
            return

        self.connector.call_func('restartservices', ib_member['_ref'],
                                 {'restart_option': 'RESTART_IF_NEEDED',
                                  'service_option': 'ALL'})

    def get_object_refs_associated_with_a_record(self, a_record_ref):
        associated_with_a_record = [  # {object_type, search_field}
            {'type': 'record:cname', 'search': 'canonical'},
            {'type': 'record:txt', 'search': 'name'}
        ]

        obj_refs = []
        a_record = self.connector.get_object(a_record_ref)

        for rec_inf in associated_with_a_record:
            objs = self.connector.get_object(
                rec_inf['type'], {'view': a_record['view'],
                                  rec_inf['search']: a_record['name']})
            if objs:
                for obj in objs:
                    obj_refs.append(obj['_ref'])

        return obj_refs

    def get_all_associated_objects(self, net_view_name, ip):
        ip_backend = IPBackendFactory.get(self, ip)
        return ip_backend.get_all_associated_objects(net_view_name, ip)

    def delete_all_associated_objects(self, net_view_name, ip, delete_list):
        del_objs = []
        obj_refs = self.get_all_associated_objects(net_view_name, ip)

        for obj_ref in obj_refs:
            del_objs.append(obj_ref)
            if (self._get_object_type_from_ref(obj_ref) in
                    ['record:a', 'record:aaaa']):
                del_objs.extend(
                    self.get_object_refs_associated_with_a_record(obj_ref))

        for obj_ref in del_objs:
            if self._get_object_type_from_ref(obj_ref) in delete_list:
                self.connector.delete_object(obj_ref)

    def delete_object_by_ref(self, ref):
        try:
            self.connector.delete_object(ref)
        except exc.InfobloxCannotDeleteObject as e:
            LOG.info(_("Failed to delete an object: %s"), e)

    def _create_infoblox_ip_address(self, ip_object):
        try:
            created_ip_json = self._create_infoblox_object(
                ip_object.infoblox_type,
                ip_object.to_dict(),
                check_if_exists=False,
                return_fields=ip_object.return_fields)

            return ip_object.from_dict(created_ip_json)
        except exc.InfobloxCannotCreateObject as e:
            if "Cannot find 1 available IP" in e.response['text']:
                raise exc.InfobloxCannotAllocateIp(ip_data=ip_object.to_dict())
            else:
                raise e
        except exc.HostRecordNotPresent:
            raise exc.InfobloxHostRecordIpAddrNotCreated(ip=ip_object.ip,
                                                         mac=ip_object.mac)
        except exc.InfobloxInvalidIp:
            raise exc.InfobloxDidNotReturnCreatedIPBack()

    def _create_infoblox_object(self, obj_type, payload,
                                additional_create_kwargs=None,
                                check_if_exists=True,
                                return_fields=None,
                                delegate_member=None,
                                update_if_exists=False):
        if additional_create_kwargs is None:
            additional_create_kwargs = {}

        ib_object = None
        if check_if_exists or update_if_exists:
            ib_object = self._get_infoblox_object_or_none(obj_type, payload)
            if ib_object:
                LOG.info(
                    _("Infoblox %(obj_type)s "
                      "already exists: %(ib_object)s"),
                    {'obj_type': obj_type, 'ib_object': ib_object})

        if not ib_object:
            payload.update(additional_create_kwargs)
            ib_object = self.connector.create_object(obj_type,
                                                     payload,
                                                     return_fields,
                                                     delegate_member)
            LOG.info(
                _("Infoblox %(obj_type)s "
                  "was created: %(ib_object)s"),
                {'obj_type': obj_type, 'ib_object': ib_object})
        elif update_if_exists:
            self._update_infoblox_object_by_ref(ib_object,
                                                additional_create_kwargs)

        return ib_object

    def _get_infoblox_object_or_none(self, obj_type, payload,
                                     return_fields=None, proxy=False):
        # Ignore 'extattrs' for get_object, since this field is not searchible
        search_payload = {}
        for key in payload:
            if key is not 'extattrs':
                search_payload[key] = payload[key]
        ib_object = self.connector.get_object(obj_type, search_payload,
                                              return_fields, proxy=proxy)
        if ib_object:
            if return_fields:
                return ib_object[0]
            else:
                return ib_object[0]['_ref']

        return None

    def _update_infoblox_object(self, obj_type, payload, update_kwargs):
        ib_object_ref = None
        warn_msg = _('Infoblox %(obj_type)s will not be updated because'
                     ' it cannot be found: %(payload)s')
        try:
            ib_object_ref = self._get_infoblox_object_or_none(obj_type,
                                                              payload)
            if not ib_object_ref:
                LOG.warning(warn_msg, {'obj_type': obj_type,
                                       'payload': payload})
        except exc.InfobloxSearchError as e:
            LOG.warning(warn_msg, obj_type, payload)
            LOG.info(e)

        if ib_object_ref:
            self._update_infoblox_object_by_ref(ib_object_ref, update_kwargs)

    def _update_infoblox_object_by_ref(self, ref, update_kwargs,
                                       return_fields=None):
        updated_object = self.connector.update_object(ref, update_kwargs,
                                                      return_fields)
        LOG.info(_('Infoblox object was updated: %s'), ref)
        return updated_object

    def _delete_infoblox_object(self, obj_type, payload):
        ib_object_ref = None
        warn_msg = _('Infoblox %(obj_type)s will not be deleted because'
                     ' it cannot be found: %(payload)s')
        try:
            ib_object_ref = self._get_infoblox_object_or_none(obj_type,
                                                              payload)
            if not ib_object_ref:
                LOG.warning(warn_msg, {'obj_type': obj_type,
                                       'payload': payload})
        except exc.InfobloxSearchError as e:
            LOG.warning(warn_msg, {'obj_type': obj_type,
                                   'payload': payload})
            LOG.info(e)

        if ib_object_ref:
            self.connector.delete_object(ib_object_ref)
            LOG.info(_('Infoblox object was deleted: %s'), ib_object_ref)

    def _update_host_record_ips(self, ipaddrs_name, host_record):
        ipaddrs = {ipaddrs_name: [ip.to_dict(add_host=False)
                                  for ip in host_record.ips]}
        return self._update_infoblox_object_by_ref(
            host_record.ref, ipaddrs, return_fields=[ipaddrs_name])

    @staticmethod
    def _get_object_type_from_ref(ref):
        return ref.split('/', 1)[0]
