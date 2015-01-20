# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2014 OpenStack Foundation.
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

import mock
from mock import patch

from neutron.ipam.drivers.infoblox import ea_manager
from neutron.tests import base


def get_members():
    return [
        {"name": "test_member1.com", "ipv4addr": "10.0.0.100"},
        {"name": "test_member2.com", "ipv4addr": "10.0.0.200",
         'is_public': True},
        {"name": "test_member3.com", "ipv4addr": "10.0.0.220"}
    ]


INFOBLOX_NETWORKS = [
    {
        '_ref': 'network_1_fake_ref',
        'extattrs': {
            'Subnet ID': {'value': 'fake_subnet_id'},
            'Network ID': {'value': 'fake_network_id'}
        },
    },
    {
        '_ref': 'network_2_fake_ref',
        'extattrs': {
            'Subnet ID': {'value': 'fake_subnet_id'},
            'Network ID': {'value': 'fake_network_id'}
        },
    }
]

INFOBLOX_IP_OBJECTS = [
    {
        '_ref': 'host_record_1_fake_ref',
        'extattrs': {'Port ID': {'value': 'fake_port_id'}}
    },
    {
        '_ref': 'host_record_2_fake_ref',
        'extattrs': {'Port ID': {'value': 'fake_port_id'}}}
]


@mock.patch.object(ea_manager, 'InfobloxEaManager', mock.Mock())
@patch('neutron.ipam.drivers.infoblox.connector.Infoblox')
class InfobloxBDHooksTestCase(base.BaseTestCase):
    def setUp(self):
        super(InfobloxBDHooksTestCase, self).setUp()
        # mock configs
        self.query = mock.Mock()

    def test_get_subnets_with_result_filter_hook(self, infoblox_mock):
        # Filters in Neutron look like a dict
        # {
        #   'filter1_name': ['filter1_value'],
        #   'filter2_name': ['filter2_value']
        # }
        # That's why we construct filter dict as following:
        filters = {'infoblox_ea:location': ['USA']}
        conn_mock = infoblox_mock()
        conn_mock.get_object.return_value = INFOBLOX_NETWORKS

        ea_manager.subnet_extattrs_result_filter_hook(self.query, filters)

        conn_mock.get_object.assert_called_with(
            'network',
            return_fields=['extattrs'],
            extattrs={'location': {'value': 'USA'}}
        )
        self.query.filter.assert_called_once()

    def _test_get_ports_extattrs_result_filter_hook(self, infoblox_mock,
                                                    ib_objtype):
        # Filters in Neutron look like a dict
        # {
        #   'filter1_name': ['filter1_value'],
        #   'filter2_name': ['filter2_value']
        # }
        # That's why we construct filter dict as following:
        filters = {'infoblox_ea:Account': ['fake_user_id']}
        conn_mock = infoblox_mock()
        conn_mock.get_object.return_value = INFOBLOX_IP_OBJECTS

        ea_manager.port_extattrs_result_filter_hook(self.query, filters)

        conn_mock.get_object.assert_called_with(
            ib_objtype,
            return_fields=['extattrs'],
            extattrs={'Account': {'value': 'fake_user_id'}}
        )
        self.query.filter.assert_called_once()

    def test_get_ports_extattrs_result_filter_hook_record_host(
            self, conn_mock):
        self.config(use_host_records_for_ip_allocation=True)
        self._test_get_ports_extattrs_result_filter_hook(conn_mock,
                                                         'record:host')

    def test_get_ports_extattrs_result_filter_hook_record_a(self, conn_mock):
        self.config(use_host_records_for_ip_allocation=False)
        self._test_get_ports_extattrs_result_filter_hook(conn_mock, 'record:a')

    def test_get_networks_extattrs_result_filter_hook(self, infoblox_mock):
        # Filters in Neutron look like a dict
        # {
        #   'filter1_name': ['filter1_value'],
        #   'filter2_name': ['filter2_value']
        # }
        # That's why we construct filter dict as following:
        filters = {'infoblox_ea:Account': ['fake_user_id']}
        conn_mock = infoblox_mock()
        conn_mock.get_object.return_value = INFOBLOX_NETWORKS

        ea_manager.network_extattrs_result_filter_hook(self.query, filters)

        conn_mock.get_object.assert_called_with(
            'network',
            return_fields=['extattrs'],
            extattrs={'Account': {'value': 'fake_user_id'}}
        )
        self.query.filter.assert_called_once()

    def test_hook_ignored_for_other_objects(self, infoblox_mock):
        conn_mock = infoblox_mock()
        filters = {'not_infoblox_filter:Account': ['fake_user_id']}

        ea_manager.subnet_extattrs_result_filter_hook(self.query, filters)

        self.assertFalse(conn_mock.get_object.called)
