# Copyright 2014 OpenStack Foundation
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

from neutron.agent.linux import dns_dhcp_proxy

from neutron.common import exceptions as exc
from neutron.agent.common import config
from neutron.tests import base


class DnsDhcpProxyTestCase(base.BaseTestCase):
    def setUp(self):
        super(DnsDhcpProxyTestCase, self).setUp()

    def _get_config(self):
        conf = mock.MagicMock()
        conf.interface_driver = "neutron.agent.linux.interface.NullDriver"
        config.register_interface_driver_opts_helper(conf)
        return conf

    def test_raises_exception_on_unset_config_options(self):
        conf = self._get_config()
        network = mock.Mock()
        self.assertRaises(exc.InvalidConfigurationOption,
                          dns_dhcp_proxy.DnsDhcpProxy, conf, network)

    def test_implements_get_isolated_subnets(self):
        network = mock.Mock()
        conf = self._get_config()
        conf.external_dhcp_servers = ['1.1.1.1']
        conf.external_dns_servers = ['1.1.1.2']

        proxy = dns_dhcp_proxy.DnsDhcpProxy(conf, network)
        try:
            self.assertTrue(callable(proxy.get_isolated_subnets))
        except AttributeError as ex:
            self.fail(ex)

    def test_implements_should_enable_metadata(self):
        network = mock.Mock()
        conf = self._get_config()
        conf.external_dhcp_servers = ['1.1.1.1']
        conf.external_dns_servers = ['1.1.1.2']

        proxy = dns_dhcp_proxy.DnsDhcpProxy(conf, network)

        try:
            self.assertTrue(callable(proxy.should_enable_metadata))
        except AttributeError as ex:
            self.fail(ex)
