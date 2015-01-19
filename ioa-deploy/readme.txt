Infoblox OpenStack Adapter (IOA) POC 1.0.1 for Icehouse 

Date:       9/32/2014
Createor:   Infoblox

---------------------------------------------------------------------------------
Introduction
---------------------------------------------------------------------------------

IOA POC is created to demonstrate the ability to plug in IPAM solution to 
OpenStack Neutron to provide DHCP and DNS services by Infoblox NIOS appliances.

---------------------------------------------------------------------------------
System Requirements
---------------------------------------------------------------------------------

OS      : Currently IOA has been tested with RedHat 6.5, Centos 6.5, Ubuntu 14.04
RAM     : Recommended 6 GB or more although less will work but will notice 
          slowness with OpenStack

---------------------------------------------------------------------------------
Known Issues and Limitations
---------------------------------------------------------------------------------

Note the following known issues and limitations for Infoblox OpenStack 
Adapter POC:

   * You cannot add public/shared network from OpenStack if the network already 
     exists on NIOS.
   
   * This POC is not IPv6 compatible.
     
   * POC is designed and tested for the server with a single IP address, so we 
     recommend that you use "br-ex" bridge for the DHCP/DNS relay to our Infoblox
     NIOS server because PackStack creates the bridge automatically for you. 
     Although you can have multiple NIC cards and each have its own IP address
     (For example, one IP for management, another IP for external communication), 
     you will need to use "br-ex" for DHCP/DNS relay and the external 
     communication to test floating IPs. Although different setup can be 
     exercised, we encourage you to test POC with a single IP first so that you
     can use that single IP for "br-ex", the external bridge. Then, "br-ex" 
     bridge is the single source of your management traffic, floating IP mapping 
     for external communication, and DHCP/DNS relay to the Infoblox NIOS server.
     Binding the network interface to "br_ex" is done by the Infoblox 
     OpenStack Adapter POC installation.

   * While working on this POC, we discovered three blocking issues in the 
     OpenSource neutron codebase. Those are known issues in the community.
     Though code for fixes have been proposed, none has been formally accepted.
     For this POC we made the following fixes suggested by the community.
     
    — Openvswitch version check issue with some of linux distro like CentOS, RHEL:
    
        The following URL links to details about the bug filed by the OpenStack
        community:
        
        https://ask.openstack.org/en/question/30100/neutron-vxlan-not-working-with-rdo-icehouse-and-centos-65/
        
        The issue is that Openstack uses the modinfo command to find out the 
        openvswitch version, which does not show any version information.
        
        This is currently how the OS figures out openvswitch version and it 
        does not show the version.
        
            [hhwang@hhwang-10324102 ~]$ modinfo openvswitch
            filename:
            /lib/modules/2.6.32-431.el6.x86_64/kernel/net/openvswitch/openvswitch.ko
            license: GPL
            description: Open vSwitch switching datapath
            srcversion: 993363C44DF474BD67B03CC
            depends: vxlan
            vermagic: 2.6.32-431.el6.x86_64 SMP mod_unload modversions
            
        But the following works:
            
            [hhwang@hhwang-10324102 ~]$ ovs-vswitchd --version
            ovs-vswitchd (Open vSwitch) 2.0.1
            Compiled Apr 16 2014 13:21:41
            18 Infoblox Quick Start Guide (Rev. A) OpenStack Adapter POC 1
            OpenFlow versions 0x1:0x1
        
        So the fix would be to use “ovs-vswitchd –version”.
        
        The fix we made is the same as information shown using the following:
        
        https://review.openstack.org/#/c/98615/2/neutron/agent/linux/ovs_lib.py
        
    — IPv6 issue with IptableFirewallDrive:
    
        By default, PackStack installation enables IptablesFirewallDriver, and 
        IptablesFirewallDriver uses IPv6 iptables as a default even though IPv6
        is not fully supported in Icehouse.
        
        For our POC, we disabled IPv6 and this conflicts with the way 
        IptablesFirewallDriver uses IPv6 iptables.
        Take a look at how this class is constructed, and you will notice that
        use_ipv6=True is used as the default.
        We cannot overwrite use_ipv6 parameter currently because it does not 
        get this value from the configuration files.
        This is a faulty implementation in OpenStack.
        
        From neutron/agent/linux/iptables_firewall.py:
        
        class IptablesFirewallDriver(firewall.FirewallDriver):
            """Driver which enforces security groups through iptables rules."""
            IPTABLES_DIRECTION = {INGRESS_DIRECTION: 'physdev-out',
                                  EGRESS_DIRECTION: 'physdev-in'}
                                  
            def __init__(self):
                self.iptables = iptables_manager.IptablesManager(
                    root_helper=cfg.CONF.AGENT.root_helper,
                    use_ipv6=True)
        
                # list of port which has security group
                self.filtered_ports = {}
                self._add_fallback_chain_v4v6()
                self._defer_apply = False
                self._pre_defer_filtered_ports = None
                
        THe following links show where the bug wsa filed:
           - https://bugs.launchpad.net/neutron/+bug/1203611        
           - https://review.openstack.org/#/c/38098/2/neutron/agent/linux/iptables_firewall.py

        For this POC, we changed this parameter’s default value to False: 
            "use_ipv6=False".

    - Unicode Issue with str():
    
        taskflow library throws Unicode exception when str() is called.
        The error message looks like the following:
        
        "UnicodeError: Message objects do not support str() because they may contain 
         non-ascii characters. Please use unicode() or translate() instead."
        
        In order to address this issue, we created a patch to resolve the issue using six library.
        Refer to ib_patch_taskflow.diff in the POC package for details.

        
        
