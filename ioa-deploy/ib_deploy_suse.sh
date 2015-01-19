# 
# Requires bash 4.0 or greater
#

# Save trace setting
#XTRACE=$(set +o | grep xtrace)
#set -o xtrace


function deploy_suse {
    if [ $ioa_patch_deploy = 'TRUE' ]; then
        deploy_ioa_patch
    elif [ $DEPLOY_SERVICE_IOA = "TRUE" ]; then
        deploy_ioa
    fi
}

function deploy_ioa_patch {
    # detect neutron path
    NEUTRON_PATH=$(python -c 'import neutron; print ",".join(neutron.__path__)')
    PYTHON_SITE_PACKAGE_PATH=$(dirname ${NEUTRON_PATH})
    export NEUTRON_PATH
    export PYTHON_SITE_PACKAGE_PATH

    if [[ -z $NEUTRON_PATH ]]; then
        echo "neutron cannot be not found. OpenStack must be installed before installing IOA."
        exit 1
    fi

    echo "Installing IOA..."
    echo "----------------------------------------------------------------------------------"
    stop_neutron_services

    echo "********************************************************"

    patch_neutron

    echo "********************************************************"

    restart_neutron_services
}

function deploy_ioa {
    # detect neutron path
    NEUTRON_PATH=$(python -c 'import neutron; print ",".join(neutron.__path__)')
    PYTHON_SITE_PACKAGE_PATH=$(dirname ${NEUTRON_PATH})
    export NEUTRON_PATH
    export PYTHON_SITE_PACKAGE_PATH
    
    if [[ -z $NEUTRON_PATH ]]; then
        echo "neutron cannot be not found. OpenStack must be installed before installing IOA."
        exit 1
    fi
    
    # this is needed in case when openstack is manually installed without using this installer.
    # IOA requires the packages
    echo "Installing packages..."
    if [[ -n $IOA_SKIP_PACKAGE_INSTALL && $IOA_SKIP_PACKAGE_INSTALL = "true" ]]; then
        echo_indented "Skipping package install..."
    else
        install_suse_packages
    fi

    echo "Installing dhcp relay..."
    if [[ -n $IOA_SKIP_RELAY && $IOA_SKIP_RELAY = "true" ]]; then
        echo_indented "Skipping dhcp relay..."
    else
        if ! install_dhcp_relay; then
            echo "Failed to install dhcp relay"
            exit 1
        fi
    fi
    
    echo "Disabling ipv6..."
    if [[ -n $IOA_SKIP_IPV6_DISABLING && $IOA_SKIP_IPV6_DISABLING = "true" ]]; then
        echo_indented "Skipping IPv6 disabling..."
    else
        disable_ipv6
    fi
    
    echo "Installing IOA..."
    if ! install_ioa; then
        echo "Failed to install IOA"
        exit 1
    fi
}

function configure_hostname {
    # update hostname
    if [[ -n $HOST_NAME && ${#HOST_NAME} -gt 0 ]]; then
        hostname=`$SUDO cat /etc/sysconfig/network | grep HOSTNAME | tr -d ' '`
        # no HOSTNAME defined
        if [ ${#hostname} -eq 0 ]; then
            cat << EOF | $SUDO tee -a /etc/sysconfig/network
HOSTNAME=$HOST_NAME
EOF
            echo_indented "hostname '$HOST_NAME' has been added"
        # HOSTNAME is defined and already the correct name exists
        elif [[ $hostname =~ HOSTNAME=$HOST_NAME ]]; then
            echo_indented "No hostname change is needed"
        # HOSTNAME defined but different name found
        else            
            $SUDO sed -i -e "s/HOSTNAME=.*/HOSTNAME=$HOST_NAME/g" /etc/sysconfig/network
            echo_indented "hostname '$HOST_NAME' has been replaced"
        fi
    else
        echo_indented "No hostname update is requested"
    fi
    
    # update hosts
    hostname=$(hostname)
    if [[ -n $hostname && ${#hostname} -gt 0 ]]; then
        hosts_hostname=`$SUDO cat /etc/hosts | grep $hostname`
        if [ ${#hosts_hostname} -eq 0 ]; then
            cat << EOF | $SUDO tee -a /etc/hosts
127.0.0.1   $(hostname)
EOF
            echo_indented "hostname '$hostname' has been added"
        else
            echo_indented "hostname is up-to-date"
        fi
    else
        echo_indented "hostname is not defined"
    fi
}

function disable_ipv6 {
    _disable_ipv6_network_conf
    _disable_ipv6_modprobe_conf
    _disable_ipv6_sysctl_conf
    _disable_ipv6_hosts_conf
}

function _disable_ipv6_network_conf {
    is_updated='FALSE'
    
    ipv6=`$SUDO cat /etc/sysconfig/network | grep NETWORKING_IPV6 | tr -d ' '`
    if [ ${#ipv6} -gt 0 ]; then
        if [[ $ipv6 =~ NETWORKING_IPV6=(yes|YES|Yes) ]]; then
            $SUDO sed -i -e "s/NETWORKING_IPV6=.*/NETWORKING_IPV6=no/g" /etc/sysconfig/network
            is_updated='TRUE'
        fi
    else
        cat << EOF | $SUDO tee -a /etc/sysconfig/network
NETWORKING_IPV6=no
EOF
        is_updated='TRUE'
    fi
    
    if [ $is_updated = 'TRUE' ]; then
        echo_indented "/etc/sysconfig/network is disabled"
    else
        echo_indented "/etc/sysconfig/network is already disabled"
    fi
}

function _disable_ipv6_modprobe_conf {
    is_updated='FALSE'
    is_file_found='FALSE'
    
    if [ -e "/etc/modprobe.d/ipv6.conf" ]; then
        is_file_found='TRUE'
        ipv6=`$SUDO cat /etc/modprobe.d/ipv6.conf | grep 'options ipv6 disable=1' | wc -l`
        if [ $ipv6 -gt 0 ]; then
            is_updated='TRUE'
        fi
    fi
    
    if [ $is_updated = 'TRUE' ]; then
        echo_indented "/etc/modprobe.d/ipv6.conf is disabled"
    else
        if [ $is_file_found = 'TRUE' ]; then
            $SUDO sed -i '1,$ d' /etc/modprobe.d/ipv6.conf
        fi
    
        cat << EOF | $SUDO tee -a /etc/modprobe.d/ipv6.conf
options ipv6 disable=1
EOF
        echo_indented "/etc/modprobe.d/ipv6.conf is already disabled"
    fi
}

function _disable_ipv6_sysctl_conf {
    ipv6=`$SUDO cat /etc/sysctl.conf | grep 'net.ipv6.conf.all.disable_ipv6 = 1' | wc -c`
    if [ $ipv6 -gt 0 ]; then
        echo_indented "/etc/sysctl.conf is already disabled"
    else
        cat << EOF | $SUDO tee -a /etc/sysctl.conf

# IPv6 support in the kernel, set to 0 by default
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
        echo_indented "/etc/sysctl.conf is disabled"
    fi
}

function _disable_ipv6_hosts_conf {
    ipv6=`$SUDO cat /etc/hosts | grep '^[[:space:]]*::' | wc -l`
    if [ $ipv6 -eq 0 ]; then
        echo_indented "/etc/hosts is already disabled"
    else
        $SUDO cp -p /etc/hosts /etc/hosts.disableipv6
        $SUDO sed -i 's/^[[:space:]]*::/#::/' /etc/hosts
        echo_indented "/etc/hosts is disabled"
    fi
}

function uninstall_packages {
    if [[ -z "$PACKAGES" ]]; then
        echo_indented "PACKAGES parameter is not specified"
        return 1
    fi
    
    _uninstall_package $PACKAGES
}

function install_ioa {
    echo "----------------------------------------------------------------------------------"
    stop_neutron_services
    
    echo "********************************************************"
    
    configure_neutron_ioa
    patch_neutron
    configure_network_for_ioa
    customize_db_upgrade
    
    echo "********************************************************"
    
    restart_neutron_services
    echo "----------------------------------------------------------------------------------"
}

function configure_neutron_ioa {
    require_relay='true'
    if [[ -n $IOA_SKIP_RELAY && $IOA_SKIP_RELAY = "true" ]]; then
        require_relay='false'
    fi
    
    echo_indented "Updating neutron config..."
    #--------------------------------------------------------------------------------------------------------
    run_crudini $NEUTRON_CONF DEFAULT ipam_driver neutron.ipam.drivers.infoblox.infoblox_ipam.InfobloxIPAM
    run_crudini $NEUTRON_CONF DEFAULT infoblox_members_config /etc/neutron/infoblox_members.conf
    run_crudini $NEUTRON_CONF DEFAULT conditional_config /etc/neutron/infoblox_conditional.conf
    # used to choose between host records or fixed address objects, by default it is set to True, so if you skip this option, 
    # neutron adapter will use host record objects. If you’re testing creation of fixed address objects, 
    # you’d need to set this option explicitly to False.
    run_crudini $NEUTRON_CONF DEFAULT use_host_records_for_ip_allocation $IB_DHCP_USE_HOST_RECORD_FOR_IP_ALLOC
    run_crudini $NEUTRON_CONF DEFAULT bind_dns_records_to_fixed_address $IB_BIND_DNS_RECORDS_TO_FIXED_ADDRESS
    run_crudini $NEUTRON_CONF DEFAULT unbind_dns_records_from_fixed_address $IB_UNBIND_DNS_RECORDS_FROM_FIXED_ADDRESS
    run_crudini $NEUTRON_CONF DEFAULT delete_dns_records_associated_with_fixed_address $IB_DELETE_DNS_RECORDS_ASSOCIATED_WITH_FIXED_ADDRESS

    run_crudini $NEUTRON_CONF DEFAULT debug True
    run_crudini $NEUTRON_CONF DEFAULT verbose True
    run_crudini $NEUTRON_CONF DEFAULT notification_driver neutron.openstack.common.notifier.rpc_notifier
    run_crudini $NEUTRON_CONF DEFAULT infoblox_wapi $WAPI
    run_crudini $NEUTRON_CONF DEFAULT infoblox_username $IB_USERNAME
    run_crudini $NEUTRON_CONF DEFAULT infoblox_password $IB_PASSWORD
    
    #echo_indented "Updating ML2 plugin config..."
    #--------------------------------------------------------------------------------------------------------
    
    echo_indented "Updating dhcp agent config..."
    #--------------------------------------------------------------------------------------------------------
    if [ $require_relay = "true" ]; then
        run_crudini $DHCP_AGENT_CONF DEFAULT dhcp_driver neutron.agent.linux.dhcp_relay.DhcpDnsProxy
        run_crudini $DHCP_AGENT_CONF DEFAULT dhcp_agent_manager neutron.agent.dhcp_agent.DhcpAgentWithStateReport
        run_crudini $DHCP_AGENT_CONF DEFAULT dhcp_confs $DHCP_CONFS
        run_crudini $DHCP_AGENT_CONF DEFAULT interface_dev_name_len 9
        run_crudini $DHCP_AGENT_CONF DEFAULT dhcp_relay_bridge $IOA_BRIDGE
        run_crudini $DHCP_AGENT_CONF DEFAULT dhclient_path $DHCP_RELAY_BIN_PATH/dhclient
        run_crudini $DHCP_AGENT_CONF DEFAULT dhcrelay_path $DHCP_RELAY_BIN_PATH/dhcrelay
        run_crudini $DHCP_AGENT_CONF DEFAULT debug True

        run_crudini $NEUTRON_CONF DEFAULT dhcp_relay_management_network $IOA_DHCP_RELAY_MANAGEMENT_NETWORK
        run_crudini $NEUTRON_CONF DEFAULT dhcp_relay_management_network_view $IOA_DHCP_RELAY_MANAGEMENT_NETWORK_VIEW
    else
        echo_indented "Skipping.." 6
    fi
    
    echo_indented "Updating L3 agent config..."
    #--------------------------------------------------------------------------------------------------------
    if [ $require_relay = "true" ]; then
        run_crudini $L3_AGENT_CONF DEFAULT l3_agent_manager neutron.agent.l3_agent.L3NATAgentWithStateReport
        run_crudini $L3_AGENT_CONF DEFAULT external_network_bridge br-ex
        run_crudini $L3_AGENT_CONF DEFAULT interface_driver neutron.agent.linux.interface.OVSInterfaceDriver
        # for value with space(s) cannot use run_crudini
        $SUDO crudini --set $L3_AGENT_CONF DEFAULT root_helper 'sudo neutron-rootwrap /etc/neutron/rootwrap.conf'
        run_crudini $L3_AGENT_CONF DEFAULT ovs_use_veth False
        run_crudini $L3_AGENT_CONF DEFAULT use_namespaces True
        run_crudini $L3_AGENT_CONF DEFAULT debug True
        run_crudini $L3_AGENT_CONF DEFAULT verbose True
    else
        echo_indented "Skipping.." 6
    fi
    
    echo_indented "Creating infoblox conditional config..."
    if [ -e "/etc/neutron/infoblox_conditional.conf" ]; then
        $SUDO sed -i '1,$ d' /etc/neutron/infoblox_conditional.conf
    fi
    
    cat << EOF | $SUDO tee -a /etc/neutron/infoblox_conditional.conf
[
    {
        "condition": "tenant",
        "is_external": false,
        "network_view": "$IB_PRIVATE_NETWORK_VIEW",
        "dhcp_members": "<next-available-member>",
        "require_dhcp_relay": $require_relay,
        "domain_suffix_pattern": "{subnet_name}.$IB_FQDN_SUFFIX",
        "hostname_pattern": "host-{ip_address}"
    },
    {
        "condition": "global",
        "is_external": true,
        "network_view": "$IB_EXTERNAL_NETWORK_VIEW",
        "dhcp_members": "<next-available-member>",
        "require_dhcp_relay": $require_relay,
        "domain_suffix_pattern": "{subnet_name}.cloud.global.com",
        "hostname_pattern": "host-{ip_address}"
    }
]
EOF

    echo_indented "Creating infoblox members config..."
    if [ -e "/etc/neutron/infoblox_members.conf" ]; then
        $SUDO sed -i '1,$ d' /etc/neutron/infoblox_members.conf
    fi
    cat << EOF | $SUDO tee -a /etc/neutron/infoblox_members.conf
$IB_MEMBERS
EOF
    $SUDO chown root:neutron /etc/neutron/infoblox_members.conf
    
    echo_indented "Creating dhcp.filters..."
    if [ $require_relay = "true" ]; then
        #/usr/share/neutron/rootwrap/dhcp.filters
        if [ -e "$DHCP_FILTERS_CONF" ]; then
            $SUDO sed -i '1,$ d' $DHCP_FILTERS_CONF
        fi
        cat << EOF | $SUDO tee -a $DHCP_FILTERS_CONF
# neutron-rootwrap command filters for nodes on which neutron is
# expected to control network
#
# This file should be owned by (and only-writeable by) the root user

# format seems to be
# cmd-name: filter-name, raw-command, user, args

[Filters]

# dhcp-agent
dnsmasq: EnvFilter, dnsmasq, root, NEUTRON_NETWORK_ID=

# dhcp-agent uses kill as well, that's handled by the generic KillFilter
# it looks like these are the only signals needed, per
# neutron/agent/linux/dhcp.py
kill_dnsmasq: KillFilter, root, /sbin/dnsmasq, -9, -HUP
kill_dnsmasq_usr: KillFilter, root, /usr/sbin/dnsmasq, -9, -HUP

ovs-vsctl: CommandFilter, ovs-vsctl, root
ivs-ctl: CommandFilter, ivs-ctl, root
mm-ctl: CommandFilter, mm-ctl, root
dhcp_release: CommandFilter, dhcp_release, root

# DHCP relay specific options
dhcrelay: CommandFilter, /usr/local/dhcp-4.3.0/sbin/dhcrelay, root
dhclient: CommandFilter, /usr/local/dhcp-4.3.0/sbin/dhclient, root
dnsmasq: CommandFilter, dnsmasq, root
kill_dhcrelay: KillFilter, root, /usr/local/dhcp-4.3.0/sbin/dhcrelay, -9
kill_dhclient: KillFilter, root, /usr/local/dhcp-4.3.0/sbin/dhclient, -9

# metadata proxy
metadata_proxy: CommandFilter, neutron-ns-metadata-proxy, root
metadata_proxy_quantum: CommandFilter, quantum-ns-metadata-proxy, root
# If installed from source (say, by devstack), the prefix will be
# /usr/local instead of /usr/bin.
metadata_proxy_local: CommandFilter, /usr/local/bin/neutron-ns-metadata-proxy, root
metadata_proxy_local_quantum: CommandFilter, /usr/local/bin/quantum-ns-metadata-proxy, root
# RHEL invocation of the metadata proxy will report /usr/bin/python
kill_metadata: KillFilter, root, /usr/bin/python, -9
kill_metadata7: KillFilter, root, /usr/bin/python2.7, -9
kill_metadata6: KillFilter, root, /usr/bin/python2.6, -9

# ip_lib
ip: IpFilter, ip, root
ip_exec: IpNetnsExecFilter, ip, root
EOF
    else
        echo_indented "Skipping.." 6
    fi
}

function configure_network_for_ioa {
    echo_indented "Configuring network..."
    if [[ -n $IOA_SKIP_NETWORK_CONFIGURATION && $IOA_SKIP_NETWORK_CONFIGURATION = "true" ]]; then
        echo_indented "Skipping.." 6
        return 0
    fi
    
    configure_network_interfaces
    
    # check if IOA_BRIDGE already exists
    cmd=`$SUDO ovs-vsctl list-br | grep $IOA_BRIDGE | wc -c`
    if [ $cmd -eq 0 ]; then
        $SUDO ovs-vsctl add-br $IOA_BRIDGE
    fi
    
    # check if port IOA_INTERFACE is added to IOA_BRIDGE
    cmd=`ovs-ofctl show $IOA_BRIDGE | grep $IOA_INTERFACE | wc -l`
    if [ $cmd -eq 0 ]; then
        $SUDO ifconfig $IOA_BRIDGE up
        $SUDO ovs-vsctl add-port $IOA_BRIDGE $IOA_INTERFACE && \
        $SUDO ip addr del $IOA_HOST_IP/24 dev $IOA_INTERFACE && \
        $SUDO ip addr add $IOA_HOST_IP/24 dev $IOA_BRIDGE && \
        $SUDO ip route add default via $IOA_HOST_GATEWAY
        $SUDO ifconfig $IOA_INTERFACE 0.0.0.0

        $SUDO service network restart
   fi
}

function configure_network_interfaces {
    if [[ -e "/etc/sysconfig/network/ifcfg-$IOA_INTERFACE" &&
          -e "/etc/sysconfig/network/ifcfg-$IOA_BRIDGE"    ]]; then
        cmd1=`$SUDO cat /etc/sysconfig/network/ifcfg-$IOA_INTERFACE | grep OVS_BRIDGE=$IOA_BRIDGE | wc -c`
        cmd2=`$SUDO cat /etc/sysconfig/network/ifcfg-$IOA_BRIDGE | grep IPADDR=${IOA_HOST_IP} | wc -c`
        if [[ $cmd1 -gt 0 && $cmd2 -gt 0 ]]; then
            echo_indented "No need to update network interfaces"
            return 0
        fi
    fi

    echo_indented "Creating $IOA_BRIDGE and adding port $IOA_INTERFACE..."
    if [ -e "/etc/sysconfig/network/ifcfg-$IOA_INTERFACE" ]; then
        $SUDO sed -i '1,$ d' /etc/sysconfig/network/ifcfg-$IOA_INTERFACE
    fi
    if [ -e "/etc/sysconfig/network/ifcfg-$IOA_BRIDGE" ]; then
        $SUDO sed -i '1,$ d' /etc/sysconfig/network/ifcfg-$IOA_BRIDGE
    fi
    
    cat << EOF | $SUDO tee -a /etc/sysconfig/network/ifcfg-$IOA_INTERFACE
NAME='$IOA_INTERFACE'
STARTMODE='auto'
BOOTPROTO='static'
OVS_BRIDGE='$IOA_BRIDGE'
USERCONTROL='no'
EOF

    cat << EOF | $SUDO tee -a /etc/sysconfig/network/ifcfg-$IOA_BRIDGE
NAME='$IOA_BRIDGE'
BRIDGE=yes
BRIDGE_PORTS='$IOA_INTERFACE'
BOOTPROTO='static'
IPADDR=${IOA_HOST_IP}
NETMASK=$IOA_HOST_NETMASK
STARTMODE='onboot'
USERCONTROL='no'
EOF

    if [ -n "$IOA_HOST_GATEWAY" ]; then
        cat << EOF | $SUDO tee -a /etc/sysconfig/network/ifroute-$IOA_BRIDGE
default $IOA_HOST_GATEWAY
EOF
    fi

    return 0
}

function patch_neutron {
    # neutron.tar.gz is no longer included.
    # -------------------------------------------------------------------------------
    #if ! [ -e "$IB_NEUTRON_PATCH_PATH/$IB_NEUTRON_TARBALL" ]; then
    #    echo_indented "$IB_NEUTRON_PATCH_PATH/$IB_NEUTRON_TARBALL cannot be found."
    #    return 1
    #fi
    
    #echo_indented "Extracting $IB_NEUTRON_PATCH_PATH/$IB_NEUTRON_TARBALL..."
    #cd ${IB_NEUTRON_PATCH_PATH}
    #tar -zxf $IB_NEUTRON_TARBALL > /dev/null 2>&1
    #if ! [ -e "./neutron/requirements.txt" ]; then
    #    echo_indented "./neutron/requirements.txt cannot be found."
    #    return 1
    #fi
    
    echo_indented "Patching IOA neutron core sources..."
    cd $IB_NEUTRON_PATCH_PATH/neutron
    patch_neutron_sources
    
    echo_indented "Applying patches for Openstack stability..."
    if [ "$REQUIRE_FIX_PATCH" = "TRUE" ]; then
        run_patches
    else
        echo_indented "None..." 6
    fi
    
    echo_indented "Updating neutron db..."
    if [[ -n $IOA_SKIP_NEUTRON_DB_UPDATE && $IOA_SKIP_NEUTRON_DB_UPDATE = "true" ]]; then
        echo_indented "Skipped..." 6
    else
        $SUDO neutron-db-manage --config-file=/etc/neutron/neutron.conf --config-file=$NEUTRON_PLUGIN_INI upgrade head
    fi
}

function patch_neutron_sources {
    echo_indented "neutron path found: $NEUTRON_PATH"
    
    # backup existing version
    archive_path="$PYTHON_SITE_PACKAGE_PATH/neutron.$(date +%d%m%y-%H%M%S)"
    echo_indented "Archiving the existing neutron to $archive_path from $PYTHON_SITE_PACKAGE_PATH/neutron..."
    $SUDO cp -rf $PYTHON_SITE_PACKAGE_PATH/neutron $archive_path
    
    _patch_unique_files
    _patch_modified_files
    _clean_leftover_files
    _restore_ownership
}

function _patch_unique_files {
    for i in `find neutron -type d`
    do
        if ! test -d $PYTHON_SITE_PACKAGE_PATH/$i  
        then
            echo_indented "$SUDO mkdir $PYTHON_SITE_PACKAGE_PATH/$i"
            $SUDO mkdir $PYTHON_SITE_PACKAGE_PATH/$i
        fi
    done

    for i in `find neutron -type f`
    do
        if ! test -f $PYTHON_SITE_PACKAGE_PATH/$i  
        then
            echo_indented "NEW >>> $SUDO cp $i $PYTHON_SITE_PACKAGE_PATH/$i"
            $SUDO cp $i $PYTHON_SITE_PACKAGE_PATH/$i
        fi
    done
}

function _patch_modified_files {
    for i in `find neutron -type f \! -name '*.pyc' \! -name '*.pyo'`
    do
        if ! cmp -s $i $PYTHON_SITE_PACKAGE_PATH/$i  
        then
            echo_indented "UPD >>> $SUDO cp $i $PYTHON_SITE_PACKAGE_PATH/$i"
            $SUDO cp $i $PYTHON_SITE_PACKAGE_PATH/$i
        fi
    done
}

function _clean_leftover_files {
    echo_indented "DEL >>> $SUDO find $PYTHON_SITE_PACKAGE_PATH/neutron -name \"*.py[co]\" -delete"
    $SUDO find $PYTHON_SITE_PACKAGE_PATH/neutron -name "*.py[co]" -delete
}

function _restore_ownership {
    echo_indented "OWNER >>> $SUDO chown -R neutron.neutron $PYTHON_SITE_PACKAGE_PATH/neutron"
    $SUDO chown -R neutron.neutron $PYTHON_SITE_PACKAGE_PATH/neutron
}

function customize_db_upgrade {
    echo_indented "Customizing IOA db upgrade..."
    if [[ -n $IOA_NUAGE_DB_MIGRATION_SUPPORT && $IOA_NUAGE_DB_MIGRATION_SUPPORT = "true" ]]; then
        echo_indented "Nuage neutron db update..." 6
        if _install_ioa_db_for_nuage ; then
            echo_indented "Done..." 12
        else
            echo_indented "Failed...Check ib_db_upgrade_nuage.sql and you can try to run it manually" 12
        fi
        return 0
    fi

    # implement other db upgrade if needed here...
    # ....
}

function _install_ioa_db_for_nuage {
    $SUDO mysql < $IB_NEUTRON_PATCH_PATH/ib_db_upgrade_nuage.sql
    return $?
}

function install_suse_packages {
    if [[ -z "$PACKAGES" ]]; then
        echo_indented "PACKAGES parameter is not specified"
        return 1
    fi

    echo_indented "Installing required packages ..."
    for i in $PACKAGES
    do
        $SUDO zypper install -y $i
    done

    echo_indented "Done!"
    return 0
}

###################################################################################################
#   Deprecated (Havana supported)
###################################################################################################

function run_crudini {
    conf_file=$1
    conf_section=$2
    conf_key=$3
    conf_val=$4

    cmd=`$SUDO grep '$conf_key = $conf_val' $conf_file | wc -c`
    if [ $cmd -eq 0 ]; then
        echo_indented "crudini --set $conf_file $conf_section $conf_key $conf_val"
        $SUDO crudini --set $conf_file $conf_section $conf_key $conf_val
    fi
}

# Restore xtrace
#$XTRACE
