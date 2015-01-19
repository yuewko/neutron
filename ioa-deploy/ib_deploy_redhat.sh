# 
# Requires bash 4.0 or greater
#

declare -A STACK_RELEASE_REDHAT=( [havana]="4.0" [icehouse]="5.0" [juno]="6.0" )

# Save trace setting
#XTRACE=$(set +o | grep xtrace)
#set -o xtrace

function deploy_redhat {
    if ! check_redhat_supportability; then
        echo "'$os_RELEASE' not supported version. Please consult to Infoblox."
        exit 1
    fi
    
    if [ $DEPLOY_SERVICE_STACK = "TRUE" ]; then
        deploy_stack
    fi

    if [ $DEPLOY_SERVICE_IOA = "TRUE" ]; then
        deploy_ioa
    fi
}

function deploy_stack {
    echo "Handling RedHat registration..."
    if ! handle_redhat_subscription ; then
        echo "Red Hat subscription registration is not complete. Please register subscription and run 'deploy.sh' again."
        exit 1
    fi

    echo "Preparing repos..."
    if ! prepare_redhat_repo; then
        echo "Failed to enable OpenStack channel and disable CloudForms and Virtualization Channels."
        echo "Check if a valid openstack release name is specified and subscription is valid"
        exit 1
    fi
    
    echo "Disabling Network Manager and SELINUX..."
    disable_network_manager;  disable_selinux

    echo "Configuring hostname..."
    configure_hostname
    
    echo "Disabling ipv6..."
    disable_ipv6
    
    echo "Installing packages..."
    install_packages

    if [ ${os_RELEASE::1} -eq 7 ]; then
        add_ioa_neutron_sudoer
    fi

    echo "Installing packstack..."
    install_packstack
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
    
    # this is needed in case when openstack is manually installed without using this installer.
    # IOA requires the packages
    echo "Installing packages..."
    if [[ -n $IOA_SKIP_PACKAGE_INSTALL && $IOA_SKIP_PACKAGE_INSTALL = "true" ]]; then
        echo_indented "Skipping package install..."
    else
        install_packages
    fi

    echo "Installing IOA..."
    if ! install_ioa; then
        echo "Failed to install IOA"
        exit 1
    fi
}

function check_redhat_supportability {
    if [[ $os_RELEASE =~ (6\.[5-9]|7\.[0-9]) ]]; then
        return 0
    else
        return 1
    fi
}

function handle_redhat_subscription {
    if [[ -n $SKIP_SUBSCRIPTION_CHECK && $SKIP_SUBSCRIPTION_CHECK = "true" ]]; then
        echo_indented "Skipping subscription check..."
        return 0
    fi

    if is_redhat_subscription_valid ; then
        echo_indented "Already registered..."
        return 0
    else
        echo "----------------------------------------------------------------------------------"
        echo "Registering subscription..."
        if has_custom_config && [[ -n $RH_USER && -n $RH_PASSWORD ]] ; then
            register_redhat_subscription $RH_USER $RH_PASSWORD
        else
            register_redhat_subscription_by_user
        fi
        echo "----------------------------------------------------------------------------------"
        is_redhat_subscription_valid
        return $?
    fi
}

# get subscription status for REDHAT distro
# subscription status can be {Valid, Subscribed, Sufficient,
#    Insufficient, Partially Subscribed, Invalid, Not Subscribed, Expired}
# but using 'subscription-manager status' gives Current, Unknown,
#    and possible other vaues.
# So we need to just check if 'Current' or not
# --------------------------------------------------------------------
function is_redhat_subscription_valid {
    status=$($SUDO subscription-manager status | grep Current)
    if [ ${#status} -eq 0 ] ; then
        return 1
    else
        return 0
    fi
}

function register_redhat_subscription_by_user {
    read -p "Enter Redhat subscripton username: " subscr_user
    read -p "Enter Redhat subscripton password: " subscr_pwd
    register_redhat_subscription $subscr_user $subscr_pwd
}

function register_redhat_subscription {
    subscr_user=$1
    subscr_pwd=$2
    
    cmd1=`$SUDO subscription-manager register --username=$subscr_user --password=$subscr_pwd`
    exitcode=$?
    echo "$cmd1"
    if [ $exitcode -ne 0 ]; then
        echo_indented "Unregister and try again..."
        $SUDO subscription-manager unregister
        $SUDO subscription-manager clean
        cmd1=`$SUDO subscription-manager register --username=$subscr_user --password=$subscr_pwd`
        exitcode=$?
        echo "$cmd1"
    fi
    
    if [ $exitcode -eq 0 ]; then
        # "subscription-manager subscribe --auto >/dev/stderr" => /dev/stderr has permission error when used with sudo
        cmd2=`$SUDO subscription-manager subscribe --auto` 
        echo "$cmd2"
    fi
}

function get_redhack_verson_for_openstack_release {
    if [[ -z $STACK_RELEASE ]]; then
        get_openstack_release
    fi
    echo ${STACK_RELEASE_REDHAT[$STACK_RELEASE]}
}

# subscription-manager repos --list; displays repos (Repo ID, Repo Name, Repo URL, Enabled)
# subscription-manager list --installed;
# yum repolist disabled | grep rhel-6-server-cf-*
# yum repolist enabled | grep rhel-6-server-cf-*
function prepare_redhat_repo {
    packstack_ver=$(get_redhack_verson_for_openstack_release)
    if [[ -z $packstack_ver ]]; then
        return 1
    fi
    
    if [[ -n $SKIP_REPOS_UPDATE && $SKIP_REPOS_UPDATE = "true" ]]; then
        echo_indented "Skipping repos update..."
        return 0
    fi
    
    export RH_OPENSTACK_VERSION=$packstack_ver
    # for RH 6.5, server version for repo channel is '6', for RH 7.0, '7'
    if [[ $os_RELEASE =~ 6\.[5-9] ]]; then
        export RH_SERVER_CHANNEL_VERSION='6'
    elif [[ $os_RELEASE =~ 7\.[0-9] ]]; then
        export RH_SERVER_CHANNEL_VERSION='7'
    fi
    
    echo "----------------------------------------------------------------------------------"
    # yum clean all && yum clean metadata && yum clean dbcache && yum makecache
    #echo "Cleanup and refresh ac yum-utils..."
    #$SUDO yum clean all && $SUDO yum clean metadata && $SUDO yum clean dbcache && $SUDO yum makecache
    
    enable_redhat_repositories_2
    
    echo "Installing yum-utils..."
    $SUDO yum install -y yum-utils
    
    # Probably not necessary to run the following
    # yum install -y yum-plugin-priorities returns "No package yum-priorities available" 
    # ----------------------------------------------------------------------------------
    #$SUDO yum install -y yum-plugin-priorities yum-utils
    #$SUDO yum-config-manager --setopt= "rhel-$RH_SERVER_CHANNEL_VERSION-server-openstack-$RH_OPENSTACK_VERSION-rpms.priority=1" \
    #    --enable rhel-$RH_SERVER_CHANNEL_VERSION-server-openstack-$RH_OPENSTACK_VERSION-rpms
    
    echo "Updating yum..."
    $SUDO yum update -y
    echo "----------------------------------------------------------------------------------"
    return 0
}

function enable_redhat_repositories_1 {
    # required channels
    # --------------------------------------------------------------------------------------------------------
    $SUDO subscription-manager repos --enable=rhel-$RH_SERVER_CHANNEL_VERSION-server-openstack-$RH_OPENSTACK_VERSION-rpms
    $SUDO subscription-manager repos --enable=rhel-$RH_SERVER_CHANNEL_VERSION-server-openstack-foreman-rpms
    $SUDO subscription-manager repos --enable=rhel-$RH_SERVER_CHANNEL_VERSION-server-rpms
    
    # disable channel
    # --------------------------------------------------------------------------------------------------------
    # cf-me-* does not seem to exist at all, so this will check if repo exists before disabling it
    cmd=`$SUDO subscription-manager repos --list | grep cf-me-*`
    if [ ${#cmd} -gt 0 ]; then
        $SUDO subscription-manager repos --disable=cf-me-*
    fi
    
    # Whether RH_SERVER_CHANNEL_VERSION is 6 or 7, 6 is used to diable. 
    # this needs to be tested in 7
    $SUDO subscription-manager repos --disable=rhel-6-server-cf-*
    $SUDO subscription-manager repos --disable=rhel-6-server-rhev* 
    $SUDO subscription-manager repos --disable=*-eus-rpms
    $SUDO subscription-manager repos --disable=rhel-server-rhscl-6-rpms*
}

function enable_redhat_repositories_2 {
    # Content Delivery Network (CDN) Channels
    # -----------------------------------------------------------
    # disable all channels
    $SUDO subscription-manager repos --disable=*
    
    # enable channels
    $SUDO subscription-manager repos --enable=rhel-$RH_SERVER_CHANNEL_VERSION-server-rpms
    $SUDO subscription-manager repos --enable=rhel-$RH_SERVER_CHANNEL_VERSION-server-openstack-$RH_OPENSTACK_VERSION-rpms
    
    # The RedHat Common for RHEL Server channel is recommended for use if creating custom RedHat 
    # Enterprise Linux guest images that require cloud-init.
    #if [ $RH_SERVER_CHANNEL_VERSION = '7' ]; then
    #    $SUDO subscription-manager repos --enable=rhel-$RH_SERVER_CHANNEL_VERSION-server-rh-common-rpms
    #fi
}

function configure_hostname {
    # RHEL 7 uses /etc/hostname but 6 uses /etc/sysconfig/network
    hostname_file='/etc/sysconfig/network'
    if [[ $RH_SERVER_CHANNEL_VERSION = '7' ]]; then
        hostname_file='/etc/hostname'
    fi

    # update hostname
    if [[ -n $HOST_NAME && ${#HOST_NAME} -gt 0 ]]; then
        hostname=`$SUDO cat $hostname_file | grep HOSTNAME | tr -d ' '`
        # no HOSTNAME defined
        if [ ${#hostname} -eq 0 ]; then
            cat << EOF | $SUDO tee -a $hostname_file
HOSTNAME=$HOST_NAME
EOF
            echo_indented "hostname '$HOST_NAME' has been added"
        # HOSTNAME is defined and already the correct name exists
        elif [[ $hostname =~ HOSTNAME=$HOST_NAME ]]; then
            echo_indented "No hostname change is needed"
        # HOSTNAME defined but different name found
        else            
            $SUDO sed -i -e "s/HOSTNAME=.*/HOSTNAME=$HOST_NAME/g" $hostname_file
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

#
# sed -i -e "s/CONFIG_CEILOMETER_INSTALL=y/CONFIG_CEILOMETER_INSTALL=n/g; \
#           s/CONFIG_CINDER_VOLUMES_SIZE=20G/CONFIG_CINDER_VOLUMES_SIZE=1G/g; \
#           s/CONFIG_NEUTRON_LB_TENANT_NETWORK_TYPE=local/CONFIG_NEUTRON_LB_TENANT_NETWORK_TYPE=vxlan/g; \
#           s/CONFIG_NEUTRON_OVS_TUNNEL_RANGES=/CONFIG_NEUTRON_OVS_TUNNEL_RANGES=1:1000/g; \
#           s/CONFIG_NEUTRON_OVS_TUNNEL_IF=/CONFIG_NEUTRON_OVS_TUNNEL_IF=$EXT_INTERFACE/g; \
#           s/CONFIG_NEUTRON_OVS_TENANT_NETWORK_TYPE=local/CONFIG_NEUTRON_OVS_TENANT_NETWORK_TYPE=vxlan/g" \
# /root/havana_openstack.cfg
#
#    CONFIG_NEUTRON_ML2_VNI_RANGES=10:100/CONFIG_NEUTRON_ML2_VNI_RANGES=1001:2000
#
function install_packstack {
    echo "----------------------------------------------------------------------------------"
    stop_neutron_services
    get_stack_deployment_type
    install_packstack_icehouse
    
    restart_neutron_services
    echo "----------------------------------------------------------------------------------"
}

function get_stack_deployment_type {
    if [[ -z $STACK_DEPLOYMENT_TYPE ]]; then
        deployment_type='single'
    elif [ $STACK_DEPLOYMENT_TYPE = 'multi' ]; then
        deployment_type='multi'
    else
        deployment_type='single'
    fi
    export STACK_DEPLOYMENT_TYPE=$deployment_type
}

function install_packstack_icehouse {
    #echo_indented "Generating packstack answer file..."
    #packstack --gen-answer-file=packstack-answers.txt
    
    # packstack --allinone --os-neutron-install=y --provision-demo=n --provision-all-in-one-ovs-bridge=n
    echo "Please provide 'root' password below if asked >>>"
    $SUDO packstack --allinone --provision-demo=n --timeout=7200
    echo "***************************************************************"
    
    # Horizon access issue
    $SUDO sed -i '/^ALLOWED_HOSTS/ s/=.*/= [ "*" ]/' /etc/openstack-dashboard/local_settings 
    $SUDO service httpd restart
    
    # --provision-demo=n option does not install demo networks as well as images.
    echo "Installing image (cirros-0.3.2-x86_64-disk.img)..."
    $SUDO wget http://cdn.download.cirros-cloud.net/0.3.2/cirros-0.3.2-x86_64-disk.img
    if [ -e "cirros-0.3.2-x86_64-disk.img" ]; then
        $SUDO source /root/keystonerc_admin
        $SUDO glance image-create --name "cirros-0.3.2-x86_64" --file cirros-0.3.2-x86_64-disk.img \
              --disk-format qcow2 --container-format bare --is-public True --progress
    else
        echo "cirros-0.3.2-x86_64-disk.img is not yet downloaded or failed to download."
        echo "Please download the image and register it to glance in order to create an instance"
        echo "Check here for more information: http://docs.openstack.org/trunk/install-guide/install/yum/content/glance-verify.html"
    fi
    
    # 'packstack --allinone' installs roles such as admin, _member_, SwiftOperator, and ResellerAdmin
    # -----------------------------------------------------------------------------------------------
    #$SUDO source /root/keystonerc_admin
    #cmd=`keystone role-list | grep Member | wc -c`
    #if [ $cmd -eq 0 ]; then
    #    keystone role-create --name=Member
    #fi
    
    #echo_indented "Updating ML2 config..."
    #run_crudini $ML2_PLUGIN_CONF securitygroup firewall_driver neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
    #run_crudini $ML2_PLUGIN_CONF ovs local_ip $HOST_IP
    #crudini --set $ML2_PLUGIN_CONF database connection mysql://root:admin@127.0.0.1/neutron_ml2?charset=utf8
    #$SUDO crudini --set $ML2_PLUGIN_CONF agent root_helper 'sudo neutron-rootwrap /etc/neutron/rootwrap.conf'
}

function install_packstack_havana {
    # packstack --allinone --os-neutron-install=y --provision-demo=n --provision-all-in-one-ovs-bridge=n
    echo "Please provide 'root' password below if asked >>>"
    $SUDO packstack --allinone --timeout=7200

    $SUDO source /root/keystonerc_admin
    cmd=`keystone role-list | grep Member | wc -c`
    if [ $cmd -eq 0 ]; then
        keystone role-create --name=Member
    fi
    
    $SUDO service neutron-server stop

    configure_neutron_hanava
    
    # change network interface
    configure_network_interfaces
    
    cmd=`$SUDO ovs-vsctl list-br | grep br-phys | wc -c`
    if [ $cmd -eq 0 ]; then
        $SUDO ovs-vsctl add-br br-phys
        $SUDO ifconfig br-phys up
        $SUDO ovs-vsctl add-port br-phys eth2 
    fi
    
    $SUDO service network restart
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
        run_crudini $DHCP_AGENT_CONF DEFAULT interface_dev_name_len 10
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
    # ifconfig is not supported in RHEL 7.1 beta but supported on 7.0
    # So replaced ifconfig with ip commmands
    cmd=`ovs-ofctl show $IOA_BRIDGE | grep $IOA_INTERFACE | wc -l`
    if [ $cmd -eq 0 ]; then
        #$SUDO ifconfig $IOA_BRIDGE up
        $SUDO ip link set $IOA_BRIDGE up
        $SUDO ovs-vsctl add-port $IOA_BRIDGE $IOA_INTERFACE && \
        $SUDO ip addr del $IOA_HOST_IP/24 dev $IOA_INTERFACE && \
        $SUDO ip addr add $IOA_HOST_IP/24 dev $IOA_BRIDGE && \
        $SUDO ip route add default via $IOA_HOST_GATEWAY
        #$SUDO ifconfig $IOA_INTERFACE 0.0.0.0
        $SUDO ip addr add 0.0.0.0 dev $IOA_INTERFACE

        $SUDO service network restart
   fi
}

function configure_network_interfaces {
    if [[ -e "/etc/sysconfig/network-scripts/ifcfg-$IOA_INTERFACE" &&
          -e "/etc/sysconfig/network-scripts/ifcfg-$IOA_BRIDGE"    ]]; then
        cmd1=`$SUDO cat /etc/sysconfig/network-scripts/ifcfg-$IOA_INTERFACE | grep OVS_BRIDGE=$IOA_BRIDGE | wc -c`
        cmd2=`$SUDO cat /etc/sysconfig/network-scripts/ifcfg-$IOA_BRIDGE | grep IPADDR=${IOA_HOST_IP} | wc -c`
        if [[ $cmd1 -gt 0 && $cmd2 -gt 0 ]]; then
            echo_indented "No need to update network interfaces"
            return 0
        fi
    fi

    echo_indented "Creating $IOA_BRIDGE and adding port $IOA_INTERFACE..."
    if [ -e "/etc/sysconfig/network-scripts/ifcfg-$IOA_INTERFACE" ]; then
        $SUDO sed -i '1,$ d' /etc/sysconfig/network-scripts/ifcfg-$IOA_INTERFACE
    fi
    if [ -e "/etc/sysconfig/network-scripts/ifcfg-$IOA_BRIDGE" ]; then
        $SUDO sed -i '1,$ d' /etc/sysconfig/network-scripts/ifcfg-$IOA_BRIDGE
    fi
    
    cat << EOF | $SUDO tee -a /etc/sysconfig/network-scripts/ifcfg-$IOA_INTERFACE
DEVICE=$IOA_INTERFACE
TYPE=OVSPort
ONBOOT=yes
NM_CONTROLLED=no
BOOTPROTO=none
OVS_BRIDGE=$IOA_BRIDGE
DEVICETYPE=ovs
EOF

    cat << EOF | $SUDO tee -a /etc/sysconfig/network-scripts/ifcfg-$IOA_BRIDGE
DEVICE=$IOA_BRIDGE
BOOTPROTO=static
IPADDR=${IOA_HOST_IP}
NETMASK=$IOA_HOST_NETMASK
GATEWAY=$IOA_HOST_GATEWAY
DEVICETYPE=ovs
DNS1=$IOA_HOST_DNS
TYPE=OVSBridge
ONBOOT=yes
EOF

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
    
    echo_indented "Installing IOA required libraries..."
    $SUDO pip install -r $IB_NEUTRON_PATCH_PATH/neutron/requirements.txt
    
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
        $SUDO neutron-db-manage --config-file=/etc/neutron/neutron.conf --config-file=/etc/neutron/plugin.ini upgrade head
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

function configure_neutron_hanava {
    if [ $NEUTRON_PLUGIN == 'ml2' ]; then
        configure_neutron_ml2
    elif [ $NEUTRON_PLUGIN == 'ml2' ]; then
        configure_neutron_ovs
    fi
    
    $SUDO crudini --set $NEUTRON_CONF DEFAULT logging_context_format_string '%(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [%(request_id)s %(user_name)s %(project_name)s%(color)s] %(instance)s%(color)s%(message)s'
    $SUDO crudini --set $NEUTRON_CONF DEFAULT logging_debug_format_suffix 'from (pid=%(process)d) %(funcName)s %(pathname)s:%(lineno)d'
    $SUDO crudini --set $NEUTRON_CONF DEFAULT logging_default_format_string '%(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [-%(color)s] %(instance)s%(color)s%(message)s'
    $SUDO crudini --set $NEUTRON_CONF DEFAULT logging_exception_prefix '%(color)s%(asctime)s.%(msecs)03d TRACE %(name)s %(instance)s'
    $SUDO crudini --set $NEUTRON_CONF DEFAULT notification_driver neutron.openstack.common.notifier.rpc_notifier
    $SUDO crudini --set $NEUTRON_CONF DEFAULT policy_file /etc/neutron/policy.json
    
    $SUDO crudini --set $NEUTRON_CONF DEFAULT debug True
    $SUDO crudini --set $NEUTRON_CONF DEFAULT lock_path '$state_path/lock'
    $SUDO crudini --set $NEUTRON_CONF DEFAULT agent_down_time 9
    
    cmd=`$SUDO ovs-vsctl list-br | grep br-eth1 | wc -c`
    if [ $cmd -eq 0 ]; then
        $SUDO ovs-vsctl add-br br-eth1
    fi
    
    $SUDO crudini --set $OVS_PLUGIN_CONF OVS tenant_network_type 'vlan'
    $SUDO crudini --set $OVS_PLUGIN_CONF OVS bridge_mappings physnet1:br-eth1
    $SUDO crudini --set $OVS_PLUGIN_CONF OVS vxlan_udp_port 4789
    $SUDO crudini --set $OVS_PLUGIN_CONF OVS enable_tunneling False
    $SUDO crudini --set $OVS_PLUGIN_CONF OVS integration_bridge 'br-int'
    
    # L3_AGENT_CONF
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT l3_agent_manager neutron.agent.l3_agent.L3NATAgentWithStateReport
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT external_network_bridge br-phys
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT interface_driver neutron.agent.linux.interface.OVSInterfaceDriver
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT ovs_use_veth False
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT root_helper 'sudo /usr/local/bin/neutron-rootwrap /etc/neutron/rootwrap.conf'
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT use_namespaces True
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT debug True
    $SUDO crudini --set $L3_AGENT_CONF DEFAULT verbose True

    $SUDO neutron-db-manage --config-file=$NEUTRON_CONF --config-file=/etc/neutron/plugin.ini upgrade head
    if [ $NEUTRON_PLUGIN == 'ml2' ];
      then
        export DBVERSION=`echo 'select version_num from neutron_ml2.alembic_version' | mysql | tail -1`
      else
        export DBVERSION=`echo 'select version_num from ovs_neutron.alembic_version' | mysql | tail -1`
    fi

    $SUDO sed -i "s/havana/$DBVERSION/g" /etc/sysconfig/openstack-neutron
    $SUDO sed -i 's/"x$neutron_db_version" != "x$NEUTRON_EXPECTED_DB_VERSION"/"x$NEUTRON_EXPECTED_DB_VERSION" != "x$NEUTRON_EXPECTED_DB_VERSION"/g' /usr/bin/neutron-db-check
    $SUDO sed -i 's/{print $NF}/{print $7}/g' /usr/bin/neutron-db-check
}

function configure_neutron_ovs {
    $SUDO crudini --set $NEUTRON_CONF DEFAULT core_plugin neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2;
}

function configure_neutron_ml2 {
    [ -h /etc/neutron/plugin.ini ] && $SUDO unlink /etc/neutron/plugin.ini
    $SUDO ln -s /etc/neutron/plugins/ml2/ml2_conf.ini /etc/neutron/plugin.ini
    
    $SUDO sed -i 's/\/ovs_neutron/\/neutron_ml2/g' /etc/neutron/neutron.conf
    
    # configure neutron-server to load the ML2 core plugin and the L3Router service plugin
    $SUDO crudini --set $NEUTRON_CONF DEFAULT core_plugin neutron.plugins.ml2.plugin.Ml2Plugin
    $SUDO crudini --set $NEUTRON_CONF DEFAULT service_plugins neutron.services.l3_router.l3_router_plugin.L3RouterPlugin
    
    $SUDO mysql -e "drop database if exists neutron_ml2;"
    $SUDO mysql -e "create database neutron_ml2 character set utf8;"
    $SUDO mysql -e "grant all on neutron_ml2.* to 'neutron'@'%';"
    
    $SUDO crudini --set $ML2_PLUGIN_CONF ml2 tenant_network_types vlan
    $SUDO crudini --set $ML2_PLUGIN_CONF ml2 type_drivers local,flat,vlan,gre,vxlan
    $SUDO crudini --set $ML2_PLUGIN_CONF ml2 mechanism_drivers openvswitch,linuxbridge
    $SUDO crudini --set $ML2_PLUGIN_CONF ml2_type_vlan network_vlan_ranges 'physnet1:1000:1999'
    $SUDO crudini --set $ML2_PLUGIN_CONF ml2_type_gre tunnel_id_ranges '1:1000'
    $SUDO crudini --set $ML2_PLUGIN_CONF ml2_type_vxlan vni_ranges '1001:2000'
    $SUDO crudini --set $ML2_PLUGIN_CONF ovs local_ip $IOA_HOST_IP
    $SUDO crudini --set $ML2_PLUGIN_CONF agent root_helper 'sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf'
    $SUDO crudini --set $ML2_PLUGIN_CONF securitygroup firewall_driver neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver

    $SUDO mysql -e "drop database if exists neutron_ml2;"
    $SUDO mysql -e "create database neutron_ml2 character set utf8;"
    $SUDO mysql -e "grant all on neutron_ml2.* to 'neutron'@'%';"
}

function remove_packstack {
    # Warning! Dangerous step! Destroys VMs
    for x in $(virsh list --all | grep instance- | awk '{print $2}') ; do
        $SUDO virsh destroy $x ;
        $SUDO virsh undefine $x ;
    done
    
    $SUDO yum remove -y "*openstack*" "*nova*" "*keystone*" "*glance*" "*cinder*" "*swift*" "*rdo-release*";
    
    # Optional - makes database cleanup cleaner.
    # If you do this bit, the database cleanup stuff below is superfluous.
    # yum remove -y "*mysql*"
    $SUDO ps -ef | grep -i repli | grep swift | awk '{print $2}' | xargs kill ;
    $SUDO rm -rf  /etc/yum.repos.d/packstack_* /var/lib/glance /var/lib/nova /etc/nova
        /etc/swift \
        /srv/node/device*/* /var/lib/cinder/ /etc/rsync.d/frag* \
        /var/cache/swift /var/log/keystone /tmp/keystone-signing-nova ;
            
    # Ensure there is a root user and that we know the password
    $SUDO service mysql stop
    cat > /tmp/set_mysql_root_pwd << EOF
UPDATE mysql.user SET Password=PASSWORD('MyNewPass') WHERE User='root';
FLUSH PRIVILEGES;
EOF
    
    # mysql cleanup
    $SUDO /usr/bin/mysqld_safe --init-file=/tmp/set_mysql_root_pwd &
    $SUDO rm /tmp/set_mysql_root_pwd
    $SUDO mysql -uroot -pMyNewPass -e "drop database nova; drop database cinder; drop
    database keystone; drop database glance; drop database if exists neutron_ml2;"
    
    $SUDO umount /srv/node/device* ;
    $SUDO vgremove -f cinder-volumes ;
    $SUDO losetup -a | sed -e 's/:.*//g' | xargs losetup -d ;
    $SUDO find /etc/pki/tls -name "ssl_ps*" | xargs rm -rf ;
    for x in $(df | grep "/lib/" | sed -e 's/.* //g') ; do
        $SUDO umount $x ;
    done
}

# Restore xtrace
#$XTRACE
