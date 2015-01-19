#!/usr/bin/env bash

##################################################################
###  DEFINE VARIABLES HERE TO CREATE YOUR TEST NETWORK
##################################################################
EXTERNAL_NETWORK_NAME='extnet'
EXTERNAL_NETWORK_SUBNET_NAME='extnet_subnet'
EXTERNAL_NETWORK_SUBNET_IP_ALLOCATION_POOL_START='10.32.4.130'
EXTERNAL_NETWORK_SUBNET_IP_ALLOCATION_POOL_END='10.32.4.140'
EXTERNAL_NETWORK_SUBNET_GATEEAY='10.32.0.1'
EXTERNAL_NETWORK_SUBNET_CIDER='10.32.0.0/16'
EXTERNAL_NETWORK_SUBNET_DNS_SERVER='10.102.3.50'
EXTERNAL_NETWORK_ROUTER='extrouter'

PRIVATE_NETWORK_NAME='priv_net1'
PRIVATE_NETWORK_SUBNET_DNS_SERVER='10.102.3.50'

PRIVATE_NETWORK_SUBNET_NAME_1='priv_net1_sub_88'
PRIVATE_NETWORK_SUBNET_CIDER_1='88.88.0.0/24'

PRIVATE_NETWORK_SUBNET_NAME_2='priv_net1_sub_99'
PRIVATE_NETWORK_SUBNET_CIDER_2='99.99.0.0/24'

TEST_NETWORK_INSTANCE_NAME_1="priv_net1_sub_88-vm01"
TEST_NETWORK_INSTANCE_NAME_2="priv_net1_sub_99-vm01"
###################################################################

if [ "$1" = "clean_all" ]; then
    echo "delete"
fi


# Prepare script environment
# =================================================================
# Keep track of the devstack directory
TOP_DIR=$(cd $(dirname "$0") && pwd)

# Import common functions
source $TOP_DIR/ib_deploy_func.sh

source /root/keystonerc_admin
echo " "

echo "Updating admin user password to 'infoblox'..."
echo "----------------------------------------------------------------------------------"
user_id_admin=$(keystone user-list  | grep admin | grep -oP '(\w{32})')
if [ -z "$user_id_admin" ]; then
    echo_indented "Cannot find admin user in keystone"
    exit 1
else
    admin_pwd=$(cat /root/keystonerc_admin | grep 'export OS_PASSWORD=' | grep -oP '[^export OS_PASSWORD=]\w+$')
    if [ "$admin_pwd" != "infoblox" ]; then
        keystone user-password-update --pass infoblox $user_id_admin
        sed -i -e "s/export OS_PASSWORD=.*/export OS_PASSWORD=infoblox/g" /root/keystonerc_admin
        source /root/keystonerc_admin
        echo_indented "Done!"
    else
        echo_indented "Already changed!"
    fi
fi
echo " "

# Create a provider network
# =================================================================
echo "Creating a provider network..."
echo "----------------------------------------------------------------------------------"

echo_indented "Creating a provider external network..."
cmd=$(neutron net-list --field name | grep $EXTERNAL_NETWORK_NAME | wc -l)
if [ $cmd -eq 0 ]; then
    EXTERNAL_NET_ID=`neutron net-create $EXTERNAL_NETWORK_NAME --router:external=True | egrep "\sid\s" | awk '{print $4}'`
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi

echo_indented "Creating a provider subnet for the external network..."
cmd=$(neutron net-list | grep $EXTERNAL_NETWORK_NAME | wc -c)
# why 96?
# each id takes up 36 length. we have netowrk id and subnet id so both are 72
# 72 + 10 (column separator and spaces) + CIDR (9 ~ 14) + $EXTERNAL_NETWORK_SUBNET_NAME
if [ $cmd -lt 96 ]; then
    EXTERNAL_SUBNET_ID=`neutron subnet-create --name $EXTERNAL_NETWORK_SUBNET_NAME --enable_dhcp=False \
                          --allocation-pool=start=$EXTERNAL_NETWORK_SUBNET_IP_ALLOCATION_POOL_START,end=$EXTERNAL_NETWORK_SUBNET_IP_ALLOCATION_POOL_END \
                          --gateway=$EXTERNAL_NETWORK_SUBNET_GATEEAY \
                          $EXTERNAL_NETWORK_NAME $EXTERNAL_NETWORK_SUBNET_CIDER | egrep "\sid\s" | awk '{print $4}'`
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi

# Create a router and set the router's gateway
# =================================================================
echo_indented "Creating a router for the external network..."
cmd=$(neutron router-list | grep $EXTERNAL_NETWORK_ROUTER | wc -l)
# create a router and connect it to the private network and the external network
if [ $cmd -eq 0 ]; then
    neutron router-create $EXTERNAL_NETWORK_ROUTER
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Router Created!" 6
    else
        echo_indented "Router Failed to created!" 6
        exit 1
    fi

    neutron router-gateway-set $EXTERNAL_NETWORK_ROUTER $EXTERNAL_NETWORK_NAME
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Router Gateway Created!" 6
    else
        echo_indented "Router Gateway Failed to created!" 6
        exit 1
    fi

    neutron net-list
    echo_indented "Completed!" 6
else
    echo_indented "Already existed!" 6
fi
echo " "

# Create a tenant network
# =================================================================
echo "Creating a private network..."
echo "----------------------------------------------------------------------------------"

cmd=$(neutron net-list --field name | grep $PRIVATE_NETWORK_NAME | wc -l)
if [ $cmd -eq 0 ]; then
    PRIVATE_NET_ID=`neutron net-create $PRIVATE_NETWORK_NAME | egrep "\sid\s" | awk '{print $4}'`
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi

echo_indented "Creating the tenant subnet 1..."
cmd=$(neutron subnet-list | grep $PRIVATE_NETWORK_SUBNET_NAME_1 | wc -c)
# why 96?
# each id takes up 36 length. we have netowrk id and subnet id so both are 72
# 72 + 10 (column separator and spaces) + CIDR (9 ~ 14) + $EXTERNAL_NETWORK_SUBNET_NAME
if [ $cmd -lt 96 ]; then
    PRIVATE_NETWORK_SUBNET_ID_1=`neutron subnet-create --name $PRIVATE_NETWORK_SUBNET_NAME_1 \
                          --dns-nameserver $PRIVATE_NETWORK_SUBNET_DNS_SERVER \
                          $PRIVATE_NETWORK_NAME $PRIVATE_NETWORK_SUBNET_CIDER_1 | egrep "\sid\s" | awk '{print $4}'`
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
    
    #source /root/keystonerc_admin
    neutron router-interface-add $EXTERNAL_NETWORK_ROUTER $PRIVATE_NETWORK_SUBNET_NAME_1
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Router Interface Created!" 6
    else
        echo_indented "Router Interface Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi

echo_indented "Creating the tenant subnet 2..."
cmd=$(neutron subnet-list | grep $PRIVATE_NETWORK_SUBNET_NAME_2 | wc -c)
# why 96?
# each id takes up 36 length. we have netowrk id and subnet id so both are 72
# 72 + 10 (column separator and spaces) + CIDR (9 ~ 14) + $EXTERNAL_NETWORK_SUBNET_NAME
if [ $cmd -lt 96 ]; then
    PRIVATE_NETWORK_SUBNET_ID_2=`neutron subnet-create --name $PRIVATE_NETWORK_SUBNET_NAME_2 \
                          --dns-nameserver $PRIVATE_NETWORK_SUBNET_DNS_SERVER \
                          $PRIVATE_NETWORK_NAME $PRIVATE_NETWORK_SUBNET_CIDER_2 | egrep "\sid\s" | awk '{print $4}'`
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
    
    #source /root/keystonerc_admin
    neutron router-interface-add $EXTERNAL_NETWORK_ROUTER $PRIVATE_NETWORK_SUBNET_NAME_2
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Router Interface Created!" 6
    else
        echo_indented "Router Interface Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi

echo_indented "Creating security rules to allow ICMP traffics..."
#source /root/keystonerc_admin
cmd=$(neutron security-group-rule-list | grep ingress | grep default | wc -l)
if [ $cmd -eq 0 ]; then
    neutron security-group-rule-create --protocol icmp default
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
    fi
else
    echo_indented "Already existed!" 6
fi

echo_indented "Creating security rules to allow SSH traffics..."
cmd=$(neutron security-group-rule-list | grep ingress | grep default | wc -l)
if [ $cmd -eq 0 ]; then
    neutron security-group-rule-create --protocol tcp --port-range-min 22 --port-range-max 22 default
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
    fi
else
    echo_indented "Already existed!" 6
fi
echo " "


# Testing Networks
# =================================================================
echo "Testing Networks..."
echo "----------------------------------------------------------------------------------"

#Creating an SSH key allows you to have it set in a VM when you boot it, making it easier to login with SSH. 
echo_indented "Creating an SSH key to SSH to an instance..." 
if [ -e "/root/vm_ssh_key.key" ]; then
    echo_indented "/root/vm_ssh_key.key is found." 6
else
    nova keypair-add vmkey > /root/vm_ssh_key.key
    echo_indented "/root/vm_ssh_key.key is created." 6
fi

echo_indented "Creating an instance 1..."
cmd=$(nova list | grep $TEST_NETWORK_INSTANCE_NAME_1 | wc -l)
if [ $cmd -eq 0 ]; then
    #instaince_id=$(nova list | grep $TEST_NETWORK_INSTANCE_NAME_1 | grep -oP '([A-Za-z0-9-]{36})'
    image_id=$(glance image-list 2>&1 | grep 'cirros-0.3.2-x86_64' | grep -oP '([A-Za-z0-9-]{36})')
    #priv_network_id=$(neutron net-list --c id --c name | grep $PRIVATE_NETWORK_NAME | grep -oP '([A-Za-z0-9-]{36})')
    
    echo_indented "Now you are about to create an instance. This may take a while..."
    nova boot --poll --flavor 1 --image $image_id \
              --nic net-id=$PRIVATE_NET_ID \
              --key-name vmkey \
              $TEST_NETWORK_INSTANCE_NAME_1
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi

echo_indented "Creating an instance 2..."
cmd=$(nova list | grep $TEST_NETWORK_INSTANCE_NAME_2 | wc -l)
if [ $cmd -eq 0 ]; then
    #instaince_id=$(nova list | grep $TEST_NETWORK_INSTANCE_NAME_1 | grep -oP '([A-Za-z0-9-]{36})'
    image_id=$(glance image-list 2>&1 | grep 'cirros-0.3.2-x86_64' | grep -oP '([A-Za-z0-9-]{36})')
    #priv_network_id=$(neutron net-list --c id --c name | grep $PRIVATE_NETWORK_NAME | grep -oP '([A-Za-z0-9-]{36})')
    
    echo_indented "Now you are about to create an instance. This may take a while..."
    nova boot --poll --flavor 1 --image $image_id \
              --nic net-id=$PRIVATE_NET_ID \
              --key-name vmkey \
              $TEST_NETWORK_INSTANCE_NAME_2
    exitcode=$?
    if [ $exitcode -eq 0 ]; then
        echo_indented "Created!" 6
    else
        echo_indented "Failed to created!" 6
        exit 1
    fi
else
    echo_indented "Already existed!" 6
fi
echo " "
echo "----------------------------------------------------------------------------------"
echo "EXTERNAL_NET_ID: $EXTERNAL_NET_ID"
echo "EXTERNAL_SUBNET_ID: $EXTERNAL_SUBNET_ID"
echo "PRIVATE_NET_ID: $PRIVATE_NET_ID"
echo "PRIVATE_NETWORK_SUBNET_ID_1: $PRIVATE_NETWORK_SUBNET_ID_1"
echo "PRIVATE_NETWORK_SUBNET_ID_2: $PRIVATE_NETWORK_SUBNET_ID_2"
echo " "

exit 0