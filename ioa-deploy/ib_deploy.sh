#!/usr/bin/env bash

# Keep track of the devstack directory
TOP_DIR=$(cd $(dirname "$0") && pwd)
# Import common functions
source $TOP_DIR/ib_deploy_func.sh

echo 'Preparing deployment...'
if ! prepare_env ; then
    exit 1
fi

echo "Getting OpenStack Release version to install..."
get_openstack_release

#########################################################################
# Needs to determine whether OpenStack is already installed or not here.
# It could be fresh install or just patching our adapter.
#
# check if OpenStack is already running or not.
# If running, ask if user wants to patch IOA
#    IOA new install or upgrade?
#
#########################################################################

process_deployment

exit 0

