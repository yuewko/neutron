# 
# Requires bash 4.0 or greater
#

DEFAULT_MSG_PADDING=3

# Save trace setting
#XTRACE=$(set +o | grep xtrace)
#set -o xtrace

function prepare_env {
    get_distro
    get_distro_short_name
    
    load_custom_config

    echo "Detecting system..."
    echo_indented "$DISTRO from $os_VENDOR, release: $os_RELEASE, update: $os_UPDATE, codename: $os_CODENAME"

    if is_root_user; then
        SUDO=''
    else
        echo_indented "You are not a sudo user. Please enter sudo user password if prompted for password."
        sudo sh -c "ls /etc/ >/dev/null"
        SUDO="sudo"
    fi
    export SUDO
    
    get_deployment_services
    
    local status=0
    if has_stack_config; then
        stackrc=$(get_stackrc_path)
        source $stackrc
    else
        status=1
        echo_indented "'ib_stackrc.$DISTRO_SHORT_NAME' must be present and PACKAGES must contain all the packages to run OpenStack."
    fi
    
    if has_ioa_config; then
        source $TOP_DIR/ib_ioarc 
    else
        status=1
        echo_indented "'ib_ioarc' must be present."
    fi
    
    if has_patch; then
        REQUIRE_FIX_PATCH='TRUE'
        source $TOP_DIR/ib_patch.sh
    else
        REQUIRE_FIX_PATCH='FALSE'
    fi
    export REQUIRE_FIX_PATCH
    
    return $status
}

function process_deployment {
    source $TOP_DIR/ib_deploy_$DISTRO_SHORT_NAME.sh
    eval deploy_$DISTRO_SHORT_NAME
}

function ensure_root_user {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
}

function is_root_user {
    if [ "$(id -u)" != "0" ]; then
        return 1
    fi
    return 0
}

# get_distro
# -------------------------------------------------
# Translate the OS version values into common nomenclature
# Sets ``DISTRO`` from the ``os_*`` values
function get_distro {
    if [[ -z "os_VENDOR" ]]; then
        skip_distro_check='FALSE'
    else
        skip_distro_check='TRUE'
    fi
    
    if [[ "$skip_distro_check" = "TRUE" ]]; then
        return 0;
    fi
    
    get_os_version
    
    if [[ "$os_VENDOR" =~ (Ubuntu) || "$os_VENDOR" =~ (Debian) ]]; then
        # 'Everyone' refers to Ubuntu / Debian releases by the code name adjective
        DISTRO=$os_CODENAME
    elif [[ "$os_VENDOR" =~ (Fedora) ]]; then
        # For Fedora, just use 'f' and the release
        DISTRO="f$os_RELEASE"
    elif [[ "$os_VENDOR" =~ (openSUSE) ]]; then
        DISTRO="opensuse-$os_RELEASE"
    elif [[ "$os_VENDOR" =~ (SUSE LINUX) ]]; then
        # For SLE, also use the service pack
        if [[ -z "$os_UPDATE" ]]; then
            DISTRO="sle${os_RELEASE}"
        else
            DISTRO="sle${os_RELEASE}sp${os_UPDATE}"
        fi
    elif [[ "$os_VENDOR" =~ (Red Hat) || "$os_VENDOR" =~ (CentOS) ]]; then
        # Drop the . release as we assume it's compatible
        DISTRO="rhel${os_RELEASE::1}"
    elif [[ "$os_VENDOR" =~ (XenServer) ]]; then
        DISTRO="xs$os_RELEASE"
    else
        # Catch-all for now is Vendor + Release + Update
        DISTRO="$os_VENDOR-$os_RELEASE.$os_UPDATE"
    fi
    
    export DISTRO
}

# get_os_version
# -------------------------------------------------
# Determine OS Vendor, Release and Update
# Tested with OS/X, Ubuntu, RedHat, CentOS, Fedora
# Returns results in global variables:
# os_VENDOR - vendor name
# os_RELEASE - release
# os_UPDATE - update
# os_PACKAGE - package type
# os_CODENAME - vendor's codename for release
function get_os_version {
    # Figure out which vendor we are
    if [[ -x "`which sw_vers 2>/dev/null`" ]]; then
        # OS/X
        os_VENDOR=`sw_vers -productName`
        os_RELEASE=`sw_vers -productVersion`
        os_UPDATE=${os_RELEASE##*.}
        os_RELEASE=${os_RELEASE%.*}
        os_PACKAGE=""
        if [[ "$os_RELEASE" =~ "10.7" ]]; then
            os_CODENAME="lion"
        elif [[ "$os_RELEASE" =~ "10.6" ]]; then
            os_CODENAME="snow leopard"
        elif [[ "$os_RELEASE" =~ "10.5" ]]; then
            os_CODENAME="leopard"
        elif [[ "$os_RELEASE" =~ "10.4" ]]; then
            os_CODENAME="tiger"
        elif [[ "$os_RELEASE" =~ "10.3" ]]; then
            os_CODENAME="panther"
        else
            os_CODENAME=""
        fi
    elif [[ -x $(which lsb_release 2>/dev/null) ]]; then
        os_VENDOR=$(lsb_release -i -s)
        os_RELEASE=$(lsb_release -r -s)
        os_UPDATE=""
        os_PACKAGE="rpm"
        if [[ "Debian,Ubuntu,LinuxMint" =~ $os_VENDOR ]]; then
            os_PACKAGE="deb"
        elif [[ "SUSE LINUX" =~ $os_VENDOR ]]; then
            lsb_release -d -s | grep -q openSUSE
            if [[ $? -eq 0 ]]; then
                os_VENDOR="openSUSE"
            fi
        elif [[ $os_VENDOR == "openSUSE project" ]]; then
            os_VENDOR="openSUSE"
        elif [[ $os_VENDOR =~ Red.*Hat ]]; then
            os_VENDOR="Red Hat"
        fi
        os_CODENAME=$(lsb_release -c -s)
    elif [[ -r /etc/redhat-release ]]; then
        # Red Hat Enterprise Linux Server release 5.5 (Tikanga)
        # CentOS release 5.5 (Final)
        # CentOS Linux release 6.0 (Final)
        # Fedora release 16 (Verne)
        # XenServer release 6.2.0-70446c (xenenterprise)
        os_CODENAME=""
        for r in "Red Hat" CentOS Fedora XenServer; do
            os_VENDOR=$r
            if [[ -n "`grep \"$r\" /etc/redhat-release`" ]]; then
                ver=`sed -e 's/^.* \(.*\) (\(.*\)).*$/\1\|\2/' /etc/redhat-release`
                os_CODENAME=${ver#*|}
                os_RELEASE=${ver%|*}
                os_UPDATE=${os_RELEASE##*.}
                break
            fi
            os_VENDOR=""
        done
        os_PACKAGE="rpm"
    elif [[ -r /etc/SuSE-release ]]; then
        for r in openSUSE "SUSE Linux"; do
            if [[ "$r" = "SUSE Linux" ]]; then
                os_VENDOR="SUSE LINUX"
            else
                os_VENDOR=$r
            fi

            if [[ -n "`grep \"$r\" /etc/SuSE-release`" ]]; then
                os_CODENAME=`grep "CODENAME = " /etc/SuSE-release | sed 's:.* = ::g'`
                os_RELEASE=`grep "VERSION = " /etc/SuSE-release | sed 's:.* = ::g'`
                os_UPDATE=`grep "PATCHLEVEL = " /etc/SuSE-release | sed 's:.* = ::g'`
                break
            fi
            os_VENDOR=""
        done
        os_PACKAGE="rpm"
    # If lsb_release is not installed, we should be able to detect Debian OS
    elif [[ -f /etc/debian_version ]] && [[ $(cat /proc/version) =~ "Debian" ]]; then
        os_VENDOR="Debian"
        os_PACKAGE="deb"
        os_CODENAME=$(awk '/VERSION=/' /etc/os-release | sed 's/VERSION=//' | sed -r 's/\"|\(|\)//g' | awk '{print $2}')
        os_RELEASE=$(awk '/VERSION_ID=/' /etc/os-release | sed 's/VERSION_ID=//' | sed 's/\"//g')
    fi
    export os_VENDOR os_RELEASE os_UPDATE os_PACKAGE os_CODENAME
}

function get_distro_short_name {
    if is_redhat; then
        DISTRO_SHORT_NAME="redhat"
    elif is_suse; then
        DISTRO_SHORT_NAME="suse"
    elif is_ubuntu; then
        DISTRO_SHORT_NAME="deb"
    fi
    export DISTRO_SHORT_NAME
}

function get_deployment_services {
    if [[ -z "$DEPLOYMENT_SERVICES" ]]; then
        DEPLOYMENT_SERVICES='stack,ioa'
    fi
    
    ioa_patch_deploy="FALSE"
    ioa_deploy="FALSE"
    stack_deploy="FALSE"

    oldIFS=$IFS
    IFS=", "

    for f in $DEPLOYMENT_SERVICES
    do
        eval ${f}_deploy="TRUE"
    done

    IFS=$oldIFS

    export DEPLOY_SERVICE_STACK=$stack_deploy
    export DEPLOY_SERVICE_IOA=$ioa_deploy
}

function get_stackrc_path {
    echo "$TOP_DIR/ib_stackrc.$DISTRO_SHORT_NAME"
}

# Utility function for checking machine architecture
# is_arch arch-type
function is_arch {
    ARCH_TYPE=$1
    [[ "$(uname -m)" == "$ARCH_TYPE" ]]
}

# Determine if current distribution is a Fedora-based distribution
# (Fedora, RHEL, CentOS, etc).
# is_fedora
function is_redhat {
    if [[ -z "$os_VENDOR" ]]; then
        get_os_version
    fi

    [ "$os_VENDOR" = "Fedora" ] || [ "$os_VENDOR" = "Red Hat" ] || [ "$os_VENDOR" = "CentOS" ]
}


# Determine if current distribution is a SUSE-based distribution
# (openSUSE, SLE).
# is_suse
function is_suse {
    if [[ -z "$os_VENDOR" ]]; then
        get_os_version
    fi

    [ "$os_VENDOR" = "openSUSE" ] || [ "$os_VENDOR" = "SUSE LINUX" ]
}


# Determine if current distribution is an Ubuntu-based distribution
# It will also detect non-Ubuntu but Debian-based distros
# is_ubuntu
function is_ubuntu {
    if [[ -z "$os_PACKAGE" ]]; then
        get_os_version
    fi
    [ "$os_PACKAGE" = "deb" ]
}

function is_service_running {
    service=$1
    is_running=`ps aux | grep -v grep| grep -v .$0. | grep $service| wc -l | awk .{print $1}.`
    if [ $is_running != "0" ] ; then
        return 0
    else
        return 1
    fi
}

function load_custom_config {
    if has_custom_config; then
        source $TOP_DIR/ib_localrc
        echo_indented "$TOP_DIR/ib_localrc has been loaded."
    else
        echo_indented "Not found!"
    fi
}

function has_custom_config {
    if [ -e $TOP_DIR/ib_localrc ]; then
        return 0
    else
        return 1
    fi
}

function has_stack_config {
    stackrc=$(get_stackrc_path)
    if [ -e $stackrc ]; then
        return 0
    else
        return 1
    fi
}

function has_ioa_config {
    if [ -e $TOP_DIR/ib_ioarc ]; then
        return 0
    else
        return 1
    fi
}

function has_patch {
    patch_count=$(ls $TOP_DIR/ib_patch_*.diff | wc -l)
    if [ $patch_count -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# Distro-agnostic function to tell if a package is installed
# is_package_installed package [package ...]
function _is_package_installed {
    if [[ -z "$@" ]]; then
        return 1
    fi

    if [[ -z "$os_PACKAGE" ]]; then
        get_os_version
    fi

    if [[ "$os_PACKAGE" = "deb" ]]; then
        dpkg -s "$@" > /dev/null 2> /dev/null
    elif [[ "$os_PACKAGE" = "rpm" ]]; then
        rpm --quiet -q "$@"
    else
        exit_distro_not_supported "finding if a package is installed"
    fi
}

# Distro-agnostic package uninstaller
# uninstall_package package [package ...]
function _uninstall_package {
    if is_ubuntu; then
        $SUDO apt_get purge "$@"
    elif is_fedora; then
        $SUDO yum remove -y "$@"
    elif is_suse; then
        $SUDO zypper rm "$@"
    else
        exit_distro_not_supported "uninstalling packages"
    fi
}

# Distro-agnostic package installer
# install_package package [package ...]
function _install_package {
    if [[ -z "$@" ]]; then
        echo_indented "No package is specified"
        return 1
    fi
    
    echo "----------------------------------------------------------------------------------"
    local xtrace=$(set +o | grep xtrace)
    set +o xtrace
    
    if is_ubuntu; then
        # if there are transient errors pulling the updates, that's fine. It may
        # be secondary repositories that we don't really care about.
        [[ "$NO_UPDATE_REPOS" = "True" ]] || apt_get update || /bin/true
        NO_UPDATE_REPOS=True
        $xtrace
        apt_get install $@
    elif is_redhat; then
        $xtrace
        yum_install $@
    elif is_suse; then
        $xtrace
        zypper_install $@
    else
        $xtrace
        exit_distro_not_supported "installing packages"
    fi
    
    echo "----------------------------------------------------------------------------------"
    return 0
}

# Wrapper for ``apt-get`` to set cache and proxy environment variables
# Uses globals ``OFFLINE``, ``*_proxy``
# apt_get operation package [package ...]
function apt_get {
    local xtrace=$(set +o | grep xtrace)
    set +o xtrace

    [[ "$OFFLINE" = "True" || -z "$@" ]] && return
    [[ "$(id -u)" = "0" ]] && sudo="env"
    
    DEBIAN_FRONTEND=noninteractive \
        apt-get --option "Dpkg::Options::=--force-confold" --assume-yes \
        install kpartx &> /dev/null || true
        
    $xtrace
    $SUDO $DEBIAN_FRONTEND=noninteractive \
        apt-get --option "Dpkg::Options::=--force-confold" --assume-yes "$@"
}


# Wrapper for ``yum`` to set proxy environment variables
# Uses globals ``OFFLINE``, ``*_proxy``
# yum_install package [package ...]
function yum_install {
    #[[ "$OFFLINE" = "True" ]] && return
    #[[ "$(id -u)" = "0" ]] && sudo="env"

    # The manual check for missing packages is because yum -y assumes
    # missing packages are OK.  See
    # https://bugzilla.redhat.com/show_bug.cgi?id=965567
    $SUDO yum install -y "$@" 2>&1 | \
        awk '
            BEGIN { fail=0 }
            /No package/ { fail=1 }
            { print }
            END { exit fail }' || \
                die $LINENO "Missing packages detected"

    # also ensure we catch a yum failure
    if [[ ${PIPESTATUS[0]} != 0 ]]; then
        die $LINENO "Yum install failure"
    fi
}

# zypper wrapper to set arguments correctly
# zypper_install package [package ...]
function zypper_install {
    [[ "$OFFLINE" = "True" ]] && return
    [[ "$(id -u)" = "0" ]] && sudo="env"
    $SUDO zypper --non-interactive install --auto-agree-with-licenses "$@"
}

# Exit after outputting a message about the distribution not being supported.
# exit_distro_not_supported [optional-string-telling-what-is-missing]
function exit_distro_not_supported {
    if [[ -z "$DISTRO" ]]; then
        get_distro
    fi

    if [ $# -gt 0 ]; then
        die $LINENO "Support for $DISTRO is incomplete: no support for $@"
    else
        die $LINENO "Support for $DISTRO is incomplete."
    fi
}

function get_openstack_release {
    if has_custom_config && [[ -n $OPENSTACK_RELEASE ]]; then
        release=$OPENSTACK_RELEASE
    else
        release=$(prompt_question "Enter OpenStack release name to install: ")
    fi
    
    STACK_RELEASE=`echo $release | tr "[A-Z]" "[a-z]"`
    echo_indented "<$STACK_RELEASE> has been chosen."
    export STACK_RELEASE
}

function disable_network_manager {
    if is_redhat; then
        cmd=`$SUDO chkconfig --list | grep NetworkManager`
        if [ ${#cmd} -gt 0 ] ; then
            chkconfig NetworkManager off
            service NetworkManager stop
            echo_indented "Done!"
        else
            echo_indented "No action required for NetworkManager"
        fi
    elif is_ubuntu; then
        #  need to test
        $SUDO /etc/init.d/network-manager stop
        $SUDO update-rc.d network-manager remove
    elif is_suse; then
        # not sure yet
        $SUDO /etc/init.d/network-manager stop
        $SUDO update-rc.d network-manager remove
    fi
}

function disable_selinux {
    if is_redhat; then
        cmd=`cat /etc/selinux/config | grep SELINUX=disabled`
        if [ ${#cmd} -eq 0 ] ; then
            sed -i 's+SELINUX=enforcing+SELINUX=disabled+' /etc/selinux/config
        else
            echo_indented "No action required for SELINUX"
        fi
    fi
}

function install_packages {
    if [[ -z "$PACKAGES" ]]; then
        echo_indented "PACKAGES parameter is not specified"
        return 1
    fi
    
    # install dependent packages set in ib_stackrc.redhat
    _is_package_installed $PACKAGES || _install_package $PACKAGES
    
    # install ntp and set up
    _is_package_installed ntp || _install_package ntp
    ntpdate -s time.nist.gov
    
    echo "Installing pip..."
    if ! install_pip_packages; then
        echo_indented "Failed to install pip packages!"
        return 1
    fi
    
    echo_indented "Done!"
    return 0
}

function install_dhcp_relay {
    if [[ -d "$DHCP_RELAY_PATH" ]] && [[ -e "$DHCP_RELAY_BIN_PATH/dhclient" ]]; then
        echo_indented "dhcp already installed"
        return 0
    fi

    if ! [[ -e "./$DHCP_RELAY_PACKAGE" ]]; then
        echo_indented "$DHCP_RELAY_PACKAGE does not exist"
        return 1
    fi
    
    echo "----------------------------------------------------------------------------------"
    tar -zxf ./$DHCP_RELAY_PACKAGE
    dirname=`find -maxdepth 1 -type d | grep dhcp`
    pushd $dirname
    $SUDO ./configure --prefix=$DHCP_RELAY_PATH
    $SUDO make
    $SUDO make install
    popd
    echo "----------------------------------------------------------------------------------"
    
   [[ -d "$DHCP_RELAY_PATH" ]] && [[ -e "$DHCP_RELAY_BIN_PATH/dhclient" ]] && return 0 || return 1
}

function install_pip_packages {
    cmd=`which pip 2>&1| grep 'no pip' | wc -c`
    if [ $cmd -gt 0 ]; then
        $SUDO easy_install pip
    fi
   
    $SUDO pip install mysql-python qpid-python
    
    cmd=`which pip 2>&1| grep 'no pip' | wc -c`
    if [ $cmd -gt 0 ]; then
         return 1
    fi
    return 0
}


function add_ioa_neutron_sudoer {
    echo "Installing ioa-neutron sudoer file..."

    SUDOER_FILE="/etc/sudoers.d/ioa-neutron"
    echo "neutron	ALL=(ALL)	NOPASSWD: ALL" > $SUDOER_FILE
    chown root.root $SUDOER_FILE
    chmod u=r,g=r,o= $SUDOER_FILE
}

# SUSE
#   openstack-neutron
#   openstack-neutron-dhcp-agent
#   openstack-neutron-l3-agent
#   openstack-neutron-lbaas-agent
#   openstack-neutron-metadata-agent
#   openstack-neutron-metering-agent
#   openstack-neutron-openvswitch-agent
#
# RHEL
#   neutron-dhcp-agent
#   neutron-l3-agent
#   neutron-lbaas-agent
#   neutron-metadata-agent
#   neutron-openvswitch-agent
#   neutron-server
#   
# RHEL 6.5 and SUSE has startup scripts under /etc/init.d/
# RHSE 7 does not have startup scripts under /etc/init.d/
function restart_neutron_services {
    if is_redhat; then
        neutron_services=`openstack-service list neutron | grep -v cleanup`
    elif is_suse; then
        neutron_services=`$SUDO ls /etc/init.d/ | grep openstack-neutron* | grep -v cleanup`
    else
        neutron_services=`$SUDO ls /etc/init.d/ | grep neutron | grep -v cleanup`
    fi
    
    for i in $neutron_services
    do 
        $SUDO service $i restart
    done
    echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
    
    echo "Checking if neutron services are runnning..."
    sleep 3
    retry_service_restart $neutron_services
    sleep 2
    retry_service_restart $neutron_services
    sleep 2
    show_service_status $neutron_services
    echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
    echo " "
    echo "See if the required services are all running. If the required services are still down, try to reboot the server."
    echo "For example, neutron-lbaas-agent may be shown as 'dead' if load balancing is not turned on."
    echo "A core service like neutron-openvswitch-agent should be shown as 'running' if openvswitch is configured for L2 connectivity."
    echo "You can run 'openstack-status' command to check the running statues of the entire openstack services"
    echo " "
}

function stop_neutron_services {
    if is_redhat; then 
        # since RHEL 7 does not startup scripts, safer to check if neutron-server is installed.
        cmd=`service neutron-server status 2>&1 | egrep "unrecognized service|not-found" | wc -l`
        if [ $cmd -gt 0 ]; then
            $SUDO openstack-service stop neutron
        fi
    elif is_suse; then
        #cmd=`service openstack-neutron status 2>&1 | egrep 'no such service' | wc -l`
        cmd=`$SUDO ls /etc/init.d/openstack-neutron* | wc -l`
        if [ $cmd -gt 0 ]; then
            for i in `ls /etc/init.d/ | grep openstack-neutron`; do $SUDO service $i stop; done
        fi
    else
        cmd=`$SUDO ls /etc/init.d/neutron-* | wc -l`
        if [ $cmd -gt 0 ]; then
            for i in `ls /etc/init.d/ | grep neutron`; do $SUDO service $i stop; done
        fi
    fi
}

function retry_service_restart {
    neutron_services=$@
    retried='FALSE'
    for i in $neutron_services
    do 
        if [[ "$i" = "neutron-lbaas-agent" ]]; then
            continue
        fi
        
        cmd=`$SUDO service $i status | grep running | wc -c`
        if [ $cmd -eq 0 ]; then
            $SUDO service $i restart
            retried='TRUE'
        fi
        sleep 1
    done
    
    if [ $retried = 'TRUE' ]; then
        echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
    fi
}

function show_service_status {
    neutron_services=$@
    for i in $neutron_services
    do
        $SUDO service $i status
    done
}

function check_rsa_key {
    if [ -e "~/.ssh/id_rsa.pub" ]; then
        return 0
    fi
    return 1
}

# Get the default value for HOST_IP
# get_default_host_ip fixed_range floating_range host_ip_iface host_ip
function get_default_host_ip {
    local fixed_range=$1
    local floating_range=$2
    local host_ip_iface=$3
    local host_ip=$4

    # Find the interface used for the default route
    host_ip_iface=${host_ip_iface:-$(ip route | sed -n '/^default/{ s/.*dev \(\w\+\)\s\+.*/\1/; p; }' | head -1)}
    # Search for an IP unless an explicit is set by ``HOST_IP`` environment variable
    if [ -z "$host_ip" -o "$host_ip" == "dhcp" ]; then
        host_ip=""
        host_ips=`LC_ALL=C ip -f inet addr show ${host_ip_iface} | awk '/inet/ {split($2,parts,"/");  print parts[1]}'`
        for IP in $host_ips; do
            # Attempt to filter out IP addresses that are part of the fixed and
            # floating range. Note that this method only works if the ``netaddr``
            # python library is installed. If it is not installed, an error
            # will be printed and the first IP from the interface will be used.
            # If that is not correct set `HOST_IP` in `ib_localrc` to the correct
            # address.
            if ! (address_in_net $IP $fixed_range || address_in_net $IP $floating_range); then
                host_ip=$IP
                break;
            fi
        done
    fi
    echo $host_ip
}

# Exit 0 if address is in network or 1 if address is not in network
# ip-range is in CIDR notation: 1.2.3.4/20
# address_in_net ip-address ip-range
function address_in_net {
    local ip=$1
    local range=$2
    local masklen=${range#*/}
    local network=$(maskip ${range%/*} $(cidr2netmask $masklen))
    local subnet=$(maskip $ip $(cidr2netmask $masklen))
    [[ $network == $subnet ]]
}

function prompt_yesno_question {
    while true; do
        read -p "$1" ans
        case $ans in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

function prompt_question {
    while true; do
        read -p "$1" ans
        if [ ${#ans} -gt 0 ]; then
           break
        fi
    done
    echo $ans
}

function echo_indented {
    if [ -z $2 ]; then
        len=$DEFAULT_MSG_PADDING
    else
        len=$2
    fi
    padding=${2:-$len}
    v=$(printf "%-${padding}s" " ")
    echo "$v $1"
}

function random_string() {
    local len=${1:-5}
    tr -cd '[:alnum:]' < /dev/urandom | fold -w${len} | head -1
}

# Restore xtrace
#$XTRACE
