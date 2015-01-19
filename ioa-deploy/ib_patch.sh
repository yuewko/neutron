#!/usr/bin/env bash

function run_patches {
    if [ -z "$IB_NEUTRON_PATCH_PATH" ]; then
        IB_NEUTRON_PATCH_PATH=$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)
    fi

    if [ -z "$NEUTRON_PATH" ]; then
         NEUTRON_PATH=$(python -c 'import neutron; print ",".join(neutron.__path__)')
    fi

    if [ -z "$PYTHON_SITE_PACKAGE_PATH" ]; then
        PYTHON_SITE_PACKAGE_PATH=$(dirname ${NEUTRON_PATH})
    fi

    echo_indented "Applying taskflow patch..." 6
    $SUDO cd $PYTHON_SITE_PACKAGE_PATH
    $SUDO patch -p0 -N --dry-run < $IB_NEUTRON_PATCH_PATH/ib_patch_taskflow.diff >/dev/null
    if [ $? -eq 0 ];
    then
        $SUDO patch -p0 -N < $IB_NEUTRON_PATCH_PATH/ib_patch_taskflow.diff
    else
        echo_indented "Patch is already applied. Skipping..." 6
    fi

}

