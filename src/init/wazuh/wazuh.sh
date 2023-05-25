#!/bin/sh

#Copyright (C) 2015, Wazuh Inc.
# Install functions for Wazuh
# Wazuh.com (https://github.com/wazuh)

patch_version(){
    echo "########### JNote : running on wazuh.sh : patch_version() ###########"

    rm -rf $PREINSTALLEDDIR/etc/shared/ssh > /dev/null 2>&1
}
WazuhSetup(){
    patch_version
}
