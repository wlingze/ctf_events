#!/bin/bash

#########################################################################
# File Name: launch.sh
# Created on: 2019-10-02 20:18:17
# Author: raycp
# Last Modified: 2019-10-22 05:21:35
# Description: launch the qemu vm 
#########################################################################

qemu-system-x86_64 \
    -m 512 \
    -kernel ./bzImage \
    -initrd ./core.cpio \
    -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" \
    -nographic \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
