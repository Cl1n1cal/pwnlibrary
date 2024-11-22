#!/bin/bash

if [ -z "$1" ]; then
    echo "usage: ./setup-module <module_name>"
    exit 1
fi

if [ "$1" == "test" ]; then
    make target="$1"
    if [ $? -ne 0 ]; then
        echo "Error: make operation failed for target 'test'"
        exit 1
    fi
    cp init_test ./initramfs/init
    cp test.ko ./initramfs/test.ko
    rm ./initramfs/hackme.ko
    echo "test done"
fi

if [ "$1" == "hackme" ]; then
    make target="$1"
    if [ $? -ne 0 ]; then
        echo "Error: make operation failed for target 'hackme'"
        exit 1
    fi
    cp init_hackme ./initramfs/init
    cp hackme.ko ./initramfs/hackme.ko
    rm ./initramfs/test.ko
    echo "hackme done"
fi

./compress.sh "$2"
