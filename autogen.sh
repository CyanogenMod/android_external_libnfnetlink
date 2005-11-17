#!/bin/sh

include ()
{
    # If we keep a copy of the kernel header in the SVN tree, we'll have
    # to worry about synchronization issues forever. Instead, we just copy 
    # the headers that we need from the lastest kernel version at autogen
    # stage.

    INCLUDEDIR=${KERNEL_DIR:-/lib/modules/`uname -r`/build}/include/linux

    if [ -f $INCLUDEDIR/netfilter/nfnetlink.h ]
    then
    	TARGET=include/libnfnetlink/linux_nfnetlink.h
    	echo "Copying nfnetlink.h to linux_nfnetlink.h"
    	cp $INCLUDEDIR/netfilter/nfnetlink.h $TARGET
    else
    	echo "can't find nfnetlink.h kernel file in $INCLUDEDIR"
    	exit 1
    fi
}

run ()
{
    echo "running: $*"
    eval $*

    if test $? != 0 ; then
	echo "error: while running '$*'"
	exit 1
    fi
}

include
run aclocal
#run autoheader
run libtoolize -f
run automake -a
run autoconf
