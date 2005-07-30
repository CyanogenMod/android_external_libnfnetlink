#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink_log.la libnfnetlink_log_libipulog.la

libnfnetlink_log_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_log_la_SOURCES = libnfnetlink_log.c 

libnfnetlink_log_libipulog_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_log_libipulog_la_SOURCES = libipulog_compat.c
