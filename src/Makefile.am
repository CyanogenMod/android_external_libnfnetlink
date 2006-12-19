include $(top_srcdir)/Make_global.am

INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink.la

libnfnetlink_la_LDFLAGS = -Wc,-nostartfiles	\
			  -version-info $(LIBVERSION)
libnfnetlink_la_SOURCES = libnfnetlink.c 
