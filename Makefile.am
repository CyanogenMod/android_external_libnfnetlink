AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

man_MANS =

INCLUDES=-I../include -I/lib/modules/$(shell (uname -r))/build/include
CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink.la

libnfnetlink_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_la_SOURCES = libnfnetlink.c

include_HEADERS = libnfnetlink.h 

man_MANS = #nfnetlink.3 nfnetlink.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
