AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

man_MANS =

INCLUDES=-I../include -I/lib/modules/$(shell (uname -r))/build/include
CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libctnetlink.la

libctnetlink_la_LDFLAGS = -Wc,-nostartfiles
libctnetlink_la_SOURCES = libctnetlink.c

include_HEADERS = libctnetlink.h 

man_MANS = #ctnetlink.3 ctnetlink.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
