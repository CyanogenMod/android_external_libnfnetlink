AUTOMAKE_OPTIONS = no-dependencies foreign

EXTRA_DIST = $(man_MANS) acinclude.m4

SUBDIRS = src include
DIST_SUBDIRS = src include

man_MANS = #nfnetlink.3

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
