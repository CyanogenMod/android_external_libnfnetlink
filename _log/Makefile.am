AUTOMAKE_OPTIONS = foreign

INCLUDES =$(all_includes) -I$(top_srcdir)/include -I${KERNELDIR}
SUBDIRS	= src utils
DIST_SUBDIRS = src include
LINKOPTS = -lnfnetlink

man_MANS = #nfnetlink_log.3 nfnetlink_log.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
