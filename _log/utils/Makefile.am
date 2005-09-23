INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 

bin_PROGRAMS = nfulnl_test ulog_test

nfulnl_test_SOURCES = nfulnl_test.c
nfulnl_test_LDADD = ../src/libnfnetlink_log.la
nfulnl_test_LDFLAGS = -dynamic
#nfulnl_test_LDFLAGS = $(all_libraries) -lnfnetlink_log

ulog_test_SOURCES = ulog_test.c
ulog_test_LDADD = ../src/libnfnetlink_log_libipulog.la ../src/libnfnetlink_log.la
ulog_test_LDFLAGS = -dynamic
#ulog_test_LDFLAGS = $(all_libraries) -lnfnetlink_log_libipulog -lnfnetlink_log


