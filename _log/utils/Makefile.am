bin_PROGRAMS = nfulnl_test ulog_test
nfulnl_test_SOURCES = nfulnl_test.c
ulog_test_SOURCES = ulog_test.c


INCLUDES = $(all_includes) -I$(top_srcdir)/include -I${KERNELDIR} 

nfulnl_test_LDFLAGS = $(all_libraries) -lnfnetlink_log
ulog_test_LDFLAGS = $(all_libraries) -lnfnetlink_log_libipulog -lnfnetlink_log

