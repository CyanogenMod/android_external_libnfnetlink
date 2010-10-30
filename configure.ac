dnl Process this file with autoconf to create configure.

AC_INIT(libnfnetlink, 1.0.0)
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects dist-bzip2 1.6])

AC_PROG_CC
AC_EXEEXT
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

case "$host" in 
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac


dnl--------------------------------
dnl--------------------------------


dnl Output the makefile
AC_OUTPUT(Makefile src/Makefile include/Makefile include/libnfnetlink/Makefile utils/Makefile libnfnetlink.pc)
