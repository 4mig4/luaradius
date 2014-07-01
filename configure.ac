#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([luaradius], [0.1.1], [neo.neutron@gmail.com])
AC_CONFIG_SRCDIR([src/lradius.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for libraries.
have_PTHREAD="no"
AC_CHECK_LIB(pthread, pthread_create, have_PTHREAD="yes",
                AC_MSG_ERROR([System does not support POSIX thread])) 

if test "x${have_PTHREAD}" = "xyes"; then
  PTHREAD_LIBS="-lpthread"
fi

have_LIBRADIUS="no"
AC_CHECK_HEADER(freeradius/libradius.h,have_LIBRADIUS="yes",
                AC_MSG_ERROR([cannot find headers for libfreeradius; please install libfreeradius-dev])) 

if test "x${have_LIBRADIUS}" = "xyes"; then
  LIBRADIUS_LDFLAGS="-L${libdir}/freeradius -Wl,-rpath -Wl,${libdir}/freeradius"
  LIBRADIUS_LIBS="-lfreeradius-radius ${PTHREAD_LIBS}"

  AC_SUBST([LIBRADIUS_LDFLAGS])
  AC_SUBST([LIBRADIUS_LIBS])
fi

PKG_CHECK_MODULES([LIBLUA], [lua5.1 >= 5.1.4])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
