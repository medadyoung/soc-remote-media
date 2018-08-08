#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Remote-Media-server], [1.0], [ctcchien@nuvoton.com])
AC_CONFIG_SRCDIR([remote-media-server.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE



# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES(GnuTLS, [gnutls >= 2.12.0],[HAVE_GNUTLS=1],[HAVE_GNUTLS=0])
if test x$HAVE_GNUTLS = x1; then
	AC_DEFINE(HAVE_GNUTLS, 1, [Define to 1 if you have a GnuTLS version of 2.12 or above])
else
	AC_DEFINE(HAVE_GNUTLS, 0)
fi
AM_CONDITIONAL([GNUTLS], [test "x$HAVE_GNUTLS" = "x1"])


AH_TEMPLATE(HAVE_PAM, [Build for LINUX PAM])
AC_ARG_WITH(pam,
        [  --without-pam         disable pam],
        , [ with_pam=yes ])
if test "x$with_pam" = "xyes"; then
        AC_DEFINE(HAVE_PAM)
fi

AM_CONDITIONAL([HAVE_PAM], [test "x$with_pam" = "xyes"])

AS_ECHO(["with_pam = $with_pam"])

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdlib.h string.h strings.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([bzero inet_ntoa socket strerror])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
