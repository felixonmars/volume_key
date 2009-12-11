# Process this file with autoconf to produce a configure script.
AC_INIT([volume_key], [0.3.1], [mitr@redhat.com])
AC_COPYRIGHT(
[Copyright (C) 2009 Red Hat, Inc. All rights reserved.
This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301, USA.

Author: Miloslav Trmač <mitr@redhat.com>])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([lib/libvolume_key.h])
AC_CONFIG_AUX_DIR([admin])
AM_INIT_AUTOMAKE([dist-bzip2 no-define subdir-objects -Wall])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT([disable-static])
AM_PATH_PYTHON

dnl Not gpg2, it cannot receive passphrases from gpgme
AC_PATH_PROG([GPG], [gpg])
AC_ARG_VAR([GPG])
AC_DEFINE_UNQUOTED([GPG_PATH], "$GPG", [Path to the gpg executable])

# Checks for libraries.
PKG_CHECK_MODULES(blkid, [blkid])
PKG_CHECK_MODULES(glib, [glib-2.0])
AC_DEFINE(G_DISABLE_DEPRECATED, 1,
	  [Stay away from deprecated glib functionality.])
PKG_CHECK_MODULES(libcryptsetup, [libcryptsetup])
PKG_CHECK_MODULES(nss, [nss])

AM_PATH_GPGME

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.17])
AC_DEFINE([GETTEXT_PACKAGE], ["volume_key"], [Package name for <gi18n-lib.h>])

# Checks for header files.

# Checks for types.

# Checks for structures.

# Checks for compiler charateristics.

# Checks for library functions.

# Checks for system services.

# Miscellaneous hackery.

# Modify CFLAGS after all tests are run (some of them could fail because
# of the -Werror).
if test "$GCC" = yes ; then
    AC_CACHE_CHECK([for available GCC warning flags],
		   [mitr_cv_prog_gcc_warnings],
    [mitr_cv_prog_gcc_warnings=""
    for i in -Wall -W -Wcast-align -Wmissing-noreturn -Wnested-externs dnl
-Wpointer-arith -Wshadow -Wundef -Wwrite-strings; do
        oldcflags=$CFLAGS
        CFLAGS="$CFLAGS $i"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
		[mitr_cv_prog_gcc_warnings="$mitr_cv_prog_gcc_warnings $i"])
	CFLAGS=$oldcflags
     done])
     CFLAGS="$CFLAGS $mitr_cv_prog_gcc_warnings"
     AC_MSG_CHECKING([whether we should use -Werror])
     AC_ARG_ENABLE([Werror],
		   AS_HELP_STRING([--enable-Werror],
			[use -Werror if compiling with gcc (default is NO)]),
		   [], enable_Werror=no)
     if test "x$enable_Werror" != xno; then
	CFLAGS="$CFLAGS -Werror"
     fi
     AC_MSG_RESULT([$enable_Werror])
fi

dnl po/Makefile
AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
