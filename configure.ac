# Process this file with autoconf to produce a configure script.
AC_INIT([volume_key], [0.3.12], [https://pagure.io/volume_key], ,
        [https://pagure.io/volume_key])
AC_COPYRIGHT(
[Copyright (C) 2009 - 2018 Red Hat, Inc. All rights reserved.
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
AC_PREREQ([2.63b])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([lib/libvolume_key.h])
AC_CONFIG_AUX_DIR([admin])
AM_INIT_AUTOMAKE([no-dist-gzip dist-xz no-define subdir-objects -Wall])

##########################
## Checks for programs. ##
##########################

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT([disable-static])

##
# Check whether to create Python bindings.
withval=""
AC_MSG_CHECKING([whether to create Python 2 bindings])
AC_ARG_WITH([python],
AS_HELP_STRING([--with-python], [enable building Python 2 bindings]),
[use_python="$withval"],
[use_python=auto])
# no, old, yes
python_found=no
if test "x$use_python" = xno; then
    AC_MSG_RESULT([no])
else
    AC_MSG_RESULT([testing])
    # Try to find Python 2 interpreter:
    AC_PATH_PROGS([PYTHON], [python2.7 python2.6 python2.5 python2.4 python], [no])
    if test "x$PYTHON" != xno; then
      # We have Python 2 interpreter, check its version:
      AM_PATH_PYTHON([2.4], [python_found=yes], [python_found=old])
    fi
    __vk_tmp=""
    case x$python_found in
        xold)
            __vk_tmp="Python 2.4 or later"
            ;;
        xno)
            __vk_tmp="Python 2 interpreter"
            ;;
    esac
    if test "x$__vk_tmp" = x; then
        AC_PATH_PROG([PYTHON_CONFIG], [python2-config python-config], [no])
        if test "x${PYTHON_CONFIG}" = xno; then
            __vk_tmp=python2-config
        fi
    fi
    if test "x$__vk_tmp" != x; then
        if test "x$use_python" = xyes; then
            AC_MSG_ERROR([$__vk_tmp is required but not installed])
        else
            AC_MSG_WARN([$__vk_tmp is not found - Python 2 bindings will not be created])
        fi
    else
        PYTHON_INCLUDES=`${PYTHON_CONFIG} --includes 2> /dev/null`
        PYTHON_CFLAGS=`${PYTHON_CONFIG} --cflags 2> /dev/null`
        PYTHON_LIBS=`${PYTHON_CONFIG} --libs 2> /dev/null`
        PYTHON_LDFLAGS=`${PYTHON_CONFIG} --ldflags 2> /dev/null`
        AC_SUBST([PYTHON_INCLUDES])
        AC_SUBST([PYTHON_CFLAGS])
        AC_SUBST([PYTHON_LIBS])
        AC_SUBST([PYTHON_LDFLAGS])
    fi
fi
AM_CONDITIONAL([HAVE_PYTHON], [test x$python_found = xyes])

##
# Check whether to create Python 3 bindings.
withval=""
AC_MSG_CHECKING([whether to use Python 3 bindings])
AC_ARG_WITH([python3],
AS_HELP_STRING([--with-python3], [enable building Python 3 bindings]),
[use_python3="$withval"],
[use_python3=auto])
# no, old, yes
python3_found=no
if test "x$use_python3" = xno; then
    AC_MSG_RESULT([no])
else
    AC_MSG_RESULT([testing])
    # Try to find Python 3 interpreter:
    AC_PATH_PROGS([PYTHON3], [python3.6 python3.5 python3 python], [no])
    if test "x$PYTHON3" != xno; then
        AC_MSG_CHECKING([whether $PYTHON3 version is >= 3.5])
        python3_found=old
        __vk_tmp=`${PYTHON3} -c 'import sys; sys.stdout.write(repr(sys.version_info.major))'`; __vk_ec=$?
        test x$__vk_ec = x0 || __vk_tmp=0
        if test $__vk_tmp -ge 3; then
            __vk_tmp=`${PYTHON3} -c 'import sys; sys.stdout.write(repr(sys.version_info.minor))'`; __vk_ec=$?
            test x$__vk_ec = x0 || __vk_tmp=0
            if test $__vk_tmp -ge 5; then
                python3_found=yes
            fi
        fi
        if test x$python3_found = xyes; then
            AC_MSG_RESULT([yes])
        elif test x$__vk_tmp = x0; then
            AC_MSG_RESULT([no])
        else
            AC_MSG_RESULT([error])
        fi
    fi
    __vk_tmp=""
    case x$python3_found in
        xold)
            __vk_tmp="Python 3.5 or later"
            ;;
        xno)
            __vk_tmp="Python 3 interpreter"
            ;;
    esac
    if test "x$__vk_tmp" = x; then
        AC_PATH_PROG([PYTHON3_CONFIG], [python3-config], [no])
        if test "x${PYTHON3_CONFIG}" = xno; then
            __vk_tmp=python3-config
        fi
    fi
    if test "x$__vk_tmp" != x; then
        if test "x$use_python3" = xyes; then
            AC_MSG_ERROR([$__vk_tmp is required but not installed])
        else
            AC_MSG_WARN([$__vk_tmp is not found - Python 3 bindings will not be created])
        fi
    else
        # PYTHON3_VERSION:
        AC_MSG_CHECKING([for $PYTHON3 version])
        PYTHON3_VERSION=`${PYTHON3} -c "import sys; sys.stdout.write(sys.version[[:3]])"`
        AC_MSG_RESULT([$PYTHON3_VERSION])
        AC_SUBST([PYTHON3_VERSION])
        # PYTHON3_PREFIX:
        AC_SUBST([PYTHON3_PREFIX], ['${prefix}'])
        # PYTHON3_EXEC_PREFIX:
        AC_SUBST([PYTHON3_EXEC_PREFIX], ['${exec_prefix}'])
        # PYTHON3_PLATFORM:
        AC_MSG_CHECKING([for $PYTHON3 platform])
        PYTHON3_PLATFORM=`${PYTHON3} -c "import sys; sys.stdout.write(sys.platform)"`
        AC_MSG_RESULT([$PYTHON3_PLATFORM])
        AC_SUBST([PYTHON3_PLATFORM])
        # python3dir, pkgpython3dir:
        AC_MSG_CHECKING([for $PYTHON3 script directory])
        PYTHON3_PYTHONDIR=`${PYTHON3} -c "import sys; from distutils import sysconfig; sys.stdout.write(sysconfig.get_python_lib(0, 0, prefix='$PYTHON3_PREFIX'))"`
        AC_MSG_RESULT([$PYTHON3_PYTHONDIR])
        AC_SUBST([python3dir], [$PYTHON3_PYTHONDIR])
        AC_SUBST([pkgpython3dir], [\${python3dir}/$PACKAGE])
        # py3execdir, pkgpy3execdir:
        AC_MSG_CHECKING([for $PYTHON3 extension module directory])
        PYTHON3_PYEXECDIR=`${PYTHON3} -c "import sys; from distutils import sysconfig; sys.stdout.write(sysconfig.get_python_lib(1, 0, prefix='$PYTHON3_EXEC_PREFIX'))"`
        AC_MSG_RESULT([$PYTHON3_PYEXECDIR])
        AC_SUBST([py3execdir], [$PYTHON3_PYEXECDIR])
        AC_SUBST([pkgpy3execdir], [\${py3execdir}/$PACKAGE])
        # PYTHON3_{INCLUDES,CFLAGS,LIBS,LDFLAGS}
        PYTHON3_INCLUDES=`${PYTHON3_CONFIG} --includes 2> /dev/null`
        PYTHON3_CFLAGS=`${PYTHON3_CONFIG} --cflags 2> /dev/null`
        PYTHON3_LIBS=`${PYTHON3_CONFIG} --libs 2> /dev/null`
        PYTHON3_LDFLAGS=`${PYTHON3_CONFIG} --ldflags 2> /dev/null`
        AC_SUBST([PYTHON3_INCLUDES])
        AC_SUBST([PYTHON3_CFLAGS])
        AC_SUBST([PYTHON3_LIBS])
        AC_SUBST([PYTHON3_LDFLAGS])
    fi
fi
AM_CONDITIONAL([HAVE_PYTHON3], [test x$python3_found = xyes])

AC_PATH_PROG([GPG], [gpg2])
AC_ARG_VAR([GPG])
AC_DEFINE_UNQUOTED([GPG_PATH], "$GPG", [Path to the gpg2 executable])

# Checks for libraries.
PKG_CHECK_MODULES(blkid, [blkid])
PKG_CHECK_MODULES(glib, [glib-2.0])
AC_DEFINE(G_DISABLE_DEPRECATED, 1,
	  [Stay away from deprecated glib functionality.])
PKG_CHECK_MODULES(libcryptsetup, [libcryptsetup])
PKG_CHECK_MODULES(nss, [nss])

AM_PATH_GPGME

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.2])
AC_DEFINE([GETTEXT_PACKAGE], ["volume_key"], [Package name for <gi18n-lib.h>])

# Checks for header files.

# Checks for types.

# Checks for structures.

# Checks for compiler charateristics.

# Checks for library functions.

# Checks for system services.
dnl We don't use off_t, but gpgme requires this.
AC_SYS_LARGEFILE

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
AC_CONFIG_FILES([Makefile contrib/Makefile doc/Makefile lib/Makefile po/Makefile.in python/Makefile python/python/Makefile python/python3/Makefile src/Makefile tests/Makefile])
AC_OUTPUT
