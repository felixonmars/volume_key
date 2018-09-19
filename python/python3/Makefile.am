# Copyright (C) 2009 - 2018 Red Hat, Inc. All rights reserved.
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301, USA.

# Author: Miloslav Trmač <mitr@redhat.com>
#         Jiří Kučera <jkucera@redhat.com>

## Process this file with automake to produce Makefile.in
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(blkid_CFLAGS) $(glib_CFLAGS) $(GPGME_CFLAGS) \
	$(libcryptsetup_CFLAGS) $(nss_CFLAGS)
LOCALEDIR_CPPFLAGS = -DLOCALEDIR='"$(localedir)"'

SWIG_FLAGS = -python -py3 -modern
SWIG_INCLUDES = -I$(top_srcdir) $(PYTHON3_INCLUDES)
PYTHON = $(PYTHON3)

py3exec_PYTHON = volume_key.py
py3exec_LTLIBRARIES = _volume_key.la

_volume_key_la_SOURCES = volume_key_wrap.c
_volume_key_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON3_CFLAGS)
_volume_key_la_LDFLAGS = -module -avoid-version $(glib_LIBS) $(PYTHON3_LDFLAGS)
_volume_key_la_LIBADD = $(top_builddir)/lib/libvolume_key.la $(PYTHON3_LIBS) \
	$(glib_LIBS) $(nss_LIBS)

volume_key_wrap.c volume_key.py: ../volume_key.i
	swig -Wall $(SWIG_FLAGS) $(SWIG_INCLUDES) -o volume_key_wrap.c \
	$(top_srcdir)/python/volume_key.i

volume_key.py: volume_key_wrap.c
