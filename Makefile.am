# Copyright (C) 2009 Red Hat, Inc. All rights reserved.
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

## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(blkid_CFLAGS) $(glib_CFLAGS) $(GPGME_CFLAGS) \
	$(libcryptsetup_CFLAGS) $(nss_CFLAGS)
LOCALEDIR_CPPFLAGS = -DLOCALEDIR='"$(localedir)"'
PYTHON_CPPFLAGS = -I/usr/include/python$(PYTHON_VERSION)

## Targets
SUBDIRS = po

bin_PROGRAMS = src/volume_key
dist_man_MANS = doc/volume_key.8

lib_LTLIBRARIES = lib/libvolume_key.la
pkginclude_HEADERS = lib/libvolume_key.h

pyexec_PYTHON = python/volume_key.py
pyexec_LTLIBRARIES = python/_volume_key.la

TESTS = tests/packet_roundtrips.sh

EXTRA_DIST = python/volume_key.i \
	tests/packet_roundtrips.sh tests/packet_roundtrips_luks_passphrase \
	tests/packet_roundtrips_luks_symmetric

## Rules
python/volume_key_wrap.c python/volume_key.py: python/volume_key.i
	swig -Wall -python -I$(top_srcdir) -o python/volume_key_wrap.c \
		$(top_srcdir)/python/volume_key.i

python/volume_key.py: python/volume_key_wrap.c

## Dependency data
lib_libvolume_key_la_SOURCES = lib/SECerrs.h \
	lib/crypto.c lib/crypto.h \
	lib/kmip.c lib/kmip.h \
	lib/libvolume_key.c lib/libvolume_key.h \
	lib/nss_error.c lib/nss_error.h \
	lib/ui.c lib/ui.h \
	lib/volume.c lib/volume.h lib/volume_luks.c lib/volume_luks.h
lib_libvolume_key_la_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
lib_libvolume_key_la_LDFLAGS = -version-info 2:1:1
lib_libvolume_key_la_LIBADD = $(blkid_LIBS) $(glib_LIBS) $(GPGME_LIBS) \
	$(LTLIBINTL) $(libcryptsetup_LIBS) $(nss_LIBS)

python__volume_key_la_SOURCES = python/volume_key_wrap.c
python__volume_key_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS)
python__volume_key_la_LDFLAGS = -module -avoid-version $(glib_LIBS)
python__volume_key_la_LIBADD = lib/libvolume_key.la -lpython$(PYTHON_VERSION) \
	$(glib_LIBS) $(nss_LIBS)

src_volume_key_SOURCES = src/volume_key.c
src_volume_key_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
src_volume_key_LDADD = lib/libvolume_key.la $(glib_LIBS) $(nss_LIBS)

tests_packet_roundtrips_SOURCES = tests/packet_roundtrips.c
tests_packet_roundtrips_LDADD = lib/libvolume_key.la $(glib_LIBS) $(nss_LIBS)

check_PROGRAMS = tests/packet_roundtrips
