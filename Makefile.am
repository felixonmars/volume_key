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

# Author: Miloslav Trmač <mitr@redhat.com>])

## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(blkid_CFLAGS) $(glib_CFLAGS) $(GPGME_CFLAGS) $(nss_CFLAGS)
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

TESTS = tests/crypto_roundtrips.sh tests/kmip_roundtrip

EXTRA_DIST = python/volume_key.i \
	tests/crypto_roundtrips.sh \
	tests/kmip_roundtrip_luks_passphrase tests/kmip_roundtrip_luks_symmetric

## Rules
python/volume_key_wrap.c python/volume_key.py: python/volume_key.i
	swig -Wall -python -I$(top_srcdir) -o python/volume_key_wrap.c \
		$(top_srcdir)/python/volume_key.i

python/volume_key.py: python/volume_key_wrap.c

## Dependency data
lib_libvolume_key_la_SOURCES = lib/crypto.c lib/crypto.h lib/kmip.c lib/kmip.h \
	lib/libvolume_key.c lib/libvolume_key.h lib/ui.c lib/ui.h lib/volume.c \
	lib/volume.h lib/volume_luks.c lib/volume_luks.h
lib_libvolume_key_la_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
lib_libvolume_key_la_LDFLAGS = -version-info 0:0:0
lib_libvolume_key_la_LIBADD = $(blkid_LIBS) $(glib_LIBS) $(GPGME_LIBS) \
	$(LTLIBINTL) $(nss_LIBS) -lcryptsetup

python__volume_key_la_SOURCES = python/volume_key_wrap.c
python__volume_key_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS)
python__volume_key_la_LDFLAGS = -module -avoid-version $(glib_LIBS)
python__volume_key_la_LIBADD = lib/libvolume_key.la -lpython$(PYTHON_VERSION)

src_volume_key_SOURCES = src/volume_key.c
src_volume_key_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
src_volume_key_LDADD = lib/libvolume_key.la

tests_kmip_roundtrip_SOURCES = tests/kmip_roundtrip.c
tests_kmip_roundtrip_LDADD = lib/libvolume_key.la
# To make G_GNUC_INTERNAL symbols visible
tests_kmip_roundtrip_LDFLAGS = -static

tests_crypto_roundtrips_SOURCES = tests/crypto_roundtrips.c
tests_crypto_roundtrips_LDADD = lib/libvolume_key.la
# To make G_GNUC_INTERNAL symbols visible
tests_crypto_roundtrips_LDFLAGS = -static

check_PROGRAMS = tests/crypto_roundtrips tests/kmip_roundtrip
