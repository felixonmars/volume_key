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

VERSION_INFO = 3:3:2

lib_LTLIBRARIES = libvolume_key.la
pkginclude_HEADERS = libvolume_key.h

libvolume_key_la_SOURCES = SECerrs.h SSLerrs.h \
	crypto.c crypto.h \
	kmip.c kmip.h \
	libvolume_key.c libvolume_key.h \
	nss_error.c nss_error.h \
	ui.c ui.h \
	volume.c volume.h \
	volume_luks.c volume_luks.h
libvolume_key_la_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
libvolume_key_la_LDFLAGS = -version-info $(VERSION_INFO)
libvolume_key_la_LIBADD = $(blkid_LIBS) $(glib_LIBS) $(GPGME_LIBS) \
	$(LTLIBINTL) $(libcryptsetup_LIBS) $(nss_LIBS)
