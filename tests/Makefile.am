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

EXTRA_DIST = packet_roundtrips.sh packet_roundtrips_luks_passphrase \
	packet_roundtrips_luks_symmetric

check_PROGRAMS = packet_roundtrips

TESTS = packet_roundtrips.sh

packet_roundtrips_SOURCES = packet_roundtrips.c
packet_roundtrips_LDADD = $(top_builddir)/lib/libvolume_key.la \
	$(glib_LIBS) $(nss_LIBS)
