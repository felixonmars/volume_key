#! /bin/sh
# Packet encoding round-trip (encode/decode) tests.

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

workdir=$(pwd)/test_files

trap 'status=$?; rm -rf "$workdir"; exit $status' 0
trap '(exit 1); exit 1' 1 2 13 15

srcdir=$(cd "$srcdir"; pwd)

rm -rf "$workdir"
mkdir "$workdir"

mkdir "$workdir/nss_db"

echo nss_pw > "$workdir/pass_file"
certutil -d "$workdir/nss_db" -N -f "$workdir/pass_file"

certutil -d "$workdir/nss_db" -S -f "$workdir/pass_file" -n my_cert \
	-s 'CN=recipient' -t TCu,TCu,TCu -x < /dev/urandom
certutil -d "$workdir/nss_db" -L -a -n my_cert > "$workdir/cert.pem"

(cd "$workdir"; ../packet_roundtrips)
