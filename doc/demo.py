# A partial reimplementation of volume_key to demonstrate of the Python bindings
# coding=utf-8

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

from __future__ import with_statement

import getpass
import locale
import optparse
import re
import sys

import nss.nss
import nss.ssl
import volume_key

 # General utilities

def yes_or_no(question):
    re_yes = re.compile(locale.nl_langinfo(locale.YESEXPR))
    re_no = re.compile(locale.nl_langinfo(locale.NOEXPR))
    while True:
        buf = raw_input('%s (y/n) ' % question)
        if re_yes.match(buf):
            return True
        if re_no.match(buf):
            return False

 # Options

options = None
args = None

def parse_options (argv):
    global options

    parser = optparse.OptionParser(description='Manages encrypted volume keys '
                                   'and passphrases.')
    parser.add_option('--version', action='store_true', dest='mode_version',
                      help='Show version')
    parser.add_option('--save', action='store_true', dest='mode_save',
                      help='Save volume secrets to a packet.  Expects operands '
                      'VOLUME [PACKET].')
    parser.add_option('--restore', action='store_true', dest='mode_restore',
                      help='Restore volume secrets from a packet.  Expects '
                      'operands VOLUME PACKET.')
    parser.add_option('--setup-volume', action='store_true',
                      dest='mode_setup_volume',
                      help='Set up an encrypted volume using secrets from a '
                      'packet.  Expects operands VOLUME PACKET NAME.')
    parser.add_option('--reencrypt', action='store_true', dest='mode_reencrypt',
                      help='Re-encrypt an escrow packet.  Expects operand '
                      'PACKET.')
    parser.add_option('--dump', action='store_true', dest='mode_dump',
                      help='Show information contained in a packet.  Expects '
                      'operand PACKET.')
    parser.add_option('--secrets', action='store_true', dest='mode_secrets',
                      help='Show secrets contained in a packet.  Expects '
                      'operand PACKET.')
    parser.add_option('-d', '--nss-dir', dest='nss_dir',
                      help='Use the NSS database in DIR', metavar='DIR')
    # Not implemented
    parser.add_option('-b', '--batch', action='store_true', dest='batch_mode',
                      help='Run in batch mode')
    parser.add_option('-o', '--output', dest='output_default',
                      help='Write the default secret to PACKET',
                      metavar='PACKET')
    parser.add_option('--output-data-encryption-key',
                      dest='output_data_encryption_key',
                      help='Write data encryption key to PACKET',
                      metavar='PACKET')
    parser.add_option('--output-passphrase', dest='output_passphrase',
                      help='Write passphrase to PACKET', metavar='PACKET')
    parser.add_option('--create-random-passphrase',
                      dest='output_created_random_passphrase',
                      help='Create a random passphrase and write it to PACKET',
                      metavar='PACKET')
    parser.add_option('--unencrypted-yes-really', action='store_true',
                      dest='output_format_cleartext')
    parser.add_option('-c', '--certificate', dest='output_certificate',
                      help='Encrypt for the certificate in CERT',
                      metavar='CERT')
    parser.add_option('--with-secrets', action='store_true',
                      dest='dump_with_secrets',
                      help='Include secrets in --dump output')
    (options, argv) = parser.parse_args()

    if options.mode_version:
        print 'Python demo 0.0'
        print ('Copyright (C) 2009 Red Hat, Inc. All rights reserved.\n'
               'This software is distributed under the GPL v.2.\n'
               '\n'
               'This program is provided with NO WARRANTY, to the extent '
               'permitted by law.')
        sys.exit()

    c = sum([1 for n in ('mode_save', 'mode_restore', 'mode_setup_volume',
                         'mode_reencrypt', 'mode_dump', 'mode_secrets')
             if getattr(options, n)])
    if c == 0:
        sys.exit('Operation mode not specified')
    if c != 1:
        sys.exit('Ambiguous operation mode')

    if options.dump_with_secrets and not options.mode_dump:
        sys.exit("`--%s' is only valid with `--%s'" % ('with-secrets', 'dump'))
    if not options.mode_save and not options.mode_reencrypt:
        if (options.output_default is not None or
            options.output_data_encryption_key is not None or
            options.output_passphrase is not None or
            options.output_format_cleartext or
            options.output_certificate is not None):
            sys.exit("Output can be specified only with `--save' or "
                     "`--reencrypt'")
    else:
        if (options.output_default is None and
            options.output_data_encryption_key is None and
            options.output_passphrase is None and
            options.output_created_random_passphrase is None):
            sys.exit('No output specified')
        if (options.output_format_cleartext and
            options.output_certificate is not None):
            sys.exit("Ambiguous output format")
    if (options.output_created_random_passphrase is not None and
        not options.mode_save):
        sys.exit("`--%s' is only valid with `--%s'" %
                 ('create-random-passphrase', 'save'))
    return argv



def nss_password_fn (slot, retry):
    if retry:
        sys.stderr.write('Error, try again.\n')
    return getpass.getpass("Enter password for `%s': " % slot.token_name,
                           sys.stderr)

def generic_ui_cb(prompt, echo):
    if not echo:
        s = getpass.getpass('%s: ' % prompt)
        if s == '':
            return None
        return s
    else:
        s = raw_input('%s: ' % prompt)
        if s == '':
            return None
        return s

def passphrase_ui_cb(prompt, unused_failed_attempts):
    s = getpass.getpass('%s: ' % prompt)
    if s == '':
        return None
    return s

def create_ui():
    ui = volume_key.UI()
    ui.generic_cb = generic_ui_cb
    ui.passphrase_cb = passphrase_ui_cb
    return ui

 # Operation implementations

def open_packet_file(filename, ui):
    with open(filename, 'rb') as f:
        packet = f.read()
    return volume_key.Packet.open(packet, ui)

class PacketOutputState(object):
    def __init__(self):
        self.cert = None
        self.passphrase = None
        if options.output_format_cleartext:
            pass
        elif options.output_certificate:
            with open(options.output_certificate, 'rb') as f:
                self.cert = f.read()
        else:
            failed = 0
            while True:
                passphrase = passphrase_ui_cb('New packet passphrase'
                                              if failed == 0
                                              else 'Passphrases do not '
                                              'match.  New packet passphrase',
                                              failed)
                if passphrase is None:
                    sys.exit('')
                passphrase2 = passphrase_ui_cb('Repeat new packet passphrase',
                                               failed)
                if passphrase is None:
                    sys.exit('')
                if passphrase == passphrase2:
                    break
                failed += 1
            self.passphrase = passphrase

    def write_packet(self, filename, vol, secret_type, ui):
        if options.output_format_cleartext:
            packet = vol.create_packet_cleartext(secret_type)
        elif options.output_certificate is not None:
            packet = vol.create_packet_assymetric_from_cert_data(secret_type,
                                                                 self.cert, ui)
        else:
            packet = vol.create_packet_with_passphrase(secret_type,
                                                       self.passphrase)
        # This is not atomic
        with open(filename, 'wb') as f:
            f.write(packet)

    def output_packet(self, vol, ui):
        if options.output_default:
            self.write_packet(options.output_default, vol,
                              volume_key.SECRET_DEFAULT, ui)
        if options.output_data_encryption_key:
            self.write_packet(options.output_data_encryption_key, vol,
                              volume_key.SECRET_DATA_ENCRYPTION_KEY, ui)
        if options.output_passphrase:
            self.write_packet(options.output_passphrase, vol,
                              volume_key.SECRET_PASSPHRASE, ui)

def do_save(argv):
    if len(argv) < 1 or len(argv) > 2:
        sys.exit('Usage: %s --save VOLUME [PACKET]' % sys.argv[0])

    v = volume_key.Volume.open(argv[0])

    ui = create_ui()
    if len(argv) == 2:
        pack = open_packet_file(argv[1], ui)
        v.load_packet(pack)
    else:
        v.get_secret(volume_key.SECRET_DEFAULT, ui)

    pos = PacketOutputState()
    pos.output_packet(v, ui)
    if options.output_created_random_passphrase:
        PASSPHRASE_LENGTH = 8
        rnd = nss.nss.generate_random(PASSPHRASE_LENGTH)
        charset = '0123456789zbcdefghijklmnopqrstuvwxyz'
        passphrase = ''.join([charset[c % len(charset)] for c in rnd])
        v.add_secret(volume_key.SECRET_PASSPHRASE, passphrase)
        pos.write_packet(options.output_created_random_passphrase, v,
                         volume_key.SECRET_PASSPHRASE, ui)

def packet_matches_volume(packet, vol, packet_filename, vol_filename):
    (r, warnings) = packet.packet_match_volume(vol)
    if r == volume_key.PACKET_MATCH_OK:
        return True
    if r == volume_key.PACKET_MATCH_UNSURE:
        sys.stderr.write("`%s' perhaps does not match `%s'\n" %
                         (packet_filename, vol_filename))
        for s in warnings:
            sys.stderr.write('  %s\n' % s)
        return yes_or_no('Are you sure you want to use this packet?')

def do_restore(argv):
    if len(argv) != 2:
        sys.exit('Usage: %s --restore VOLUME PACKET' % sys.argv[0])

    v = volume_key.Volume.open(argv[0])

    ui = create_ui()
    pack = open_packet_file(argv[1], ui)
    if not packet_matches_volume(pack, v, argv[1], argv[0]):
        sys.exit('')

    v.apply_packet(pack, volume_key.SECRET_DEFAULT, ui)

def do_setup_volume(argv):
    if len(argv) != 3:
        sys.exit('Usage: %s --setup-volume VOLUME PACKET NAME' % sys.argv[0])

    v = volume_key.Volume.open(argv[0])

    ui = create_ui()
    pack = open_packet_file(argv[1], ui)
    if not packet_matches_volume(pack, v, argv[1], argv[0]):
        sys.exit('')

    v.open_with_packet(pack, argv[2])

def do_reencrypt(argv):
    if len(argv) != 1:
        sys.exit('Usage: %s --reencrypt PACKET' % sys.argv[0])

    ui = create_ui()
    pack = open_packet_file(argv[0], ui)

    pos = PacketOutputState()
    pos.output_packet(pack, ui)

def do_dump(argv):
    if len(argv) != 1:
        sys.exit('Usage: %s --%s PACKET' %
                 (sys.argv[0], 'dump' if options.mode_dump else 'secrets'))

    with open(argv[0], 'rb') as f:
        packet = f.read()

    f = volume_key.Packet.get_format(packet)
    if f == volume_key.PACKET_FORMAT_CLEARTEXT:
        format = 'Unencrypted'
    elif f == volume_key.PACKET_FORMAT_ASSYMETRIC:
        format = 'Public key-encrypted'
    elif f == volume_key.PACKET_FORMAT_PASSPHRASE:
        format = 'Passphrase-encrypted'
    else:
        assert False
    if options.mode_dump:
        print 'Packet format:\t%s' % format

    ui = create_ui()
    pack = volume_key.Packet.open(packet, ui)

    for prop in pack.dump_properties(options.mode_secrets or
                                     options.dump_with_secrets):
        if not options.mode_secrets or prop.type == volume_key.VP_SECRET:
            print '%s:\t%s' % (prop.label, prop.value)

def main(argv):
    locale.setlocale(locale.LC_ALL, '')

    argv = parse_options (argv)

    nss.nss.set_password_callback(nss_password_fn)
    if options.nss_dir is None:
        sys.exit('NSS without database not supported by python-nss')
    nss.ssl.nssinit(options.nss_dir)
    volume_key.libvk_init()

    if options.mode_save:
        do_save(argv)
    elif options.mode_restore:
        do_restore(argv)
    elif options.mode_setup_volume:
        do_setup_volume(argv)
    elif options.mode_reencrypt:
        do_reencrypt(argv)
    elif options.mode_dump or options.mode_secrets:
        do_dump(argv)
    else:
        assert False

if __name__ == '__main__':
    main(sys.argv)
