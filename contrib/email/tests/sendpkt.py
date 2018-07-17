#!/usr/bin/python3
#                                                         -*- coding: utf-8 -*-
# Send an escrow packet.
#
# Copyright (C) 2018 Jiří Kučera <jkucera@redhat.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#
"""Send an escrow packet"""

import sys
import os
import argparse
import hashlib
import smtplib
import email

def wout(fmt, *args):
    sys.stdout.write(fmt.format(*args))

def perror(fmt, *args):
    sys.stderr.write("{}\n".format(fmt.format(*args)))

def getemail(sender):
    parts = [p for p in sender.split() if p]
    if parts and parts[-1].startswith('<') and parts[-1].endswith('>'):
        return parts[-1][1:-1]
    return sender

def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "-s", "--subject", metavar='SUBJECT',
        default="Escrow packet",
        help="a subject of e-mail"
    )
    parser.add_argument(
        "-f", "--from", metavar='SENDER', required=True, dest='sender',
        help="an address of sender"
    )
    parser.add_argument(
        "-t", "--to", metavar='RECIPIENT', required=True,
        action='append', default=[], dest='recipients',
        help="addresses of recipients"
    )
    parser.add_argument(
        "-p", "--packet", metavar='PATH', required=True,
        help="a path to file with escrow packet"
    )
    parser.add_argument(
        "-d", "--dump",
        action='store_true', default=False,
        help="dump e-mail to the file (do not send it); " \
             "if --output is not provided, use stdout"
    )
    parser.add_argument(
        "-o", "--output", metavar='PATH',
        default="",
        help="set the output for --dump (no output means stdout)"
    )
    parser.add_argument(
        "-b", "--binary",
        action='store_true', default=False,
        help="e-mail will be dumped as binary"
    )
    parser.add_argument(
        "-v", "--verbose",
        action='store_true', default=False,
        help="be verbose"
    )
    parser.add_argument(
        "-H", "--host", metavar="HOST[:PORT]",
        default="localhost:25",
        help="set the SMTP server host name and port"
    )
    return parser.parse_args(args=argv)

def parse_host(host):
    h_p = host.split(':')
    if len(h_p) == 1:
        h_p.append('25')
    assert len(h_p) == 2, "Invalid SMTP host ({}).".format(host)
    h, p = h_p
    assert len(h) > 0 and len(p) > 0, "Invalid SMTP host ({}).".format(host)
    try:
        p = int(p)
    except ValueError:
        raise Exception("Nonnumeric port ({}).".format(p))
    assert p >= 0, "Negative port ({}).".format(p)
    return h, p

def verify_args(args):
    assert len(args.subject) > 0, "Missing subject."
    assert len(args.sender) > 0, "Missing sender."
    assert len(args.recipients) > 0, "No recipients."
    assert len(args.packet) > 0, "Missing path to escrow packet file."
    args.host = "{}:{}".format(*parse_host(args.host))

def main(argv):
    try:
        args = parse_args(argv)
        verify_args(args)
        msg = email.message.EmailMessage()
        msg['Subject'] = args.subject
        msg['From'] = args.sender
        msg['To'] = ', '.join(args.recipients)
        with open(args.packet, 'rb') as f:
            data = f.read()
        msg.set_content("packet from: {}\nMD5 checksum: {}\n".format(
            getemail(args.sender), hashlib.md5(data).hexdigest()
        ))
        msg.add_attachment(
            data,
            maintype='application',
            subtype='octet-stream',
            filename=os.path.basename(args.packet)
        )
        if args.dump:
            mode = 'w'
            if args.binary:
                mode += 'b'
            if len(args.output) > 0:
                with open(args.output, mode) as f:
                    if args.binary:
                        f.write(msg.as_bytes())
                    else:
                        f.write(msg.as_string())
            else:
                sys.stdout.write(msg.as_string())
        else:
            host, port = args.host.split(':')
            try:
                if args.verbose:
                    wout("Sending packet to {} (host: {})... ",
                        msg['To'], args.host
                    )
                with smtplib.SMTP(host=host, port=int(port)) as s:
                    s.send_message(msg)
                if args.verbose:
                    wout("ok\n")
            except:
                if args.verbose:
                    wout("FAILED\n")
                raise
    except Exception as e:
        perror("{}", repr(e))
        return 1
    except:
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
