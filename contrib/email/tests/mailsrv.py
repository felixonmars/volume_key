#!/usr/bin/python3
#                                                         -*- coding: utf-8 -*-
# Sink mail server.
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
"""Sink mail server"""

import sys
import os
import argparse
import asyncore
import smtpd

here = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, here)

from sendpkt import parse_host as sendpkt_parse_host

def error(ec, fmt, *args):
    sys.stderr.write("{}\n".format(fmt.format(*args)))
    sys.exit(ec)

def parse_host(host):
    try:
        return sendpkt_parse_host(host)
    except Exception as e:
        error(1, "{}", e)

def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "-b", "--banned", metavar='LIST',
        default="",
        help="comma-separated list of banned recipients"
    )
    parser.add_argument(
        "-B", "--ban-levels", metavar='LIST', dest="ban_levels",
        default="rcpt",
        help="comma-separated list of lowercase SMTP command names to which" \
             " the ban is applied to; supported commands are" \
             " 'vrfy', 'rcpt' and 'data'; default command is 'rcpt'"
    )
    parser.add_argument(
        "-s", "--sink", metavar='PATH',
        default="email.msg",
        help="the place all e-mails are thrown to"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true", default=False,
        help="print the communication to stderr"
    )
    parser.add_argument(
        "host", metavar='HOST[:PORT]', nargs='?',
        default="localhost:25",
        help="local address"
    )
    return parser.parse_args(args=argv)

class BanningChannel(smtpd.SMTPChannel):
    def smtp_VRFY(self, arg):
        if arg and 'vrfy' in self.smtp_server.ban_levels_:
            user, _ = self._getaddr(arg)
            # Test if user is banned:
            if user in self.smtp_server.banned_ \
            or user and user.split('@')[-1] in self.smtp_server.banned_:
                self.push("550 user <{}> is banned".format(user))
                return
        super().smtp_VRFY(arg)
    def smtp_RCPT(self, arg):
        rcpt = arg
        if rcpt and 'rcpt' in self.smtp_server.ban_levels_:
            rcpt = self._strip_command_keyword('TO:', rcpt)
            rcpt, _ = self._getaddr(rcpt)
            # Test if the recipient is banned:
            if rcpt in self.smtp_server.banned_ \
            or rcpt and rcpt.split('@')[-1] in self.smtp_server.banned_:
                self.push("554 banned recipient <{}>".format(rcpt))
                return
        super().smtp_RCPT(arg)

class SinkMailServer(smtpd.SMTPServer):
    channel_class = BanningChannel
    def __init__(self, sink, banned, ban_levels, *args, **kwargs):
        self.sink_ = sink
        self.banned_ = banned.split(",")
        self.ban_levels_ = ban_levels.split(",")
        super().__init__(*args, **kwargs)
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        if 'data' in self.ban_levels_ and (
            mailfrom in self.banned_ \
            or mailfrom and mailfrom.split('@')[-1] in self.banned_
        ):
            return "554 banned user <{}>".format(mailfrom)
        with open(self.sink_, 'wb') as f:
            f.write(data)

def main(argv):
    args = parse_args(argv)
    if args.debug:
        smtpd.DEBUGSTREAM = sys.stderr
    server = SinkMailServer(
        args.sink, args.banned, args.ban_levels, parse_host(args.host), None
    )
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main(sys.argv[1:])
