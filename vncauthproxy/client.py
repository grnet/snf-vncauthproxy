#!/usr/bin/env python
#
# Copyright (c) 2010-2011 Greek Research and Technology Network S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

import sys
import socket
import ssl

try:
    import simplejson as json
except ImportError:
    import json

try:
    from gevent import sleep
except ImportError:
    import sleep

DEFAULT_SERVER_ADDRESS = '127.0.0.1'
DEFAULT_SERVER_PORT = 24999


def parse_arguments(args):
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("--server", dest="server_address",
                      default=DEFAULT_SERVER_ADDRESS,
                      metavar="SERVER",
                      help=("vncauthproxy server address"))
    parser.add_option("--server-port", dest="server_port",
                      default=DEFAULT_SERVER_PORT, type="int",
                      metavar="SERVER_PORT",
                      help=("vncauthproxy port"))
    parser.add_option('-s', dest="sport",
                      default=0, type="int",
                      metavar='PORT',
                      help=("Use source port PORT for incoming connections "
                            "(default: allocate a port automatically)"))
    parser.add_option("-d", "--dest",
                      default=None, dest="daddr",
                      metavar="HOST",
                      help="Proxy connection to destination host HOST")
    parser.add_option("-p", "--dport", dest="dport",
                      default=None, type="int",
                      metavar="PORT",
                      help="Proxy connection to destination port PORT")
    parser.add_option("-P", "--password", dest="password",
                      default=None,
                      metavar="PASSWORD",
                      help=("Use password PASSWD to authenticate incoming "
                            "VNC connections"))

    (opts, args) = parser.parse_args(args)

    # Mandatory arguments
    if not opts.password:
        parser.error("The -P/--password argument is mandatory.")
    if not opts.daddr:
        parser.error("The -d/--dest argument is mandatory.")
    if not opts.dport:
        parser.error("The -p/--dport argument is mandatory.")

    return (opts, args)


def request_forwarding(sport, daddr, dport, password,
                       server_address=DEFAULT_SERVER_ADDRESS,
                       server_port=DEFAULT_SERVER_PORT, ssl_sock=True):
    """Connect to vncauthproxy and request a VNC forwarding."""
    if not password:
        raise ValueError("You must specify a non-empty password")

    req = {
        "source_port": int(sport),
        "destination_address": daddr,
        "destination_port": int(dport),
        "password": password,
    }

    retries = 5
    while retries:
        # Initiate server connection
        for res in socket.getaddrinfo(server_address, server_port,
                                      socket.AF_UNSPEC,
                                      socket.SOCK_STREAM, 0,
                                      socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                server = socket.socket(af, socktype, proto)
            except socket.error:
                server = None
                continue

            if ssl_sock:
                server = ssl.wrap_socket(
                      server, cert_reqs=ssl.CERT_NONE,
                      ssl_version=ssl.PROTOCOL_TLSv1)

            server.settimeout(60.0)

            try:
                server.connect(sa)
            except socket.error:
                server.close()
                server = None
                continue

            retries = 0
            break

        sleep(0.2)

    if server is None:
        raise Exception("Failed to connect to server")

    server.send(json.dumps(req))

    response = server.recv(1024)
    server.close()
    res = json.loads(response)
    return res


if __name__ == '__main__':
    (opts, args) = parse_arguments(sys.argv[1:])

    res = request_forwarding(sport=opts.sport, daddr=opts.daddr,
                             dport=opts.dport, password=opts.password)

    sys.stderr.write("Forwaring %s -> %s:%s: %s\n" % (res['source_port'],
                                                      opts.daddr, opts.dport,
                                                      res['status']))

    if res['status'] == "OK":
        sys.exit(0)
    else:
        sys.exit(1)
