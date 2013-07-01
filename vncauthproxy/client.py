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
    parser.add_option("--auth-user", dest="auth_user",
                      default=None,
                      metavar="AUTH_USER",
                      help=("User to authenticate as, for the control "
                            "connection"))
    parser.add_option("--auth-password", dest="auth_password",
                      default=None,
                      metavar="AUTH_PASSWORD",
                      help=("User password for the control connection "
                            "authentication"))
    parser.add_option("--no-ssl", dest="no_ssl",
                      action='store_true', default=False,
                      help=("Disable SSL/TLS for control connecions "
                            "(default: %s)" % False))
    parser.add_option("--ca-cert", dest="ca_cert",
                      default=None,
                      metavar="CACERT",
                      help=("CA certificate file to use for server auth"))
    parser.add_option("--strict", dest="strict",
                      default=False, action='store_true',
                      metavar="STRICT",
                      help=("Perform strict authentication on the server "
                            "SSL cert"))

    (opts, args) = parser.parse_args(args)

    # Mandatory arguments
    if not opts.password:
        parser.error("The -P/--password argument is mandatory.")
    if not opts.daddr:
        parser.error("The -d/--dest argument is mandatory.")
    if not opts.dport:
        parser.error("The -p/--dport argument is mandatory.")
    if not opts.auth_user:
        parser.error("The --auth-user argument is mandatory.")
    if not opts.auth_password:
        parser.error("The --auth-password argument is mandatory.")

    # Sanity check
    if opts.strict and not opts.ca_cert:
        parser.error("--strict requires --ca-cert to be set")
    if opts.no_ssl and opts.ca_cert:
        parser.error("--no-ssl and --ca-cert / --strict options "
                     "are mutually exclusive")

    return (opts, args)


def request_forwarding(sport, daddr, dport, password,
                       auth_user, auth_password,
                       server_address=DEFAULT_SERVER_ADDRESS,
                       server_port=DEFAULT_SERVER_PORT, no_ssl=False,
                       ca_cert=None, strict=False):
    """Connect to vncauthproxy and request a VNC forwarding."""
    if not password:
        raise ValueError("You must specify a non-empty password")

    req = {
        "source_port": int(sport),
        "destination_address": daddr,
        "destination_port": int(dport),
        "password": password,
        "auth_user": auth_user,
        "auth_password": auth_password,
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

            if not no_ssl:
                reqs = ssl.CERT_NONE
                if strict:
                    reqs = ssl.CERT_REQUIRED
                elif ca_cert:
                    reqs = ssl.CERT_OPTIONAL

                server = ssl.wrap_socket(
                      server, cert_reqs=reqs, ca_certs=ca_cert,
                      ssl_version=ssl.PROTOCOL_TLSv1)

            server.settimeout(60.0)

            try:
                server.connect(sa)
            except socket.error:
                server.close()
                server = None
                retries -= 1
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
                             dport=opts.dport, password=opts.password,
                             auth_user=opts.auth_user,
                             auth_password=opts.auth_password,
                             no_ssl=opts.no_ssl, ca_cert=opts.ca_cert,
                             strict=opts.strict)

    reason = None
    if 'reason' in res:
        reason = 'Reason: %s\n' % res['reason']
    sys.stderr.write("Forwaring %s -> %s:%s: %s\n%s" % (res['source_port'],
                                                      opts.daddr, opts.dport,
                                                      res['status'], reason))

    if res['status'] == "OK":
        sys.exit(0)
    else:
        sys.exit(1)
