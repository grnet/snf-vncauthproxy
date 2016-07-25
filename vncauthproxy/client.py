#!/usr/bin/env python
#
# Copyright (c) 2010-2014 Greek Research and Technology Network S.A.
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

""" vncauthproxy client """

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
    from time import sleep

import logging

DEFAULT_SERVER_ADDRESS = '127.0.0.1'
DEFAULT_SERVER_PORT = 24999

logger = logging.getLogger(__name__)


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
                      dest="daddr",
                      metavar="HOST",
                      help="Proxy connection to destination host HOST")
    parser.add_option("-p", "--dport", dest="dport",
                      type="int",
                      metavar="PORT",
                      help="Proxy connection to destination port PORT")
    parser.add_option("-P", "--password", dest="password",
                      metavar="PASSWORD",
                      help=("Use password PASSWD to authenticate incoming "
                            "VNC connections"))
    parser.add_option("--auth-user", dest="auth_user",
                      metavar="AUTH_USER",
                      help=("User to authenticate as, for the control "
                            "connection"))
    parser.add_option("--auth-password", dest="auth_password",
                      metavar="AUTH_PASSWORD",
                      help=("User password for the control connection "
                            "authentication"))
    parser.add_option("--type", dest="console_type",
                      metavar="console_type",
                      help=("Console type requested (vnc, vnc-ws, "
                            "vnc-wss)"))
    parser.add_option("--enable-ssl", dest="enable_ssl",
                      action='store_true', default=False,
                      help=("Enable SSL/TLS for control connecions "
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

    return (opts, args)


def request_forwarding(sport, daddr, dport, password, auth_user, auth_password,
                       server_address=DEFAULT_SERVER_ADDRESS,
                       server_port=DEFAULT_SERVER_PORT, enable_ssl=False,
                       ca_cert=None, strict=False, console_type="vnc"):
    """ Connect to vncauthproxy and request a VNC forwarding.

        @type sport: int
        @param sport: Source port for incoming connections
                      (0 for automatic allocation)"
        @type daddr: str
        @param daddr: Destination address for the forwarding
        @type dport: int
        @param dport: Destination port for the forwarding
        @type password: str
        @param password: VNC server auth password
        @type auth_user: str
        @param auth_user: vncauthproxy user
        @type auth_password: str
        @param auth_password: vncauthproxy password
        @type console_type: str
        @param console_type: console type requested (default: "vnc")
        @type server_address: str
        @param server_address: Listening address for the vncauthproxy daemon
                               (default: 127.0.0.1)
        @type server_port: int
        @param server_port: Listening port for the vncauthproxy daemon
                            (default: 24999)
        @type enable_ssl: bool
        @param enable_ssl: Enable / disable SSL on the control socket
        @type ca_cert: str
        @param ca_cert: Path to the CA cert file
        @type strict: bool
        @param strict: Enable strict cert checking for SSL
        @rtype: dict
        @return: Server response in dict / JSON format

        """

    # Sanity check
    if strict and not ca_cert:
        raise Exception("strict requires ca-cert to be set")
    if not enable_ssl and (strict or ca_cert):
        logger.warning("strict or ca-cert set, but ssl not enabled")

    req = {
        "source_port": int(sport),
        "destination_address": daddr,
        "destination_port": int(dport),
        "password": password,
        "auth_user": auth_user,
        "auth_password": auth_password,
        "type": console_type,
    }

    last_error = None
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

            if enable_ssl:
                reqs = ssl.CERT_NONE
                if strict:
                    reqs = ssl.CERT_REQUIRED
                elif ca_cert:
                    reqs = ssl.CERT_OPTIONAL

                server = ssl.wrap_socket(server, cert_reqs=reqs,
                                         ca_certs=ca_cert,
                                         ssl_version=ssl.PROTOCOL_TLSv1)

            server.settimeout(60.0)

            try:
                server.connect(sa)
            except socket.error as err:
                server.close()
                server = None
                retries -= 1
                last_error = err
                continue

            retries = 0
            break

        sleep(0.2)

    if server is None:
        raise Exception("Failed to connect to server: %s" % last_error)

    server.send(json.dumps(req))

    response = server.recv(1024)
    server.close()
    res = json.loads(response)
    return res


def main():
    logger.addHandler(logging.StreamHandler())

    (opts, args) = parse_arguments(sys.argv[1:])

    # Mandatory arguments
    if opts.password is None:
        sys.stderr.write("The password argument is mandatory.\n")
        sys.exit(1)
    if opts.daddr is None:
        sys.stderr.write("The daddr argument is mandatory.\n")
        sys.exit(1)
    if opts.dport is None:
        sys.stderr.write("The dport argument is mandatory.\n")
        sys.exit(1)
    if opts.auth_user is None:
        sys.stderr.write("The auth_user argument is mandatory.\n")
        sys.exit(1)
    if opts.auth_password is None:
        sys.stderr.write("The auth_password argument is mandatory.\n")
        sys.exit(1)
    if opts.console_type is None:
        sys.stderr.write("The type argument is mandatory.\n")
        sys.exit(1)

    res = request_forwarding(sport=opts.sport, daddr=opts.daddr,
                             dport=opts.dport, password=opts.password,
                             auth_user=opts.auth_user,
                             auth_password=opts.auth_password,
                             console_type=opts.console_type,
                             enable_ssl=opts.enable_ssl, ca_cert=opts.ca_cert,
                             strict=opts.strict)

    reason = None
    if 'reason' in res:
        reason = 'Reason: %s\n' % res['reason']
    sys.stderr.write("Forwaring %s:%s -> %s:%s: %s\n%s" %
                     (res['proxy_address'], res['source_port'], opts.daddr,
                      opts.dport, res['status'], reason))

    if res['status'] == "OK":
        sys.exit(0)
    else:
        sys.exit(1)
