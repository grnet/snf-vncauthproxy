#!/usr/bin/env python
#

# Copyright (c) 2010 GRNET SA
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

DEFAULT_CTRL_SOCKET = "/tmp/vncproxy.sock"
DEFAULT_LOG_FILE = "/var/log/vncauthproxy/vncauthproxy.log"
DEFAULT_PID_FILE = "/var/run/vncauthproxy/vncauthproxy.pid"
DEFAULT_CONNECT_TIMEOUT = 30
# Default values per http://www.iana.org/assignments/port-numbers
DEFAULT_MIN_PORT = 49152 
DEFAULT_MAX_PORT = 65535

import os
import sys
import logging
import gevent
import daemon
import random
import daemon.pidlockfile

import rfb
 
try:
    import simplejson as json
except ImportError:
    import json

from gevent import socket
from signal import SIGINT, SIGTERM
from gevent import signal
from gevent.select import select


class VncAuthProxy(gevent.Greenlet):
    """
    Simple class implementing a VNC Forwarder with MITM authentication as a
    Greenlet

    VncAuthProxy forwards VNC traffic from a specified port of the local host
    to a specified remote host:port. Furthermore, it implements VNC
    Authentication, intercepting the client/server handshake and asking the
    client for authentication even if the backend requires none.

    It is primarily intended for use in virtualization environments, as a VNC
    ``switch''.

    """
    id = 1

    def __init__(self, logger, listeners, pool, daddr, dport, password, connect_timeout):
        """
        @type logger: logging.Logger
        @param logger: the logger to use
        @type listeners: list
        @param listeners: list of listening sockets to use for client connections
        @type pool: list
        @param pool: if not None, return the client port number into this port pool
        @type daddr: str
        @param daddr: destination address (IPv4, IPv6 or hostname)
        @type dport: int
        @param dport: destination port
        @type password: str
        @param password: password to request from the client
        @type connect_timeout: int
        @param connect_timeout: how long to wait for client connections
                                (seconds)

        """
        gevent.Greenlet.__init__(self)
        self.id = VncAuthProxy.id
        VncAuthProxy.id += 1
        self.log = logger
        self.listeners = listeners
        # All listening sockets are assumed to be on the same port
        self.sport = listeners[0].getsockname()[1]
        self.pool = pool
        self.daddr = daddr
        self.dport = dport
        self.password = password
        self.server = None
        self.client = None
        self.timeout = connect_timeout

    def _cleanup(self):
        """Close all active sockets and exit gracefully"""
        # Reintroduce the port number of the client socket in
        # the port pool, if applicable.
        if not self.pool is None:
            self.pool.append(self.sport)
            self.log.debug("Returned port %d to port pool, contains %d ports",
                self.sport, len(self.pool))

        while self.listeners:
            self.listeners.pop().close()
        if self.server:
            self.server.close()
        if self.client:
            self.client.close()

        raise gevent.GreenletExit

    def info(self, msg):
        self.log.info("[C%d] %s" % (self.id, msg))

    def debug(self, msg):
        self.log.debug("[C%d] %s" % (self.id, msg))

    def warn(self, msg):
        self.log.warn("[C%d] %s" % (self.id, msg))

    def error(self, msg):
        self.log.error("[C%d] %s" % (self.id, msg))

    def critical(self, msg):
        self.log.critical("[C%d] %s" % (self.id, msg))

    def __str__(self):
        return "VncAuthProxy: %d -> %s:%d" % (self.sport, self.daddr, self.dport)

    def _forward(self, source, dest):
        """
        Forward traffic from source to dest

        @type source: socket
        @param source: source socket
        @type dest: socket
        @param dest: destination socket

        """

        while True:
            d = source.recv(8096)
            if d == '':
                if source == self.client:
                    self.info("Client connection closed")
                else:
                    self.info("Server connection closed")
                break
            dest.sendall(d)
        # No need to close the source and dest sockets here.
        # They are owned by and will be closed by the original greenlet.


    def _handshake(self):
        """
        Perform handshake/authentication with a connecting client

        Outline:
        1. Client connects
        2. We fake RFB 3.8 protocol and require VNC authentication
        3. Client accepts authentication method
        4. We send an authentication challenge
        5. Client sends the authentication response
        6. We check the authentication
        7. We initiate a connection with the backend server and perform basic
           RFB 3.8 handshake with it.

        Upon return, self.client and self.server are sockets
        connected to the client and the backend server, respectively.

        """
        self.client.send(rfb.RFB_VERSION_3_8 + "\n")
        client_version = self.client.recv(1024)
        if not rfb.check_version(client_version):
            self.error("Invalid version: %s" % client_version)
            raise gevent.GreenletExit
        self.debug("Requesting authentication")
        auth_request = rfb.make_auth_request(rfb.RFB_AUTHTYPE_VNC)
        self.client.send(auth_request)
        res = self.client.recv(1024)
        type = rfb.parse_client_authtype(res)
        if type == rfb.RFB_AUTHTYPE_ERROR:
            self.warn("Client refused authentication: %s" % res[1:])
        else:
            self.debug("Client requested authtype %x" % type)

        if type != rfb.RFB_AUTHTYPE_VNC:
            self.error("Wrong auth type: %d" % type)
            self.client.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
            raise gevent.GreenletExit

        # Generate the challenge
        challenge = os.urandom(16)
        self.client.send(challenge)
        response = self.client.recv(1024)
        if len(response) != 16:
            self.error("Wrong response length %d, should be 16" % len(response))
            raise gevent.GreenletExit

        if rfb.check_password(challenge, response, password):
            self.debug("Authentication successful!")
        else:
            self.warn("Authentication failed")
            self.client.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
            raise gevent.GreenletExit

        # Accept the authentication
        self.client.send(rfb.to_u32(rfb.RFB_AUTH_SUCCESS))

        # Try to connect to the server
        tries = 50

        while tries:
            tries -= 1

            # Initiate server connection
            for res in socket.getaddrinfo(self.daddr, self.dport, socket.AF_UNSPEC,
                                          socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
                af, socktype, proto, canonname, sa = res
                try:
                    self.server = socket.socket(af, socktype, proto)
                except socket.error, msg:
                    self.server = None
                    continue

                try:
                    self.debug("Connecting to %s:%s" % sa[:2])
                    self.server.connect(sa)
                    self.debug("Connection to %s:%s successful" % sa[:2])
                except socket.error, msg:
                    self.server.close()
                    self.server = None
                    continue

                # We succesfully connected to the server
                tries = 0
                break

            # Wait and retry
            gevent.sleep(0.2)

        if self.server is None:
            self.error("Failed to connect to server")
            raise gevent.GreenletExit

        version = self.server.recv(1024)
        if not rfb.check_version(version):
            self.error("Unsupported RFB version: %s" % version.strip())
            raise gevent.GreenletExit

        self.server.send(rfb.RFB_VERSION_3_8 + "\n")

        res = self.server.recv(1024)
        types = rfb.parse_auth_request(res)
        if not types:
            self.error("Error handshaking with the server")
            raise gevent.GreenletExit

        else:
            self.debug("Supported authentication types: %s" %
                           " ".join([str(x) for x in types]))

        if rfb.RFB_AUTHTYPE_NONE not in types:
            self.error("Error, server demands authentication")
            raise gevent.GreenletExit

        self.server.send(rfb.to_u8(rfb.RFB_AUTHTYPE_NONE))

        # Check authentication response
        res = self.server.recv(4)
        res = rfb.from_u32(res)

        if res != 0:
            self.error("Authentication error")
            raise gevent.GreenletExit
       
    def _run(self):
        try:
            self.log.debug("Waiting for client to connect")
            rlist, _, _ = select(listeners, [], [], timeout=self.timeout)

            if not rlist:
                self.info("Timed out, no connection after %d sec" % self.timeout)
                raise gevent.GreenletExit

            for sock in rlist:
                self.client, addrinfo = sock.accept()
                self.info("Connection from %s:%d" % addrinfo[:2])

                # Close all listening sockets, we only want a one-shot connection
                # from a single client.
                while self.listeners:
                    self.listeners.pop().close()
                break
       
            # Perform RFB handshake with the client and the backend server.
            # If all goes as planned, we have two connected sockets,
            # self.client and self.server.
            self._handshake()

            # Bridge both connections through two "forwarder" greenlets.
            self.workers = [gevent.spawn(self._forward, self.client, self.server),
                gevent.spawn(self._forward, self.server, self.client)]
            gevent.joinall(self.workers)

            del self.workers
            raise gevent.GreenletExit
        except Exception, e:
            # Any unhandled exception in the previous block
            # is an error and must be logged accordingly
            if not isinstance(e, gevent.GreenletExit):
                logger.exception(e)
            raise e
        finally:
            self._cleanup()


def fatal_signal_handler(signame):
    logger.info("Caught %s, will raise SystemExit" % signame)
    raise SystemExit

def get_listening_sockets(sport):
    sockets = []

    # Use two sockets, one for IPv4, one for IPv6. IPv4-to-IPv6 mapped
    # addresses do not work reliably everywhere (under linux it may have
    # been disabled in /proc/sys/net/ipv6/bind_ipv6_only).
    for res in socket.getaddrinfo(None, sport, socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res
        try:
            s = None
            s = socket.socket(af, socktype, proto)
            if af == socket.AF_INET6:
                # Bind v6 only when AF_INET6, otherwise either v4 or v6 bind
                # will fail.
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind(sa)
            s.listen(1)
            sockets.append(s)
            logger.debug("Listening on %s:%d" % sa[:2])
        except socket.error, msg:
            logger.error("Error binding to %s:%d: %s" %
                           (sa[0], sa[1], msg[1]))
            if s:
                s.close()
            while sockets:
                sockets.pop().close()
            
            # Make sure we fail immediately if we cannot get a socket
            raise msg
    
    return sockets

def parse_arguments(args):
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-s", "--socket", dest="ctrl_socket",
                      default=DEFAULT_CTRL_SOCKET,
                      metavar="PATH",
                      help="UNIX socket path for control connections (default: %s" %
                          DEFAULT_CTRL_SOCKET)
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      help="Enable debugging information")
    parser.add_option("-l", "--log", dest="log_file",
                      default=DEFAULT_LOG_FILE,
                      metavar="FILE",
                      help="Write log to FILE instead of %s" % DEFAULT_LOG_FILE),
    parser.add_option('--pid-file', dest="pid_file",
                      default=DEFAULT_PID_FILE,
                      metavar='PIDFILE',
                      help="Save PID to file (default: %s)" %
                          DEFAULT_PID_FILE)
    parser.add_option("-t", "--connect-timeout", dest="connect_timeout",
                      default=DEFAULT_CONNECT_TIMEOUT, type="int", metavar="SECONDS",
                      help="How long to listen for clients to forward")
    parser.add_option("-p", "--min-port", dest="min_port",
                      default=DEFAULT_MIN_PORT, type="int", metavar="MIN_PORT",
                      help="The minimum port to use for automatically-allocated ephemeral ports")
    parser.add_option("-P", "--max-port", dest="max_port",
                      default=DEFAULT_MAX_PORT, type="int", metavar="MAX_PORT",
                      help="The minimum port to use for automatically-allocated ephemeral ports")

    return parser.parse_args(args)


if __name__ == '__main__':
    (opts, args) = parse_arguments(sys.argv[1:])

    # Create pidfile
    pidf = daemon.pidlockfile.TimeoutPIDLockFile(
        opts.pid_file, 10)
    
    # Initialize logger
    lvl = logging.DEBUG if opts.debug else logging.INFO
    logger = logging.getLogger("vncauthproxy")
    logger.setLevel(lvl)
    formatter = logging.Formatter("%(asctime)s vncauthproxy[%(process)d] %(levelname)s: %(message)s",
        "%Y-%m-%d %H:%M:%S")
    handler = logging.FileHandler(opts.log_file)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Become a daemon:
    # Redirect stdout and stderr to handler.stream to catch
    # early errors in the daemonization process [e.g., pidfile creation]
    # which will otherwise go to /dev/null.
    daemon_context = daemon.DaemonContext(
        pidfile=pidf,
        umask=0o0022,
        stdout=handler.stream,
        stderr=handler.stream,
        files_preserve=[handler.stream])
    daemon_context.open()
    logger.info("Became a daemon")

    # A fork() has occured while daemonizing,
    # we *must* reinit gevent
    gevent.reinit()

    if os.path.exists(opts.ctrl_socket):
        logger.critical("Socket '%s' already exists" % opts.ctrl_socket)
        sys.exit(1)

    # TODO: make this tunable? chgrp as well?
    old_umask = os.umask(0077)

    ctrl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ctrl.bind(opts.ctrl_socket)

    os.umask(old_umask)

    ctrl.listen(1)
    logger.info("Initialized, waiting for control connections at %s" %
                 opts.ctrl_socket)

    # Catch signals to ensure graceful shutdown,
    # e.g., to make sure the control socket gets unlink()ed.
    #
    # Uses gevent.signal so the handler fires even during
    # gevent.socket.accept()
    gevent.signal(SIGINT, fatal_signal_handler, "SIGINT")
    gevent.signal(SIGTERM, fatal_signal_handler, "SIGTERM")

    # Init ephemeral port pool
    ports = range(opts.min_port, opts.max_port + 1) 

    while True:
        try:
            client, addr = ctrl.accept()
            logger.info("New control connection")
           
            # Receive and parse a client request.
            response = {
                "source_port": 0,
                "status": "FAILED"
            }
            try:
                # TODO: support multiple forwardings in the same message?
                # 
                # Control request, in JSON:
                #
                # {
                #     "source_port": <source port or 0 for automatic allocation>,
                #     "destination_address": <destination address of backend server>,
                #     "destination_port": <destination port>
                #     "password": <the password to use for MITM authentication of clients>
                # }
                # 
                # The <password> is used for MITM authentication of clients
                # connecting to <source_port>, who will subsequently be forwarded
                # to a VNC server at <destination_address>:<destination_port>
                #
                # Control reply, in JSON:
                # {
                #     "source_port": <the allocated source port>
                #     "status": <one of "OK" or "FAILED">
                # }
                buf = client.recv(1024)
                req = json.loads(buf)
                
                sport_orig = int(req['source_port'])
                daddr = req['destination_address']
                dport = int(req['destination_port'])
                password = req['password']
            except Exception, e:
                logger.warn("Malformed request: %s" % buf)
                cliend.send(json.dumps(response))
                client.close()
                continue
            
            # Spawn a new Greenlet to service the request.
            try:
                # If the client has so indicated, pick an ephemeral source port
                # randomly, and remove it from the port pool.
                if sport_orig == 0:
                    sport = random.choice(ports)
                    ports.remove(sport)
                    logger.debug("Got port %d from port pool, contains %d ports",
                        sport, len(ports))
                    pool = ports
                else:
                    sport = sport_orig
                    pool = None
                listeners = get_listening_sockets(sport)
                VncAuthProxy.spawn(logger, listeners, pool, daddr, dport,
                    password, opts.connect_timeout)
                logger.info("New forwarding [%d (req'd by client: %d) -> %s:%d]" %
                    (sport, sport_orig, daddr, dport))
                response = {
                    "source_port": sport,
                    "status": "OK"
                }
            except IndexError:
                logger.error("FAILED forwarding, out of ports for [req'd by "
                    "client: %d -> %s:%d]" % (sport_orig, daddr, dport))
            except socket.error, msg:
                logger.error("FAILED forwarding [%d (req'd by client: %d) -> %s:%d]" %
                    (sport, sport_orig, daddr, dport))
            finally:
                client.send(json.dumps(response))
                client.close()

        except SystemExit:
            break

 
    logger.info("Unlinking control socket at %s" %
                 opts.ctrl_socket)
    os.unlink(opts.ctrl_socket)
    daemon_context.close()
    sys.exit(0)
