#!/usr/bin/env python
"""
vncauthproxy - a VNC authentication proxy
"""
#
# Copyright (c) 2010-2013 Greek Research and Technology Network S.A.
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

DEFAULT_BIND_ADDRESS = None
DEFAULT_LPORT = 24999
DEFAULT_LOG_FILE = "/var/log/vncauthproxy/vncauthproxy.log"
DEFAULT_PID_FILE = "/var/run/vncauthproxy/vncauthproxy.pid"
DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_CONNECT_RETRIES = 3
DEFAULT_RETRY_WAIT = 0.1
DEFAULT_BACKLOG = 256
DEFAULT_SOCK_TIMEOUT = 60.0
# We must take care not to fall into the ephemeral port range,
# this can lead to transient failures to bind a chosen port.
#
# By default, Linux uses 32768 to 61000, see:
# http://www.ncftp.com/ncftpd/doc/misc/ephemeral_ports.html#Linux
# so 25000-30000 seems to be a sensible default.
DEFAULT_MIN_PORT = 25000
DEFAULT_MAX_PORT = 30000

import os
import sys
import logging
import gevent
import gevent.event
import daemon
import random
import daemon.runner

import rfb

try:
    import simplejson as json
except ImportError:
    import json

from gevent import socket
from signal import SIGINT, SIGTERM
from gevent.select import select

from lockfile import LockTimeout, AlreadyLocked
# Take care of differences between python-daemon versions.
try:
    from daemon import pidfile as pidlockfile
except:
    from daemon import pidlockfile


logger = None


# Currently, gevent uses libevent-dns for asynchronous DNS resolution,
# which opens a socket upon initialization time. Since we can't get the fd
# reliably, We have to maintain all file descriptors open (which won't harm
# anyway)
class AllFilesDaemonContext(daemon.DaemonContext):
    """DaemonContext class keeping all file descriptors open"""
    def _get_exclude_file_descriptors(self):
        class All:
            def __contains__(self, value):
                return True
        return All()


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

    def __init__(self, logger, listeners, pool, daddr, dport, server, password,
                 connect_timeout):
        """
        @type logger: logging.Logger
        @param logger: the logger to use
        @type listeners: list
        @param listeners: list of listening sockets to use for clients
        @type pool: list
        @param pool: if not None, return the client number into this port pool
        @type daddr: str
        @param daddr: destination address (IPv4, IPv6 or hostname)
        @type dport: int
        @param dport: destination port
        @type server: socket
        @param server: VNC server socket
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
        # A list of worker/forwarder greenlets, one for each direction
        self.workers = []
        # All listening sockets are assumed to be on the same port
        self.sport = listeners[0].getsockname()[1]
        self.pool = pool
        self.daddr = daddr
        self.dport = dport
        self.server = server
        self.password = password
        self.client = None
        self.timeout = connect_timeout

    def _cleanup(self):
        """Cleanup everything: workers, sockets, ports

        Kill all remaining forwarder greenlets, close all active sockets,
        return the source port to the pool if applicable, then exit
        gracefully.

        """
        # Make sure all greenlets are dead, then clean them up
        self.debug("Cleaning up %d workers", len(self.workers))
        for g in self.workers:
            g.kill()
        gevent.joinall(self.workers)
        del self.workers

        self.debug("Cleaning up sockets")
        while self.listeners:
            self.listeners.pop().close()
        if self.server:
            self.server.close()
        if self.client:
            self.client.close()

        # Reintroduce the port number of the client socket in
        # the port pool, if applicable.
        if not self.pool is None:
            self.pool.append(self.sport)
            self.debug("Returned port %d to port pool, contains %d ports",
                       self.sport, len(self.pool))

        self.info("Cleaned up connection, all done")
        raise gevent.GreenletExit

    def __str__(self):
        return "VncAuthProxy: %d -> %s:%d" % (self.sport, self.daddr,
                                              self.dport)

    def _forward(self, source, dest):
        """
        Forward traffic from source to dest

        @type source: socket
        @param source: source socket
        @type dest: socket
        @param dest: destination socket

        """

        while True:
            d = source.recv(16384)
            if d == '':
                if source == self.client:
                    self.info("Client connection closed")
                else:
                    self.info("Server connection closed")
                break
            dest.sendall(d)
        # No need to close the source and dest sockets here.
        # They are owned by and will be closed by the original greenlet.

    def _client_handshake(self):
        """
        Perform handshake/authentication with a connecting client

        Outline:
        1. Client connects
        2. We fake RFB 3.8 protocol and require VNC authentication
           [processing also supports RFB 3.3]
        3. Client accepts authentication method
        4. We send an authentication challenge
        5. Client sends the authentication response
        6. We check the authentication

        Upon return, self.client socket is connected to the client.

        """
        self.client.send(rfb.RFB_VERSION_3_8 + "\n")
        client_version_str = self.client.recv(1024)
        client_version = rfb.check_version(client_version_str)
        if not client_version:
            self.error("Invalid version: %s", client_version_str)
            raise gevent.GreenletExit

        # Both for RFB 3.3 and 3.8
        self.debug("Requesting authentication")
        auth_request = rfb.make_auth_request(rfb.RFB_AUTHTYPE_VNC,
                                             version=client_version)
        self.client.send(auth_request)

        # The client gets to propose an authtype only for RFB 3.8
        if client_version == rfb.RFB_VERSION_3_8:
            res = self.client.recv(1024)
            type = rfb.parse_client_authtype(res)
            if type == rfb.RFB_AUTHTYPE_ERROR:
                self.warn("Client refused authentication: %s", res[1:])
            else:
                self.debug("Client requested authtype %x", type)

            if type != rfb.RFB_AUTHTYPE_VNC:
                self.error("Wrong auth type: %d", type)
                self.client.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
                raise gevent.GreenletExit

        # Generate the challenge
        challenge = os.urandom(16)
        self.client.send(challenge)
        response = self.client.recv(1024)
        if len(response) != 16:
            self.error("Wrong response length %d, should be 16", len(response))
            raise gevent.GreenletExit

        if rfb.check_password(challenge, response, self.password):
            self.debug("Authentication successful")
        else:
            self.warn("Authentication failed")
            self.client.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
            raise gevent.GreenletExit

        # Accept the authentication
        self.client.send(rfb.to_u32(rfb.RFB_AUTH_SUCCESS))

    def _run(self):
        try:
            self.info("Waiting for a client to connect at %s",
                      ", ".join(["%s:%d" % s.getsockname()[:2]
                                 for s in self.listeners]))
            rlist, _, _ = select(self.listeners, [], [], timeout=self.timeout)

            if not rlist:
                self.info("Timed out, no connection after %d sec",
                          self.timeout)
                raise gevent.GreenletExit

            for sock in rlist:
                self.client, addrinfo = sock.accept()
                self.info("Connection from %s:%d", *addrinfo[:2])

                # Close all listening sockets, we only want a one-shot
                # connection from a single client.
                while self.listeners:
                    self.listeners.pop().close()
                break

            # Perform RFB handshake with the client.
            self._client_handshake()

            # Bridge both connections through two "forwarder" greenlets.
            # This greenlet will wait until any of the workers dies.
            # Final cleanup will take place in _cleanup().
            dead = gevent.event.Event()
            dead.clear()

            # This callback will get called if any of the two workers dies.
            def callback(g):
                self.debug("Worker %d/%d died", self.workers.index(g),
                           len(self.workers))
                dead.set()

            self.workers.append(gevent.spawn(self._forward,
                                             self.client, self.server))
            self.workers.append(gevent.spawn(self._forward,
                                             self.server, self.client))
            for g in self.workers:
                g.link(callback)

            # Wait until any of the workers dies
            self.debug("Waiting for any of %d workers to die",
                       len(self.workers))
            dead.wait()

            # We can go now, _cleanup() will take care of
            # all worker, socket and port cleanup
            self.debug("A forwarder died, our work here is done")
            raise gevent.GreenletExit
        except Exception, e:
            # Any unhandled exception in the previous block
            # is an error and must be logged accordingly
            if not isinstance(e, gevent.GreenletExit):
                self.exception(e)
            raise e
        finally:
            self._cleanup()

# Logging support inside VncAuthproxy
# Wrap all common logging functions in logging-specific methods
for funcname in ["info", "debug", "warn", "error", "critical",
                 "exception"]:

    def gen(funcname):
        def wrapped_log_func(self, *args, **kwargs):
            func = getattr(self.log, funcname)
            func("[C%d] %s" % (self.id, args[0]), *args[1:], **kwargs)
        return wrapped_log_func
    setattr(VncAuthProxy, funcname, gen(funcname))


def fatal_signal_handler(signame):
    logger.info("Caught %s, will raise SystemExit", signame)
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
            logger.debug("Listening on %s:%d", *sa[:2])
        except socket.error, msg:
            logger.error("Error binding to %s:%d: %s", sa[0], sa[1], msg[1])
            if s:
                s.close()
            while sockets:
                sockets.pop().close()

            # Make sure we fail immediately if we cannot get a socket
            raise msg

    return sockets


def perform_server_handshake(daddr, dport, tries, retry_wait, sock_timeout):
    """
    Initiate a connection with the backend server and perform basic
    RFB 3.8 handshake with it.

    Return a socket connected to the backend server.

    """
    server = None

    while tries:
        tries -= 1

        # Initiate server connection
        for res in socket.getaddrinfo(daddr, dport, socket.AF_UNSPEC,
                                      socket.SOCK_STREAM, 0,
                                      socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                server = socket.socket(af, socktype, proto)
            except socket.error:
                server = None
                continue

            # Set socket timeout for the initial handshake
            server.settimeout(sock_timeout)

            try:
                logger.debug("Connecting to %s:%s", *sa[:2])
                server.connect(sa)
                logger.debug("Connection to %s:%s successful", *sa[:2])
            except socket.error:
                server.close()
                server = None
                continue

            # We succesfully connected to the server
            tries = 0
            break

        # Wait and retry
        gevent.sleep(retry_wait)

    if server is None:
        raise Exception("Failed to connect to server")

    version = server.recv(1024)
    if not rfb.check_version(version):
        raise Exception("Unsupported RFB version: %s" % version.strip())

    server.send(rfb.RFB_VERSION_3_8 + "\n")

    res = server.recv(1024)
    types = rfb.parse_auth_request(res)
    if not types:
        raise Exception("Error handshaking with the server")

    else:
        logger.debug("Supported authentication types: %s",
                     " ".join([str(x) for x in types]))

    if rfb.RFB_AUTHTYPE_NONE not in types:
        raise Exception("Error, server demands authentication")

    server.send(rfb.to_u8(rfb.RFB_AUTHTYPE_NONE))

    # Check authentication response
    res = server.recv(4)
    res = rfb.from_u32(res)

    if res != 0:
        raise Exception("Authentication error")

    # Reset the timeout for the rest of the session
    server.settimeout(None)

    return server


def parse_arguments(args):
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("--bind", dest="bind_address",
                      default=DEFAULT_BIND_ADDRESS,
                      metavar="ADDRESS",
                      help=("Address to listen for control connections"))
    parser.add_option( "--lport", dest="lport",
                      default=DEFAULT_LPORT,
                      metavar="LPORT",
                      help=("Port to listen for control connections"))
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      help="Enable debugging information")
    parser.add_option("-l", "--log", dest="log_file",
                      default=DEFAULT_LOG_FILE,
                      metavar="FILE",
                      help=("Write log to FILE instead of %s" %
                            DEFAULT_LOG_FILE))
    parser.add_option('--pid-file', dest="pid_file",
                      default=DEFAULT_PID_FILE,
                      metavar='PIDFILE',
                      help=("Save PID to file (default: %s)" %
                            DEFAULT_PID_FILE))
    parser.add_option("-t", "--connect-timeout", dest="connect_timeout",
                      default=DEFAULT_CONNECT_TIMEOUT, type="int",
                      metavar="SECONDS", help=("Wait SECONDS sec for a client "
                                               "to connect"))
    parser.add_option("-r", "--connect-retries", dest="connect_retries",
                      default=DEFAULT_CONNECT_RETRIES, type="int",
                      metavar="RETRIES",
                      help="How many times to try to connect to the server")
    parser.add_option("-w", "--retry-wait", dest="retry_wait",
                      default=DEFAULT_RETRY_WAIT, type="float",
                      metavar="SECONDS", help=("Retry connection to server "
                                               "every SECONDS sec"))
    parser.add_option("-p", "--min-port", dest="min_port",
                      default=DEFAULT_MIN_PORT, type="int", metavar="MIN_PORT",
                      help=("The minimum port number to use for automatically-"
                            "allocated ephemeral ports"))
    parser.add_option("-P", "--max-port", dest="max_port",
                      default=DEFAULT_MAX_PORT, type="int", metavar="MAX_PORT",
                      help=("The maximum port number to use for automatically-"
                            "allocated ephemeral ports"))
    parser.add_option("-b", "--backlog", dest="backlog",
                      default=DEFAULT_BACKLOG, type="int", metavar="BACKLOG",
                      help=("Length of the backlog queue for the control"
                            "connection socket"))
    parser.add_option("--socket-timeout", dest="sock_timeout",
                      default=DEFAULT_SOCK_TIMEOUT, type="float",
                      metavar="SOCK_TIMEOUT",
                      help=("Socket timeout for the server handshake"))

    return parser.parse_args(args)


def establish_connection(client, addr, ports, opts):
    # Receive and parse a client request.
    response = {
        "source_port": 0,
        "status": "FAILED",
    }
    try:
        # TODO: support multiple forwardings in the same message?
        #
        # Control request, in JSON:
        #
        # {
        #     "source_port":
        #         <source port or 0 for automatic allocation>,
        #     "destination_address":
        #         <destination address of backend server>,
        #     "destination_port":
        #         <destination port>
        #     "password":
        #         <the password to use to authenticate clients>
        # }
        #
        # The <password> is used for MITM authentication of clients
        # connecting to <source_port>, who will subsequently be
        # forwarded to a VNC server listening at
        # <destination_address>:<destination_port>
        #
        # Control reply, in JSON:
        # {
        #     "source_port": <the allocated source port>
        #     "status": <one of "OK" or "FAILED">
        # }
        #
        buf = client.recv(1024)
        req = json.loads(buf)

        sport_orig = int(req['source_port'])
        daddr = req['destination_address']
        dport = int(req['destination_port'])
        password = req['password']
    except Exception, e:
        logger.warn("Malformed request: %s", buf)
        client.send(json.dumps(response))
        client.close()

    # Spawn a new Greenlet to service the request.
    server = None
    try:
        # If the client has so indicated, pick an ephemeral source port
        # randomly, and remove it from the port pool.
        if sport_orig == 0:
            while True:
                try:
                    sport = random.choice(ports)
                    ports.remove(sport)
                    break
                except ValueError:
                    logger.debug("Port %d already taken", sport)

            logger.debug("Got port %d from pool, %d remaining",
                         sport, len(ports))
            pool = ports
        else:
            sport = sport_orig
            pool = None

        listeners = get_listening_sockets(sport)
        server = perform_server_handshake(daddr, dport,
                                          opts.connect_retries,
                                          opts.retry_wait, opts.sock_timeout)

        VncAuthProxy.spawn(logger, listeners, pool, daddr, dport,
                           server, password, opts.connect_timeout)

        logger.info("New forwarding: %d (client req'd: %d) -> %s:%d",
                    sport, sport_orig, daddr, dport)
        response = {"source_port": sport,
                    "status": "OK"}
    except IndexError:
        logger.error(("FAILED forwarding, out of ports for [req'd by "
                      "client: %d -> %s:%d]"),
                     sport_orig, daddr, dport)
    except Exception, msg:
        logger.error(msg)
        logger.error(("FAILED forwarding: %d (client req'd: %d) -> "
                      "%s:%d"), sport, sport_orig, daddr, dport)
        if not pool is None:
            pool.append(sport)
            logger.debug("Returned port %d to pool, %d remanining",
                         sport, len(pool))
        if not server is None:
            server.close()
    finally:
        client.send(json.dumps(response))
        client.close()


def main():
    """Run the daemon from the command line"""

    (opts, args) = parse_arguments(sys.argv[1:])

    # Create pidfile
    pidf = pidlockfile.TimeoutPIDLockFile(opts.pid_file, 10)

    # Initialize logger
    lvl = logging.DEBUG if opts.debug else logging.INFO

    global logger
    logger = logging.getLogger("vncauthproxy")
    logger.setLevel(lvl)
    formatter = logging.Formatter(("%(asctime)s %(module)s[%(process)d] "
                                   " %(levelname)s: %(message)s"),
                                  "%Y-%m-%d %H:%M:%S")
    handler = logging.FileHandler(opts.log_file)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Become a daemon:
    # Redirect stdout and stderr to handler.stream to catch
    # early errors in the daemonization process [e.g., pidfile creation]
    # which will otherwise go to /dev/null.
    daemon_context = AllFilesDaemonContext(
        pidfile=pidf,
        umask=0022,
        stdout=handler.stream,
        stderr=handler.stream,
        files_preserve=[handler.stream])

    # Remove any stale PID files, left behind by previous invocations
    if daemon.runner.is_pidfile_stale(pidf):
        logger.warning("Removing stale PID lock file %s", pidf.path)
        pidf.break_lock()

    try:
        daemon_context.open()
    except (AlreadyLocked, LockTimeout):
        logger.critical(("Failed to lock PID file %s, another instance "
                         "running?"), pidf.path)
        sys.exit(1)
    logger.info("Became a daemon")

    # A fork() has occured while daemonizing,
    # we *must* reinit gevent
    gevent.reinit()

    sockets = []
    for res in socket.getaddrinfo(opts.bind_address, opts.lport,
                             socket.AF_UNSPEC, socket.SOCK_STREAM, 0,
                             socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res
        try:
            s = None
            s = socket.socket(af, socktype, proto)
            if af == socket.AF_INET6:
                # Bind v6 only when AF_INET6, otherwise either v4 or v6 bind
                # will fail.
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind(sa)
            s.listen(opts.backlog)
            sockets.append(s)
            logger.info("Control socket listening on %s:%d", *sa[:2])
        except socket.error, msg:
            logger.critical("Error binding control socket to %s:%d: %s",
                         sa[0], sa[1], msg[1])
            if s:
                s.close()
            while sockets:
                sockets.pop.close()

            sys.exit(1)

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
            rlist, _, _ = select(sockets, [], [])
            for ctrl in rlist:
                client, addr = ctrl.accept()
                logger.info("New control connection")

                gevent.Greenlet.spawn(establish_connection, client, addr,
                                      ports, opts)
        except Exception, e:
            logger.exception(e)
            continue
        except SystemExit:
            break

    logger.info("Closing control sockets")
    while sockets:
        sockets.pop.close()
    daemon_context.close()
    sys.exit(0)
