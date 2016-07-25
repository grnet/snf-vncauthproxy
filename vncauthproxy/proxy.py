#!/usr/bin/env python
"""
vncauthproxy - a VNC authentication proxy
"""
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

# Daemon files
DEFAULT_LOG_FILE = "/var/log/vncauthproxy/vncauthproxy.log"
DEFAULT_PID_FILE = "/var/run/vncauthproxy/vncauthproxy.pid"

# By default, bind / listen for control connections to TCP(v4) 127.0.0.1:24999
DEFAULT_LISTEN_ADDRESS = "127.0.0.1"
DEFAULT_LISTEN_PORT = 24999

# Backlog for the control socket
DEFAULT_BACKLOG = 256

# Timeout for the VNC server connection establishment / RFB handshake
DEFAULT_SERVER_TIMEOUT = 60.0

# Connect retries and delay between retries for the VNC server socket
DEFAULT_CONNECT_RETRIES = 3
DEFAULT_RETRY_WAIT = 0.1

# Connect timeout for the listening sockets
DEFAULT_CONNECT_TIMEOUT = 30

# By default, listen for client connections everywhere
DEFAULT_PROXY_LISTEN_ADDRESS = "*"

INADDR_ANY = [None, "*", "0.0.0.0", "::", "::0"]

# Port range for the listening sockets
#
# We must take care not to fall into the ephemeral port range,
# this can lead to transient failures to bind a chosen port.
#
# By default, Linux uses 32768 to 61000, see:
# http://www.ncftp.com/ncftpd/doc/misc/ephemeral_ports.html#Linux
# so 25000-30000 seems to be a sensible default.
#
# We also take into account the ports that Ganeti daemons bind to, the port
# range used by DRBD etc.
DEFAULT_MIN_PORT = 25000
DEFAULT_MAX_PORT = 30000

# SSL certificate / key files
DEFAULT_CERT_FILE = "/var/lib/vncauthproxy/cert.pem"
DEFAULT_KEY_FILE = "/var/lib/vncauthproxy/key.pem"

# Auth file
DEFAULT_AUTH_FILE = "/var/lib/vncauthproxy/users"

import os
import sys

# logging will import threading. Make sure to monkey patch threading before it
# gets loaded, to avoid an exception in the threading library (fixed in
# Python 3.3)
from gevent import monkey
monkey.patch_thread()

import logging
import gevent
import gevent.event
import daemon
import random
import daemon.runner
import crypt

from vncauthproxy import rfb
from vncauthproxy.websockets import (LoggedStream, LoggedStderr, VNCWS,
                                     VNCWebSocketWSGIApplication,
                                     VNCWSGIServer)
from vncauthproxy.circbuffer import CircularBuffer

try:
    import simplejson as json
except ImportError:
    import json

from gevent import socket, ssl
from signal import SIGINT, SIGTERM
from gevent.select import select

from lockfile import LockTimeout, AlreadyLocked
# Take care of differences between python-daemon versions.
try:
    from daemon import pidfile as pidlockfile
except ImportError:
    from daemon import pidlockfile


logger = None


class InternalError(Exception):
    """Exception for internal vncauthproxy errors"""
    pass


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

    def __init__(self, logger, client):
        """
        @type logger: logging.Logger
        @param logger: the logger to use
        @type client: socket.socket
        @param listeners: the client control connection socket

        """
        gevent.Greenlet.__init__(self)
        self.id = VncAuthProxy.id
        VncAuthProxy.id += 1
        self.log = logger
        self.client = client
        # A list of worker/forwarder greenlets, one for each direction
        self.workers = []
        self.listeners = []
        self.sport = None
        self.pool = None
        self.daddr = None
        self.dport = None
        self.server = None
        self.password = None
        self.dead_event = None
        self.client_connected = None
        self.client_rx = None
        self.client_tx = None
        self.ws = None
        self.ssl = None

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
        if self.pool is not None:
            self.pool.append(self.sport)
            self.debug("Returned port %d to port pool, contains %d ports",
                       self.sport, len(self.pool))

        self.info("Cleaned up connection, all done")
        raise gevent.GreenletExit

    def __str__(self):
        return "VncAuthProxy: %s:%d -> %s:%d" % (VncAuthProxy.proxy_address,
                                                 self.sport, self.daddr,
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

    def _perform_server_handshake(self):
        """
        Initiate a connection with the backend server and perform basic
        RFB 3.8 handshake with it.

        Return a socket connected to the backend server.

        """
        server = None

        tries = VncAuthProxy.connect_retries
        while tries:
            tries -= 1

            # Initiate server connection
            for res in socket.getaddrinfo(self.daddr, self.dport,
                                          socket.AF_UNSPEC,
                                          socket.SOCK_STREAM, 0,
                                          socket.AI_PASSIVE):
                af, socktype, proto, canonname, sa = res
                try:
                    server = socket.socket(af, socktype, proto)
                except socket.error:
                    server = None
                    continue

                # Set socket timeout for the initial handshake
                server.settimeout(VncAuthProxy.server_timeout)

                try:
                    self.debug("Connecting to %s:%s", *sa[:2])
                    server.connect(sa)
                    self.debug("Connection to %s:%s successful", *sa[:2])
                except socket.error:
                    self.debug("Failed to perform sever hanshake, retrying...")
                    server.close()
                    server = None
                    continue

                # We succesfully connected to the server
                tries = 0
                break

            # Wait and retry
            gevent.sleep(VncAuthProxy.retry_wait)

        if server is None:
            raise InternalError("Failed to connect to server")

        version = server.recv(1024)
        if not rfb.check_version(version):
            raise InternalError("Unsupported RFB version: %s"
                                % version.strip())

        server.send(rfb.RFB_VERSION_3_8 + "\n")

        res = server.recv(1024)
        types = rfb.parse_auth_request(res)
        if not types:
            raise InternalError("Error handshaking with the server")

        else:
            self.debug("Supported authentication types: %s",
                       " ".join([str(x) for x in types]))

        if rfb.RFB_AUTHTYPE_NONE not in types:
            raise InternalError("Error, server demands authentication")

        server.send(rfb.to_u8(rfb.RFB_AUTHTYPE_NONE))

        # Check authentication response
        res = server.recv(4)
        res = rfb.from_u32(res)

        if res != 0:
            raise InternalError("Authentication error")

        # Reset the timeout for the rest of the session
        server.settimeout(None)

        self.server = server

    def _establish_proxy(self):
        # Bridge both connections through the "forwarder" greenlets.
        # This greenlet will wait until any of the workers dies.
        # Final cleanup will take place in _cleanup().
        self.dead_event = gevent.event.Event()
        self.dead_event.clear()

        self.listeners = get_listening_sockets(self.sport,
                                               VncAuthProxy.proxy_address,
                                               reuse_addr=True)

        if self.ws:
            # To work around gevent's braindead direct-to-stderr logging, we
            # pass a fake stderr object which logs to a Python logger, see
            # definition of LoggedStream.
            logged_stderr = LoggedStream(sys.stderr, logger, logging.DEBUG,
                                         "WSGIServer stderr")

            # Create two circular buffers for server<->websocket client comms
            self.client_tx = CircularBuffer(16384)
            self.client_rx = CircularBuffer(16384)

            self.client_connected = gevent.event.Event()
            self.client_connected.clear()

            # FIXME: Atm, we only support the binary ws protocol
            wsgiapp = VNCWebSocketWSGIApplication(self.dead_event,
                                                  self.client_connected,
                                                  self._forward,
                                                  self.client_tx,
                                                  self.client_rx,
                                                  handler_cls=VNCWS,
                                                  protocols="binary")

            wsgiservers = []
            ssl_params = {}
            if self.ssl:
                ssl_params = {
                    'certfile': VncAuthProxy.certfile,
                    'keyfile': VncAuthProxy.keyfile
                }
            mutex = gevent.lock.Semaphore(1)
            for sock in self.listeners:
                # We set spawn=1 explicitly. "spawn=None" has the effect of
                # things running in the hub, see:
                # https://googlegroups/d/msg/gevent/T4PAVwmUXbI/4VegQeYxxmoJ
                # for all the details.
                wsgiservers.append(VNCWSGIServer(mutex, wsgiservers, sock,
                                                 wsgiapp, log=logged_stderr,
                                                 spawn=1, **ssl_params))
                worker = gevent.Greenlet(wsgiservers[-1].serve_forever)
                self.workers.append(worker)

    def _establish_connection(self):
        client = self.client
        ports = VncAuthProxy.ports

        # Receive and parse a client request.
        response = {
            "source_port": 0,
            "status": "FAILED",
            "proxy_address": None,
        }
        try:
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
            #     "auth_user":
            #         <user for control connection authentication>,
            #     "auth_password":
            #         <password for control connection authentication>,
            #     "type":
            #         <interface to use (vnc, vnc-ws, vnc-wss)>
            # }
            #
            # The <password> is used for MITM authentication of clients
            # connecting to <proxy_address:source_port>, who will subsequently
            # be forwarded to a VNC server listening at
            # <destination_address>:<destination_port>
            #
            # Control reply, in JSON:
            # {
            #     "source_port": <the allocated source port>
            #     "status": <one of "OK" or "FAILED">
            #     "proxy_address": <listening address / host  for client
            #                       connections>
            # }
            #
            buf = client.recv(1024)
            req = json.loads(buf)

            auth_user = req['auth_user']
            auth_password = req['auth_password']
            sport_orig = int(req['source_port'])
            self.daddr = req['destination_address']
            self.dport = int(req['destination_port'])
            self.password = req['password']
            console_type = req['type']

            supported_console_types = ["vnc", "vnc-ws", "vnc-wss"]
            if console_type not in supported_console_types:
                raise InternalError("%s not supported" % console_type)

            self.ws = console_type in ["vnc-ws", "vnc-wss"]
            self.ssl = console_type in ["vnc-wss"]

            if auth_user not in VncAuthProxy.authdb:
                msg = "vncauthproxy authentication failure: user not found"
                raise InternalError(msg)

            (cipher, salt, authdb_hash) = VncAuthProxy.authdb[auth_user]
            crypt_result = crypt.crypt(auth_password, '$%s$%s$' %
                                                      (cipher, salt))
            passhash = crypt_result.lstrip('$').split('$', 2)[-1]

            if passhash != authdb_hash:
                msg = "vncauthproxy authentication failure: wrong password"
                raise InternalError(msg)
        except KeyError:
            msg = "Malformed request: %s" % buf
            raise InternalError(msg)
        except InternalError as err:
            self.warn(err)
            response['reason'] = str(err)
            client.send(json.dumps(response))
            client.close()
            raise gevent.GreenletExit
        except Exception as err:
            self.exception(err)
            self.error("Unexpected error")
            client.send(json.dumps(response))
            client.close()
            raise gevent.GreenletExit

        server = None
        pool = None
        sport = sport_orig
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
                        self.debug("Port %d already taken", sport)

                self.debug("Got port %d from pool, %d remaining",
                           sport, len(ports))
                pool = ports

            self.sport = sport
            self.pool = pool

            self._perform_server_handshake()
            self._establish_proxy()

            self.info("New forwarding: %s:%d (client req'd: %d) -> %s:%d",
                      VncAuthProxy.proxy_address, sport, sport_orig,
                      self.daddr, self.dport)
            response = {"source_port": sport,
                        "status": "OK"}
            if VncAuthProxy.proxy_address not in INADDR_ANY:
                response["proxy_address"] = VncAuthProxy.proxy_address
            else:  # Return FQDN, since * is useless for the client
                response["proxy_address"] = VncAuthProxy.fqdn
        except IndexError:
            self.error("FAILED forwarding, out of ports for [req'd by "
                       "client: %s:%d -> %s:%d]",
                       VncAuthProxy.proxy_address, sport_orig, self.daddr,
                       self.dport)
            raise gevent.GreenletExit
        except InternalError as err:
            self.error(err)
            self.error(("FAILED forwarding: %s:%d (client req'd: %d) -> "
                        "%s:%d"), VncAuthProxy.proxy_address, sport,
                       sport_orig, self.daddr, self.dport)
            if pool:
                pool.append(sport)
                self.debug("Returned port %d to pool, %d remanining",
                           sport, len(pool))
            if server:
                server.close()
            raise gevent.GreenletExit
        except Exception as err:
            self.exception(err)
            self.error("Unexpected error")
            self.error(("FAILED forwarding: %s:%d (client req'd: %d) -> "
                        "%s:%d"), VncAuthProxy.proxy_address, sport,
                       sport_orig, self.daddr, self.dport)
            if pool:
                pool.append(sport)
                self.debug("Returned port %d to pool, %d remanining",
                           sport, len(pool))
            if server:
                server.close()
            raise gevent.GreenletExit
        finally:
            client.send(json.dumps(response))
            client.close()

    def _client_handshake(self, client_tx, client_rx):
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
        client_tx.send(rfb.RFB_VERSION_3_8 + "\n")
        client_version_str = client_rx.recv(1024)
        client_version = rfb.check_version(client_version_str)
        if not client_version:
            self.error("Invalid version: %s", client_version_str)
            raise gevent.GreenletExit

        # Both for RFB 3.3 and 3.8
        self.debug("Requesting authentication")
        auth_request = rfb.make_auth_request(rfb.RFB_AUTHTYPE_VNC,
                                             version=client_version)
        client_tx.send(auth_request)

        # The client gets to propose an authtype only for RFB 3.8
        if client_version == rfb.RFB_VERSION_3_8:
            res = client_rx.recv(1024)
            type = rfb.parse_client_authtype(res)
            if type == rfb.RFB_AUTHTYPE_ERROR:
                self.warn("Client refused authentication: %s", res[1:])
            else:
                self.debug("Client requested authtype %x", type)

            if type != rfb.RFB_AUTHTYPE_VNC:
                self.error("Wrong auth type: %d", type)
                client_tx.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
                raise gevent.GreenletExit

        # Generate the challenge
        challenge = os.urandom(16)
        client_tx.send(challenge)
        response = client_rx.recv(1024)
        if len(response) != 16:
            self.error("Wrong response length %d, should be 16", len(response))
            raise gevent.GreenletExit

        if rfb.check_password(challenge, response, self.password):
            self.debug("Authentication successful")
        else:
            self.warn("Authentication failed")
            client_tx.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
            raise gevent.GreenletExit

        # Accept the authentication
        client_tx.send(rfb.to_u32(rfb.RFB_AUTH_SUCCESS))

    def _proxy(self):
        try:
            # This callback will get called if any of the workers dies.
            def callback(g):
                self.debug("Worker %d/%d died", self.workers.index(g) + 1,
                           len(self.workers))
                if not self.ws or self.client_connected.is_set():
                    self.dead_event.set()

            self.info("Waiting for a client to connect at %s",
                      ", ".join(["%s:%d" % s.getsockname()[:2]
                                 for s in self.listeners]))

            if self.ws:
                for w in self.workers:
                    w.link(callback)
                    with LoggedStderr(logger, logging.DEBUG,
                                      "WSGIServer stderr"):
                        w.start()
                self.client_connected.wait(VncAuthProxy.connect_timeout)
                if not self.client_connected.is_set():
                    self.info("Timed out, no connection after %d sec",
                              VncAuthProxy.connect_timeout)
                    for w in self.workers:
                        w.kill()
                    raise gevent.GreenletExit

                for w in self.workers:
                    if w.dead:
                        self.workers.remove(w)

                self.client = self.client_tx
            else:
                rlist, _, _ = select(self.listeners, [], [],
                                     timeout=VncAuthProxy.connect_timeout)
                if not rlist:
                    self.info("Timed out, no connection after %d sec",
                              VncAuthProxy.connect_timeout)
                    raise gevent.GreenletExit

                for sock in rlist:
                    self.client, addrinfo = sock.accept()
                    self.info("Connection from %s:%d", *addrinfo[:2])

                    # Close all listening sockets, we only want a one-shot
                    # connection from a single client.
                    while self.listeners:
                        sock = self.listeners.pop().close()
                    break

                self.client_tx = self.client
                self.client_rx = self.client

            # Perform RFB handshake with the client.
            self._client_handshake(self.client_tx, self.client_rx)

            self.workers.append(gevent.spawn(self._forward,
                                             self.server, self.client_tx))
            self.workers.append(gevent.spawn(self._forward,
                                             self.client_rx, self.server))
            for g in self.workers[-2:]:
                g.link(callback)

            # Wait until any of the workers dies
            self.debug("Waiting for any of %d workers to die",
                       len(self.workers))
            self.dead_event.wait()

            # We can go now, _cleanup() will take care of
            # all worker, socket and port cleanup
            self.debug("A forwarder died, our work here is done")
            raise gevent.GreenletExit
        except Exception as err:
            # Any unhandled exception in the previous block
            # is an error and must be logged accordingly
            if not isinstance(err, gevent.GreenletExit):
                self.exception(err)
                self.error("Unexpected error")
            raise err
        finally:
            self._cleanup()

    def _run(self):
        self._establish_connection()
        self._proxy()

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


def get_listening_sockets(sport, saddr=None, reuse_addr=False):
    sockets = []

    # Use two sockets, one for IPv4, one for IPv6. IPv4-to-IPv6 mapped
    # addresses do not work reliably everywhere (under linux it may have
    # been disabled in /proc/sys/net/ipv6/bind_ipv6_only).
    for res in socket.getaddrinfo(saddr, sport, socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res
        try:
            s = None
            s = socket.socket(af, socktype, proto)

            if af == socket.AF_INET6:
                # Bind v6 only when AF_INET6, otherwise either v4 or v6 bind
                # will fail.
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

            if reuse_addr:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind(sa)
            s.listen(1)
            sockets.append(s)
            logger.debug("Listening on %s:%d", *sa[:2])
        except socket.error as err:
            logger.error("Error binding to %s:%d: %s", sa[0], sa[1], err[1])
            if s:
                s.close()
            while sockets:
                sockets.pop().close()

            # Make sure we fail immediately if we cannot get a socket
            raise InternalError(err)

    return sockets


def parse_auth_file(auth_file):
    users = {}

    if os.path.isfile(auth_file) is False:
        logger.warning("Authentication file not found. Continuing without "
                       "users")
        return users

    try:
        with open(auth_file) as f:
            lines = [l.strip().split(':', 1) for l in f.readlines()]
            for (user, passhash) in lines:
                users[user] = passhash.lstrip('$').split('$', 2)
    except ValueError as err:
        logger.exception(err)
        raise InternalError("Malformed auth file")

    if not users:
        logger.warning("No users defined")

    return users


def parse_arguments(args):
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      help="Enable debugging information")
    parser.add_option("--log", dest="log_file",
                      default=DEFAULT_LOG_FILE,
                      metavar="FILE",
                      help=("Write log to FILE (default: %s)" %
                            DEFAULT_LOG_FILE))
    parser.add_option('--pid-file', dest="pid_file",
                      default=DEFAULT_PID_FILE,
                      metavar='PIDFILE',
                      help=("Save PID to file (default: %s)" %
                            DEFAULT_PID_FILE))
    parser.add_option("--listen-address", dest="listen_address",
                      default=DEFAULT_LISTEN_ADDRESS,
                      metavar="LISTEN_ADDRESS",
                      help=("Address to listen for control connections"
                            "(default: 127.0.0.1)"))
    parser.add_option("--listen-port", dest="listen_port",
                      default=DEFAULT_LISTEN_PORT,
                      metavar="LISTEN_PORT",
                      help=("Port to listen for control connections"
                            "(default: %d)" % DEFAULT_LISTEN_PORT))
    parser.add_option("--server-timeout", dest="server_timeout",
                      default=DEFAULT_SERVER_TIMEOUT, type="float",
                      metavar="N",
                      help=("Wait for N seconds for the VNC server RFB "
                            "handshake (default %s)" % DEFAULT_SERVER_TIMEOUT))
    parser.add_option("--connect-retries", dest="connect_retries",
                      default=DEFAULT_CONNECT_RETRIES, type="int",
                      metavar="N",
                      help=("Retry N times to connect to the "
                            "server (default: %d)" %
                            DEFAULT_CONNECT_RETRIES))
    parser.add_option("--retry-wait", dest="retry_wait",
                      default=DEFAULT_RETRY_WAIT, type="float",
                      metavar="N",
                      help=("Wait N seconds before retrying "
                            "to connect to the server (default: %s)" %
                            DEFAULT_RETRY_WAIT))
    parser.add_option("--connect-timeout", dest="connect_timeout",
                      default=DEFAULT_CONNECT_TIMEOUT, type="int",
                      metavar="N",
                      help=("Wait N seconds for a client "
                            "to connect (default: %d)"
                            % DEFAULT_CONNECT_TIMEOUT))
    parser.add_option("-p", "--min-port", dest="min_port",
                      default=DEFAULT_MIN_PORT, type="int", metavar="MIN_PORT",
                      help=("The minimum port number to use for automatically-"
                            "allocated ephemeral ports (default: %s)" %
                            DEFAULT_MIN_PORT))
    parser.add_option("-P", "--max-port", dest="max_port",
                      default=DEFAULT_MAX_PORT, type="int", metavar="MAX_PORT",
                      help=("The maximum port number to use for automatically-"
                            "allocated ephemeral ports (default: %s)" %
                            DEFAULT_MAX_PORT))
    parser.add_option('--enable-ssl', dest="enable_ssl",
                      default=False, action='store_true',
                      help=("Enable SSL/TLS for control connections "
                            "(default: False"))
    parser.add_option('--cert-file', dest="cert_file",
                      default=DEFAULT_CERT_FILE,
                      metavar='CERTFILE',
                      help=("SSL certificate (default: %s)" %
                            DEFAULT_CERT_FILE))
    parser.add_option('--key-file', dest="key_file",
                      default=DEFAULT_KEY_FILE,
                      metavar='KEYFILE',
                      help=("SSL key (default: %s)" %
                            DEFAULT_KEY_FILE))
    parser.add_option('--auth-file', dest="auth_file",
                      default=DEFAULT_AUTH_FILE,
                      metavar='AUTHFILE',
                      help=("Authentication file (default: %s)" %
                            DEFAULT_AUTH_FILE))
    parser.add_option("--proxy-listen-address", dest="proxy_listen_address",
                      default=DEFAULT_PROXY_LISTEN_ADDRESS,
                      metavar="PROXY_LISTEN_ADDRESS",
                      help=("Address to listen for client connections"
                            "(default: *)"))

    (opts, args) = parser.parse_args(args)

    if args:
        parser.print_help()
        sys.exit(1)

    return opts


def main():
    """Run the daemon from the command line"""

    opts = parse_arguments(sys.argv[1:])

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

    try:
        # Create pidfile
        pidf = pidlockfile.TimeoutPIDLockFile(opts.pid_file, 10)

        # Init ephemeral port pool
        ports = range(opts.min_port, opts.max_port + 1)

        # Init VncAuthProxy class attributes
        VncAuthProxy.server_timeout = opts.server_timeout
        VncAuthProxy.connect_retries = opts.connect_retries
        VncAuthProxy.retry_wait = opts.retry_wait
        VncAuthProxy.connect_timeout = opts.connect_timeout
        VncAuthProxy.ports = ports

        VncAuthProxy.authdb = parse_auth_file(opts.auth_file)

        VncAuthProxy.keyfile = opts.key_file
        VncAuthProxy.certfile = opts.cert_file

        VncAuthProxy.proxy_address = opts.proxy_listen_address
        VncAuthProxy.fqdn = socket.getfqdn()

        sockets = get_listening_sockets(opts.listen_port, opts.listen_address,
                                        reuse_addr=True)

        wrap_ssl = lambda sock: sock
        if opts.enable_ssl:
            ssl_prot = ssl.PROTOCOL_TLSv1
            wrap_ssl = lambda sock: ssl.wrap_socket(sock, server_side=True,
                                                    keyfile=opts.key_file,
                                                    certfile=opts.cert_file,
                                                    ssl_version=ssl_prot)

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
            raise InternalError(("Failed to lock PID file %s, another "
                                 "instance running?"), pidf.path)

        logger.info("Became a daemon")

        # A fork() has occured while daemonizing,
        # we *must* reinit gevent
        gevent.reinit()

        # Catch signals to ensure graceful shutdown,
        #
        # Uses gevent.signal so the handler fires even during
        # gevent.socket.accept()
        gevent.signal(SIGINT, fatal_signal_handler, "SIGINT")
        gevent.signal(SIGTERM, fatal_signal_handler, "SIGTERM")
    except InternalError as err:
        logger.critical(err)
        sys.exit(1)
    except Exception as err:
        logger.critical("Unexpected error:")
        logger.exception(err)
        sys.exit(1)

    while True:
        try:
            client = None
            rlist, _, _ = select(sockets, [], [])
            for ctrl in rlist:
                client, _ = ctrl.accept()
                client = wrap_ssl(client)
                logger.info("New control connection")

                VncAuthProxy.spawn(logger, client)
            continue
        except Exception as err:
            logger.error("Unexpected error:")
            logger.exception(err)
            if client:
                client.close()
            continue
        except SystemExit:
            break

    try:
        logger.info("Closing control sockets")
        while sockets:
            sock = sockets.pop()
            sock.close()

        daemon_context.close()
        sys.exit(0)
    except Exception as err:
        logger.critical("Unexpected error:")
        logger.exception(err)
        sys.exit(1)
