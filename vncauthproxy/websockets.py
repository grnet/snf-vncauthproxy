#!/usr/bin/env python
#
# Copyright (c) 2014 Greek Research and Technology Network S.A.
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
import gevent

from ws4py import websocket
from ws4py.server.geventserver import \
    WSGIServer as _ws4py_WSGIServer, \
    WebSocketWSGIHandler as _ws4py_WebSocketWSGIHandler
from ws4py.server.wsgiutils import \
    WebSocketWSGIApplication as _ws4py_WebSocketWSGIApplication
from ws4py.exc import HandshakeError

try:
    import wsaccel
    wsaccel.patch_ws4py()
except ImportError:
    pass

import logging

logger = logging.getLogger(__name__)


# We need to subclass gevent's WSGIServer because
# it logs errors directly to stderr, which doesn't make much
# sense. It's been open as a gevent bug since Nov 2011.
#
# https://github.com/surfly/gevent/issues/106
# https://github.com/surfly/gevent/issues/106
# https://groups.google.com/forum/?fromgroups=#!topic/gevent/WXK7N0AevXI
class LoggedStream(object):
    """File-like stream object that redirects all writes to a logger."""
    def __init__(self, stream, logger, log_level=logging.INFO,
                 description=""):
        self.logger = logger
        self.log_level = log_level
        self.description = description

        self.original_stream = stream

    def write(self, msg):
        for line in msg.rstrip().splitlines():
            self.logger.log(self.log_level, "%s: %s", self.description,
                            line.rstrip())

    def __getattr__(self, name):
        return getattr(self.original_stream, name)


class LoggedStderr(object):
    def __init__(self, logger, log_level=logging.INFO, description="stderr"):
        self.logger = logger
        self.log_level = log_level
        self.description = description

        self.original_stderr = sys.stderr

    def __enter__(self):
        sys.stderr = LoggedStream(sys.stderr, self.logger, self.log_level,
                                  self.description)

    def __exit__(self, type, value, traceback):
        sys.stderr = self.original_stderr


class VNCWebSocketWSGIHandler(_ws4py_WebSocketWSGIHandler):
    def log_error(self, *args, **kwargs):
        with LoggedStderr(logger, logging.DEBUG, "WSGIHandle stderr"):
            super(VNCWebSocketWSGIHandler, self).log_error(*args,
                                                           **kwargs)

    def handle_one_request(self, *args, **kwargs):
        with LoggedStderr(logger, logging.DEBUG, "WSGIHandler stderr"):
            super_inst = super(VNCWebSocketWSGIHandler, self)
            super_inst.handle_one_request(*args, **kwargs)


class VNCWSGIServer(_ws4py_WSGIServer):
    handler_class = VNCWebSocketWSGIHandler

    def log_error(self, *args, **kwargs):
        with LoggedStderr(logger, logging.DEBUG, "WSGIServer stderr"):
            super(VNCWSGIServer, self).log_error(*args, **kwargs)

    def __init__(self, mutex, servers, *args, **kwargs):
        super(VNCWSGIServer, self).__init__(*args, **kwargs)
        self._servers = servers
        self._mutex = mutex

    def handle(self, *args, **kwargs):
        try:
            if self._mutex.acquire(blocking=True):
                for s in self._servers:
                    if s != self:
                        s.stop()
                super(VNCWSGIServer, self).handle(*args, **kwargs)
        finally:
            self._mutex.release()

    def wrap_socket_and_handle(self, *args, **kwargs):
        with LoggedStderr(logger, logging.INFO, "WSGIServer stderr"):
            try:
                super(VNCWSGIServer, self).wrap_socket_and_handle(*args,
                                                                  **kwargs)
            # FIXME: Raise an exception in case of a non-SSL error?
            except Exception as e:
                logger.error("Exception (%s): %s" % (self, e))

    def serve_forever(self, *args, **kwargs):
        with LoggedStderr(logger, logging.INFO, "WSGIServer stderr"):
            try:
                super(VNCWSGIServer, self).serve_forever(*args, **kwargs)
            except gevent.GreenletExit:
                pass
            except Exception as e:
                logger.error("Exception (%s): %s" % (self, e))
                self.stop()


class VNCWebSocketWSGIApplication(_ws4py_WebSocketWSGIApplication):
    def __init__(self, dead, connected, forward, server_rx, server_tx, *args,
                 **kwargs):
        super(VNCWebSocketWSGIApplication, self).__init__(*args, **kwargs)
        self._forward = forward
        self._server_rx = server_rx
        self._server_tx = server_tx
        self._single = gevent.coros.Semaphore(1)
        self._dead = dead
        self._connected = connected

    def make_websocket(self, sock, protocols, extensions, environ):
        """
        Initialize the `handler_cls` instance with the given
        negociated sets of protocols and extensions as well as
        the `environ` and `sock`.

        Stores then the instance in the `environ` dict
        under the `'ws4py.websocket'` key.
        """
        websocket = self.handler_cls(self._dead, self._connected, self._single,
                                     self._forward, self._server_rx,
                                     self._server_tx, sock, protocols,
                                     extensions, environ.copy())
        environ['ws4py.websocket'] = websocket
        return websocket

    def __call__(self, environ, start_response):
        try:
            super(VNCWebSocketWSGIApplication, self).__call__(environ,
                                                              start_response)
        except HandshakeError as e:
            logger.info("Handshake error %s" % e)
            start_response("400 Bad Request", [('Content-Type', 'text/html')])
            return []
        except Exception as e:
            logger.error("Unexpected error %s" % e)
            start_response("500 Internal Server Error",
                           [('Content-Type', 'text/html')])
            return []


class VNCWS(websocket.WebSocket):
    def __init__(self, dead, connected, single, forward, server_rx, server_tx,
                 *args, **kwargs):
        super(VNCWS, self).__init__(*args, **kwargs)
        self._single = single
        self._worker = None
        self._worker_callback = None
        self._forward = forward
        self._server_rx = server_rx
        self._server_tx = server_tx
        self._dead = dead
        self._primary = False
        self._connected = connected

    def opened(self):
        """Called when WebSocket is first opened."""
        # Ensure only a single Websocket per WSGIServer is active,
        # i.e., only a single client connection is serviced
        if not self._single.acquire(blocking=False):
            self.close(1001, reason="Only a single connection allowed")
            return
        self._primary = True
        self._connected.set()

        # Create a forwarding greenlet to handle server->client traffic.
        # Ensure this WebSocket is notified and closed, when the greenlet dies.
        def callback(glet):
            logger.debug("Worker died, closing client WebSocket")
            self.close(1001, reason="Server connection went away")

        self._worker = gevent.spawn(self._forward, self._server_rx, self)
        self._worker_callback = callback
        self._worker.link(self._worker_callback)
        logger.debug("Created worker for server->client forwarding")

    def closed(self, code, reason=None):
        # This WebSocket has been closed, ensure the associated worker
        # is killed and cleaned up
        logger.info("Client WebSocket closed, code = %s, reason = %s",
                    code, reason)
        if self._worker:
            # The WebSocket has already been closed,
            # unlink the worker greenlet from the callback
            self._worker.unlink(self._worker_callback)
            self._worker.kill(block=True)
        logger.debug("Cleaned up worker greenlet")
        if self._primary:
            self._dead.set()

    def received_message(self, message):
        """Process message received from WebSocket.

        Process a message that has been received from the WebSocket,
        by forwarding it to the server socket at the backend.

        """
        self._server_tx.sendall(message.data)

    def sendall(self, payload):
        self.send(payload, binary=True)
