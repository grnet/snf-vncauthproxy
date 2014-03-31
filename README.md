snf-vncauthproxy
=================

Overview
--------

snf-vncauthproxy is a small gevent-based VNC proxy with man-in-the-middle
authentication.

snf-vncauthproxy listens on a control channel (TCP socket) for control messages
and sets up one-time port forwardings upon request. As soon as a client
connects, vncauthproxy fakes an RFB 3.8 server to request authentication from
the client. If the client authenticates successfully, a server connection is
initiated by the proxy and both connections are bridged to allow transparent
client-server communication.

Features include:
* Lightweight, coroutine-based main loop with gevent
* JSON-formatted requests and replies over the control channel
* Port pooling for automatic selection of source port
* Supports RFB protocol versions 3.3, 3.8
* IPv4 and IPv6 support
* Configurable timeout for client connections
* Control channel over TCP, allowing isolated operation of VNC proxy clusters


Project Page
------------

Please see the [official Synnefo site](http://www.synnefo.org) and the
[latest snf-vncauthproxy docs](http://www.synnefo.org/docs/snf-vncauthproxy/latest/index.html)
for more information.


Copyright and license
=====================

Copyright (C) 2010-2014 GRNET S.A.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.
