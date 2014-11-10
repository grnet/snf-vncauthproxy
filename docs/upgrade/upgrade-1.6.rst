Upgrade notes
^^^^^^^^^^^^^

v1.6
====
Version 1.6 added support for the `Websockets <http://tools.ietf.org/html/rfc6455>`_
(HTML5) protocol. In order to support ``vnc-wss`` (VNC over a secure (TLS)
Websocket channel) snf-vncauthproxy will need to be configured with a pair of
private / public SSL (PEM) certificates. Otherwise, any client request with
type of ``vnc-wss`` will fail.

To support the new WebSocket functionality, the client (``client.py`` and the
``request_forwarding`` method) was modified to include the ``type`` in the json
request to the proxy. To retain backwards compatibility, if no type is
requested, it defaults to plain ``vnc``.
