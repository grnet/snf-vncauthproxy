.. snf-vncauthproxy documentation master file, created by
   sphinx-quickstart on Thu Nov 14 20:47:22 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

snf-vncauthproxy's documentation
********************************

snf-vncauthproxy is a daemon, which acts as a VNC authentication proxy between
a VNC client and server.

snf-vncauthproxy daemon listens on a TCP socket for control messages and sets
up one-time port forwardings upon request.

Main features include:
  * Lightweight, coroutine-based main loop with gevent
  * Support for the RFB protocol version 3.8
  * IPv4 and IPv6 support
  * Configurable timeout for client connections
  * Support for HTML5 WebSocket clients

Its main use is to enable VNC clients to connect to firewalled VNC servers.

It is used by `Synnefo <https://code.grnet.gr/projects/synnefo>`_ to provide
users with (VNC) console access to their VMs.

Installation
^^^^^^^^^^^^

snf-vncauthproxy is currently packaged only for Debian (stable).

You can find and install the latest version snf-vncauthproxy at Synnefo's apt
repository:

| ``http://apt.dev.grnet.gr {release}``

To import the GPG key of the repo, use:

| ``curl https://dev.grnet.gr/files/apt-grnetdev.pub | apt-key add -``

In case you're upgrading from an older snf-vncauthproxy version or it's the
first time you're installing snf-vncauthproxy, you should create a vncauthproxy
user, in order to have a functional vncauthproxy installation (see below for
more information on user management).

Overview
^^^^^^^^

snf-vncauthproxy listens on a TCP socket for control (JSON) messages from
clients. The format of the control messages is:

.. code-block:: console

     Control request, in JSON:
     {
         "source_port":
             <source port or 0 for automatic allocation>,
         "destination_address":
             <destination address of backend server>,
         "destination_port":
             <destination port>
         "password":
             <the password to use to authenticate clients>
         "auth_user":
             <user for control connection authentication>,
          "auth_password":
             <password for control connection authentication>,
          "type":
             <interface to use (vnc, vnc-ws, vnc-wss)>,
     }

     The <password> is used for MITM authentication of clients
     connecting to <proxy_address:source_port>, who will subsequently be
     forwarded to a VNC server listening at
     <destination_address>:<destination_port>

     Control reply, in JSON:
     {
         "source_port": <the allocated source port>
         "status": <one of "OK" or "FAILED">
         "proxy_address": <listening address / host  for client
                           connections>
     }

snf-vncauthproxy will then spawn a greenlet to handle the incoming control
message, establish the connection with the server (RFB handshake) and set up a
listening socket for the client to connect (with a configurable timeout).

When the client connects, the greenlet will proxy the traffic between the
client and server (reading and writing to the client and server socket when
needed).

The handling of control connections, client connections and the actual proxying
is implemented using `gevent <http://www.gevent.org/>`_ and greenlets.

Since release 1.6, snf-vncauthproxy supports configurable client socket
'types'. The client can request a specific type, via the json control request.
The ``vnc`` type will behave the same way as pre-1.6 releases (i.e. plain RFB over
TCP), while ``vnc-ws`` and ``vnc-wss`` will set up an (HTTP(s)) WebSocket server for
HTML5 clients (eg noVNC). In the case of ``vnc-wss``, you will need to provide
snf-vncauthproxy with a public and private SSL certificate (in PEM format --
see below).

The WebSocket support uses `WS4PY <https://ws4py.readthedocs.org/en/latest/>`_
and the ``gevent.pywsgi`` WSGI server.

Usage
^^^^^

The snf-vncauthproxy daemon can be either run manually or managed via its init
script.

If you're using the init script, snf-vncauthproxy reads its options from its
default file (``DAEMON_OPTS`` parameter in ``/etc/default/vncauthproxy``).
Refer to the vncauthproxy help output for a detailed listing and information
on all available options:

.. code-block:: console

    # vncauthproxy --help

By default snf-vncauthproxy will listen to ``127.0.0.1:24999`` TCP, for
incoming control connections and uses the ``25000-30000`` range for the
listening / data sockets.

Version 1.5 replaced Unix domain control sockets with TCP control sockets. This
change made it necessary to introduce an authentication file to replace the
POSIX file permissions, which protected the domain sockets.

The default path for the auth file is ``/var/lib/vncauthproxy/users``
(configurable by the ``--auth-file`` option). Each line in the file represents
one user which is allowed to use the control socket and should be in the
following format:

.. code-block:: console

    username:$6$salt$hash

The password part of the line (after the colon) is the output of crypt(), using
a random 16-char salt with SHA-512.

To manage the authentication file, you can use the vncauthproxy-passwd tool,
to easily add, update and delete users:

To add a user:

.. code-block:: console

    # vncauthproxy-passwd /var/lib/vncauthproxy/users user

You will be prompted for a password.

To delete a user:

.. code-block:: console

    # vncauthproxy-passwd -D /var/lib/vncauthproxy/users user

See the help output of the tool for more options:

.. code-block:: console

    # vncauthproxy-passwd -h

.. warning:: The vncauthproxy daemon requires a restart for the changes in the
 authentication file to take effect.

.. warning:: After installing snf-vncauthproxy for the fist time, make sure
 that you create a valid authentication file and define any users needed. The
 vncauthproxy daemon will start but will not be usable if no users are defined
 or if no authentication file is present.

Version 1.5 introduced also support for SSL for the control socket. If you
enable SSL support (``--enable-ssl`` parameter, disabled by default) you will
have to provide a certificate and key file (``--cert-file`` and ``--key-file``
parameters). The default values for certificate and key files are
``/var/lib/vncauthrpoxy/{cert,key}.pem`` respectively.

With version 1.6, the private and public certificates are necessary for the
secure WebSocket (``vnc-wss``) console type. Otherwise, any ``vnc-wss`` request
will fail.

For detailed help on its configuration parameters, either consult its man page
or run:

| ``snf-vncauthproxy --help``

on the command line.

snf-vncauthproxy also provides a client which can be used to test from the
command line that snf-vncauhtproxy has been deployed correctly. It also
provides a method (``request_forwarding``) which can be used from any Python
program to request forwarding from the snf-vncauthproxy daemon.

See the client's usage / help output and the method's signature for more
information on how to use the them

Regarding the WebSocket functionality, ``snf-authproxy`` will try to use
``wsaccell`` (WebSockets accelerator), if installed (currently not in the
Debian repos), to patch ``ws4py``.

Usage with Synnefo
==================

Synnefo (snf-cyclades-app) uses snf-vncauthproxy to provide users (VNC) console
access to their VMs. In release 0.16, the Java (applet) VNC client was replaced
with an HTML5 WebSocket client (noVNC).

Synnefo uses `Ganeti <https://code.google.com/p/ganeti/>`_ and KVM for the
cluster and VM management. In the common case the Ganeti nodes, running the KVM
instances are firewalled, and only the Cyclades (Compute) app server
(snf-cyclades-app) is publicly accessible. In order for users to be able to
access the VNC console /server (spawned by the KVM instances on the Ganeti
nodes), snf-cyclades-app uses snf-vncauthproxy to allow users to connect to the
VNC servers and access the VNC consoles of their VMs.

If you're running snf-vncauthproxy on the same host as snf-cyclades-app,
you will only need to configure one Synnefo setting. Specifically,
the ``CYCLADES_VNCAUTHPROXY_OPTS`` dict in
``/etc/synnefo/20-snf-cyclades-app-api.conf`` should be edited to match
snf-vncauthproxy configuration (user, password, SSL support, certificate file).

In case you want to deploy snf-vncauthproxy on a different host other than
snf-cyclades-app, you should make sure that you change the default listening
address (and / or port) and the proxy address (``--proxy-listen-address``) for
snf-vncauthproxy and make sure that snf-cyclades-app can connect to the
snf-vncauthproxy on the listening address / port and that clients can connect
to the proxy address.  It's also recommended to enable SSL on the control
socket in that case. You can refer to the Synnefo `admin guide
<https://www.synnefo.org/docs/synnefo/latest/admin-guide.html#admin-guide-vnc`_
for more information.

Starting with v0.16, Synnefo supports WebSockets for the VNC console (the
Synnefo Compute API supports all the 'console types' supported by
``snf-vncauthproxy``, ie ``vnc``, ``vnc-ws`` and ``vnc-wss``).

The Synnefo UI was also updated to include a WebSockets / HTML5 VNC client
(`noVNC <http://github.com/kanaka/noVNC>`_)` and by default requests a
``vnc-wss`` console. This means that in order to avoid browser issues / warning
about insecure certificates and have a functional / working Synnefo out-of-band VM
access / console, you should either provide ``snf-vncauthrpoxy`` with SSL
certificates signed by a trusted CA or pre-accept a self-signed certificate.
Note that there is currently a known issue with Firefox requiring the user to
accept self-signed / untrusted certificates for each different destination
port. This means that using Firefox to access the Synnefo console, while
running ``snf-vncauthproxy`` with self-signed certificates, won't work.

Please refer to the Synnefo `documentation
<https://www.synnefo.org/docs/synnefo/latest/admin-guide.html>`_ for detailed
instructions on setting up your own CA and importing the CA certificate into
your browser.

Changelog
^^^^^^^^^

* v1.6 :ref:`Changelog <Changelog-1.6>`
* v1.5 :ref:`Changelog <Changelog-1.5>`

Upgrade notes
^^^^^^^^^^^^^

.. toctree::
   :maxdepth: 1

    v1.5 -> v1.6 <upgrade/upgrade-1.6.rst>
    v1.4 -> v1.5 <upgrade/upgrade-1.5.rst>

Contact
^^^^^^^

For questions or bug reports you can contact the Synnefo team at the following
mailing lists:

 * Users list: synnefo@googlegroups.com
 * Developers list: synnefo-devel@googlegroups.com

License
^^^^^^^

snf-vncauthproxy is licensed under GNU Generic Public License version 2
(GPLv2), please see LICENSE for the full text.
