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
  * Supports RFB protocol version 3.8
  * IPv4 and IPv6 support
  * Configurable timeout for client connections

Its main use is to enable VNC clients to connect to firwalled VNC servers.

It is used by `Synnefo <https://code.grnet.gr/projects/synnefo>`_ to provide
users with (VNC) console access to their VMs.

Installation
^^^^^^^^^^^^

snf-vncauthproxy is currently packaged only for Debian (stable / oldstable).

You can find and install the latest version snf-vncauthproxy at Synnefo's apt
repository:

| ``http://apt.dev.grnet.gr {release}``

To import the GPG key of the repo, use:

| ``curl https://dev.grnet.gr/files/apt-grnetdev.pub | apt-key add -``

Overview
^^^^^^^^

snf-vncauthproxy listens on a TCP socket for control (JSON) messages from clients.
The format of the control messages is:

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
     }

     The <password> is used for MITM authentication of clients
     connecting to <source_port>, who will subsequently be
     forwarded to a VNC server listening at
     <destination_address>:<destination_port>

     Control reply, in JSON:
     {
         "source_port": <the allocated source port>
         "status": <one of "OK" or "FAILED">
     }

snf-vncauthproxy will then spawn a greenlet to handle the incoming control
message, establish the connection with the server (RFB handshake) and set up a
listening socket for the client to connect (with a configurable timeout).

When the client connects, the greenlet will proxy the traffic between the
client and server (reading and writing to the client and server socket when
needed).

The handling of control connections, client connections and the actual proxying
is implemented using `gevent <http://www.gevent.org/>`_ and greenlets.

Usage
^^^^^

The snf-vncauthproxy daemon can be either run manually or managed via its init
script.

If you're using the init script, snf-vncauthproxy reads its paramater from its
default file (``DAEMON_OPTS`` parameter in ``/etc/default/vncauthproxy``).

By default snf-vncauthproxy will listen to ``127.0.0.1:24999`` TCP, for incoming
control connections and uses the ``25000-30000`` range for the listening / data
sockets.

Version 1.5 introduced replaced Unix domain control sockets with TCP
control sockets. This change made it necessary to also introduce an
authentication file to replace the Unix file permissions, which protected the
domain sockets.

The default path for the auth file is ``/var/lib/vncauthproxy/users``
(configurable by the ``--auth-file`` option). Each line in the file represents
one user which is allowed to use the control socket and should be in the
following format:

.. code-block:: console

    user password
    user1 {cleartext}password
    user2 {HA1}md5hash

The Debian package provides an example users file.

Version 1.5 introduced also support for SSL for the control socket. If you
enable SSL support (``--enable-ssl`` parameter, disabled by default) you wil
have to provide a certficate and key file (``--cert-file`` and ``--key-file``
parameters). The default values for certificate and key files are
``/var/lib/vncauthrpoxy/{cert,key}.pem`` respectively.

For detailed help on its configuration parameters, either consult its man page
or run:

| ``snf-vncauthproxy --help``

on the command line.

snf-vncauthproxy also provides a client which can be used to test from the
command line that snf-vncauhtproxy has been deployed correctly. It also
provides a method (``request_forwarding``) which can be used fron any Python
programm to request forwarding from the snf-vncauthproxy daemon.

See the client's usage / help output and the method's signature for more
information on how to use the them

Usage with Synnefo
==================

Synnefo (snf-cyclades-app) uses snf-vncauthproxy to provide users (VNC) console
access to their VMs.

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

In case you want to deploy snf-vncauthproxy on a different host than
snf-cyclades-app, you should make sure that you change the default listening
address (and / or port) for snf-vncauthproxy and make sure that
snf-cyclades-app can connect to the snf-vncauthproxy on the listening address /
port. It's also recommended to enable SSL on the control socket in that case.

.. include:: changelog.rst

.. include:: upgrade.rst

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
