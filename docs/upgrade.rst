Upgrade notes
^^^^^^^^^^^^^

v1.4next
========
Version 1.4next replaced Unix domain control sockets with TCP
control sockets. This change made it necessary to also introduce an
authentication file to replace the POSIX file permissions, which protected the
domain sockets.

The default path for the auth file is ``/var/lib/snf-vncauthproxy/users``
(configurable by the ``--auth-file`` option). Each line in the file represents
one user which is allowed to use the control socket and should be in the
following format:

.. code-block:: console

    user password
    user1 {cleartext}password
    user2 {HA1}md5hash

The Debian package provides an example users file.

Version 1.4next also introduced support for SSL for the control socket. If you
enable SSL support (``--enable-ssl`` parameter, disabled by default) you wil
have to provide a certficate and key file (``--cert-file`` and ``--key-file``
parameters).

If you're using snf-vncauthproxy with Synnefo, you should make sure to set the
``VNCAUTHPROXY_USER`` and ``VNCAUTHPROXY_PASSWORD`` options in
``/etc/synnefo/20-snf-cyclades-app-api.conf``. They should match a user defined
in snf-vncauthproxy's users (auth) file. You should also make sure that the
node running snf-cyclades-app can connect to the snf-vncauthproxy's control
socket address /port (the default deployment to run snf-vncauthproxy on the
same host with snf-cyclades-app should work with the defaults of
snf-vncauthproxy, with the exception of the authentiction file).
