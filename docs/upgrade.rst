Upgrade notes
^^^^^^^^^^^^^

v1.5
====
Version 1.5 replaced Unix domain control sockets with TCP
control sockets. This change made it necessary to also introduce an
authentication file to replace the POSIX file permissions, which protected the
domain sockets.

The default path for the auth file is ``/var/lib/vncauthproxy/users``
(configurable by the ``--auth-file`` option). Each line in the file represents
one user which is allowed to use the control socket and should be in the
following format:

.. code-block:: console

    user password
    user1 {cleartext}password
    user2 {HA1}md5hash

If you want to use a hash instead of a password, you should provide the MD5
digest of the string ``user:vncauthproxy:password``. It can be generated with
the following command:

.. code-block:: console

    $ echo -n 'user:vncauthproxy:password' | openssl md5

The Debian package provides an example users file.

Version 1.5 also introduced support for SSL for the control socket. If you
enable SSL support (``--enable-ssl`` parameter, disabled by default) you will
have to provide a certficate and key file (``--cert-file`` and ``--key-file``
parameters). The default values for certificate and key files are
``/var/lib/vncauthrpoxy/{cert,key}.pem`` respectively.

If you're using snf-vncauthproxy with Synnefo, you should make sure to edit the
``CYCLADES_VNCAUTHPROXY_OPTS`` setting in
``/etc/synnefo/20-snf-cyclades-app-api.conf``.  The
``CYCLADES_VNCAUTHPROXY_OPTS`` dict in
``/etc/synnefo/20-snf-cyclades-app-api.conf`` should be edited to match
snf-vncauthproxy configuration (user, password, SSL support, certificate file).
You should also make sure that the node running snf-cyclades-app can connect to
the snf-vncauthproxy's control socket address / port (the suggested deployment to
run snf-vncauthproxy on the same host as snf-cyclades-app should work with
the defaults of snf-vncauthproxy, with the exception of the authentication
file).
