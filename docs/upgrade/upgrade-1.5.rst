Upgrade notes
^^^^^^^^^^^^^

v1.5
====
Version 1.5 replaced Unix domain control sockets with TCP control sockets. This
change made it necessary to introduce an authentication file to replace the
POSIX file permissions, which protected the domain sockets.

You can configure vncauthproxy daemon by modifying the Debian default file
(``/etc/default/vncauthproxy``) and more specifically the ``DAEMON_OPTS``
variable. This option (along with the modified ``CHUID`` option) has been added
to the v1.5 default file (which you'll need to 'merge' if you're upgrading from
an older version of snf-vncauthproxy).

The ``DAEMON_OPTS`` variable accepts any valid option you can pass to the
vncauthproxy daemon on the command line. For a detailed listing and information
about the avaialble options plese check vncauthproxy help output:

.. code-block:: console

    # vncauthproxy --help

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

Finally, snf-vncauthproxy now adds a user and group (``vncauthproxy``) to be
used by the vncauthproxy daemon. As a result the ``CHUID`` option in the Debian
default file (``/etc/default/vncauthproxy``) has changed accordingly. Although
it is recommended to run vncauhtproxy with the predfined user and group, it's
not mandatory.
