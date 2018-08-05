# Accessing Electrum Personal Server remotely

While it is possible to allow access to Electrum Personal Server
remotely, it may compromise your privacy if done without
consideration.  For more details on the risks, see: [Using Electrum
Personal Server and Electrum with a
smartphone](https://github.com/chris-belcher/electrum-personal-server/issues/36).

A solution to this problem would be accessing Electrum Personal Server
over Tor.  There are two kinds of hidden services supported by Tor:
version 2, and version 3.  While a version 2 hidden service is not
entirely private, it is possible to set it up with basic
authentication, allowing you to limit access to the onion address.  A
version 3 hidden service on the other hand, is entirely private.
Unless you share the onion address of your hidden service publicly,
your privacy won't be violated.

# Accessing Electrum Personal service as a Tor Hidden Service

At present there are two ways to configure a hidden service,
1. by editing the `torrc` of your Tor installation, and
2. by creating an ephemeral hidden service.
While (1) allows you to configure both kinds of hidden services, only
version 2 ephemeral hidden services are supported at the moment.

## Configuring a Tor Hidden Service with `torrc`

You can setup a version 3 hidden service with the following lines in
your `torrc`.

    HiddenServiceDir /var/lib/tor/eps_hsv/
    HiddenServiceVersion 3
    HiddenServicePort 50002 127.0.0.1:50002

A version 3 onion address is private by default, so it is sufficient
keep the onion address secret.  You can find the address in the file
`/var/lib/tor/eps_hsv/hostname`.

## Configuring an Ephemeral Tor Hidden Service

The other option is to start an ephemeral, version 2, hidden service
with basic authentication.  The `electrum-personal-server` script
supports this method.  It also saves the private keys so that on
subsequent runs the hidden service can be restarted with the same
onion address and authentication credentials.

On first run, start as:

    $ electrum-personal-server -c /path/to/config.cfg -t

If a hidden service is started successfully, a new configuration file
with the hidden service configuration is written out to
`/path/to/config.cfg_updated`.  A new configuration file is written
out as updating the original would lose any comments that are present.
The script also logs the onion address and the authentication
credentials to standard error and the log file by default; reducing
verbosity (increasing the log level), suppresses this output.  You can
merge the configuration files before restarting the script to start
the same hidden service again.

To use this option, you need to install the Tor Python bindings.  You
can either use your system's package manager, e.g. on Fedora

    $ sudo dnf install python3-stem

You could also use pip to install `stem`:

    $ pip3 install --user stem

As Tor is an optional feature, it is not installed as a dependency
during the initial installation process.

# Client side configuration

For a version 3 hidden service, there is no need for special
configuration on the client side.  For a version 2 service with basic
authentication, you need to add the onion address and the
authentication credentials when starting Tor.  In case of Orbot, you
may do this in the "Hidden Services" menu under "Client cookies".
