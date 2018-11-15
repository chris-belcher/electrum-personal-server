# Electrum Personal Server

Electrum Personal Server aims to make using Electrum bitcoin wallet more secure
and more private. It makes it easy to connect your Electrum wallet to your own
full node.

It is an implementation of the Electrum server protocol which fulfills the
specific need of using the Electrum wallet backed by a full node, but without
the heavyweight server backend, for a single user. It allows the user to
benefit from all of Bitcoin Core's resource-saving features like
[pruning](https://bitcoin.org/en/release/v0.12.0#wallet-pruning),
[blocksonly](https://bitcointalk.org/index.php?topic=1377345.0) and disabled
txindex. All of Electrum's feature-richness like hardware wallet integration,
[multisignature wallets](http://docs.electrum.org/en/latest/multisig.html),
[offline signing](http://docs.electrum.org/en/latest/coldstorage.html),
[seed recovery phrases](https://en.bitcoin.it/wiki/Seed_phrase), coin control
and so on can still be used, but connected only to the user's own full node.

Full node wallets are important in bitcoin because they are an big part of what
makes the system be trustless. No longer do people have to trust a financial
institution like a bank or paypal, they can run software on their own
computers. If bitcoin is digital gold, then a full node wallet is your own
personal goldsmith who checks for you that received payments are genuine.

Full node wallets are also important for privacy. Using Electrum under default
configuration requires it to send (hashes of) all your bitcoin addresses to some
server. That server can then easily spy on your transactions. Full node
wallets like Electrum Personal Server would download the entire blockchain and
scan it for the user's own addresses, and therefore don't reveal to anyone else
which bitcoin addresses they are interested in.

For a longer explaination of this project, see the
[mailing list email](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-February/015707.html)
and [bitcointalk thread](https://bitcointalk.org/index.php?topic=2664747.msg27179198).
See also the Bitcoin Wiki [pages](https://en.bitcoin.it/wiki/Clearing_Up_Misconceptions_About_Full_Nodes)
on [full nodes](https://en.bitcoin.it/wiki/Full_node).

## How To

* If you dont already have them, download and install python3 and Bitcoin Core
  version 0.16 or higher. Make sure you
  [verify the digital signatures](https://bitcoin.stackexchange.com/questions/50185/how-to-verify-bitcoin-core-release-signing-keys)
  of any binaries before running them, or compile from source. The Bitcoin node
  must have wallet enabled, and must have the RPC server switched on (`server=1`
  in bitcoin.conf).

* If you dont already have it, download and install
  [Electrum bitcoin wallet](https://electrum.org/), and set up your Electrum
  wallet (for example by linking your hardware wallet). To avoid damaging
  privacy by connecting to public Electrum servers, disconnect from the
  internet first or run Electrum with the command line argument
  `--server localhost:50002:s`.

* Download the [latest release](https://github.com/chris-belcher/electrum-personal-server/releases)
  of Electrum Personal Server. Enter the directory and rename the file
  `config.cfg_sample` to `config.cfg`.

* Edit the file `config.cfg` to configure everything about the server. Add your
  wallet master public keys or watch-only addresses to the
  `[master-public-keys]` and `[watch-only-addresses]` sections. Master public
  keys for an Electrum wallet (which start with xpub/ypub/zpub) can be found
  in the Electrum client menu `Wallet` -> `Information`.

* Install Electrum Personal Server in your home directory with
  `pip3 install --user .`.  On Linux the scripts
  (`electrum-personal-server` and `electrum-personal-server-rescan`) will be
  installed in `~/.local/bin`.

* Run `electrum-personal-server /path/to/config.cfg` to start Electrum
  Personal Server. The first time the server is run it will import all
  configured addresses as watch-only into the Bitcoin node, and then exit.
  If the wallets contain historical transactions you can use the rescan script
  (`electrum-personal-server-rescan /path/to/config.cfg`) to make them appear.

* Run the server again which will start Electrum Personal Server. Wait until
  the message `Listening for Electrum Wallet ...` appears and then tell
  Electrum to connect to the server in `Tools` -> `Server`. By default the
  server details are `localhost` if running on the same machine. Make sure the
  port number matches what is written in `config.cfg` (port 50002 by default).

A guide for installing Electrum Personal Server on a Raspberry Pi can be found
[here](https://github.com/Stadicus/guides/blob/master/raspibolt/raspibolt_64_electrum.md).

Pro Tip: run Electrum wallet with the command line arguments `--oneserver --server localhost:50002:s`.
This stops Electrum connecting to several other servers to obtain block
headers; and locks Electrum to connect only to your server, disabling the GUI
button to stop accidental connections. This helps avoid a user accidentally
ruining their privacy by connecting to public Electrum servers.

#### Exposure to the Internet

Right now, Electrum Personal Server is easiest to use when it, your full node
and your Electrum wallet are all on the same computer.

Other people should not be connecting to your server. They won't be
able to synchronize their wallet, and they could potentially learn all your
wallet transactions. By default the server will accept connections only from
`localhost`, though this can be changed in the configuration file.

The whitelisting feature can be used accept only certain IP addresses ranges
connecting to the server. The Electrum protocol uses SSL for encryption. If
your wallet connects over the public internet you should generate your own
SSL certificate instead of using the default one, otherwise your connection
can be decrypted. See the configuration file for instruction on how to do
this.

Another option is to use a SSH tunnel to reach Electrum Personal Server. SSH
connections are encrypted and authenticated. This can be done on the command
line with: `ssh username@host -L 50002:localhost:50002` or with [Putty](https://www.putty.org/)
for Windows. Then connect Electrum to localhost, and SSH will forward that
connection to the server.

#### How is this different from other Electrum servers ?

They are different approaches with different tradeoffs. Electrum Personal
Server is compatible with pruning, blocksonly and txindex=0, uses less CPU and
RAM, is suitable for being used intermittently rather than needing to be
always-on, and doesn't require an index of every bitcoin address ever used. The
tradeoff is when recovering an old wallet, you must to import your wallet first
and you may need to rescan, so it loses the "instant on" feature of Electrum
wallet. Other Electrum server implementations will be able to sync your wallet
immediately even if you have historical transactions, and they can serve
multiple Electrum connections at once.

Traditional Electrum servers inherently are not very scalable and use many
resources which push people towards using centralized solutions. This is what
we'd like to avoid with Electrum Personal Server.

Definitely check out implementations like [ElectrumX](https://github.com/kyuupichan/electrumx/) if you're interested in this sort of thing.

#### Caveat about pruning

Electrum Personal Server is fully compatible with pruning, except for one thing.
Merkle proofs are read from disk. If pruning is enabled and if that specific
block has been deleted from disk, then no merkle proof can be sent to Electrum
which will display the transaction as `Not Verified` in the wallet interface.

One day this may be improved on by writing new code for Bitcoin Core. See the
discussion [here](https://bitcointalk.org/index.php?topic=3167572.0).

#### Further ideas for work

* It would be cool to have a GUI front-end for this. So less technical users
can set up a personal server helped by a GUI wizard for configuring that
explains everything. With the rescan script built-in.

* An option to broadcast transactions over tor, so that transaction broadcasting
doesn't leak the user's IP address.

* The above mentioned caveat about pruning could be improved by writing new code
for Bitcoin Core.

## Contributing

Donate to help make Electrum Personal Server even better: `bc1q5d8l0w33h65e2l5x7ty6wgnvkvlqcz0wfaslpz` or `12LMDTSTWxaUg6dGtuMCVLtr2EyEN6Jimg`.

This is open source project which happily accepts coding contributions from
anyone. Please keep lines under 80 characters in length and ideally don't add
any external dependencies to keep this as easy to install as possible.

I can be contacted on freenode IRC on the `#bitcoin` and `#electrum` channels, by email or on [twitter](https://twitter.com/chris_belcher_/).

My PGP key fingerprint is: `0A8B 038F 5E10 CC27 89BF CFFF EF73 4EA6 77F3 1129`.

### Notes for developers

To seamlessly work on the codebase while using `pip`, you need to
install in the `develop`/`editable` mode.  You can do that with:

    $ pip3 install --user -e /path/to/repo

`/path/to/repo` can also be a relative path, so if you are in the
source directory, just use `.`.  This installs the scripts in the
usual places, but imports the package from the source directory.  This
way, any changes you make are immediately visible.

#### Testing

Electrum Personal Server also works on [testnet](https://en.bitcoin.it/wiki/Testnet)
and [regtest](https://bitcoin.org/en/glossary/regression-test-mode). The
Electrum wallet can be started in testnet mode with the command line flag
`--testnet` or `--regtest`.

pytest is used for automated testing. On Debian-like systems install with
`pip3 install pytest pytest-cov`

Run the tests with:

    $ PYTHONPATH=.:$PYTHONPATH py.test-3

Create the coverage report with:

    $ PYTHONPATH=.:$PYTHONPATH py.test-3 --cov-report=html --cov
    $ open htmlcov/index.html

If you have installed Electrum Personal Server with pip, there is no
need to set `PYTHONPATH`.  You could also run the tests with:

    $ python3 setup.py test

## Media Coverage and Talks

* https://bitcoinmagazine.com/articles/electrum-personal-server-will-give-users-full-node-security-they-need/

* [Discussion at Building on Bitcoin 2018](https://youtu.be/XORDEX-RrAI?t=4980) [transcript](http://diyhpl.us/wiki/transcripts/building-on-bitcoin/2018/current-and-future-state-of-wallets/)

* [Electrum Personal Server talk at London Bitcoin Developer Meetup](https://www.youtube.com/watch?v=uKMXYdfm-is)

