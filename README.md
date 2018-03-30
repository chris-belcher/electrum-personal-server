# Electrum Personal Server

Electrum Personal Server is an implementation of the Electrum server protocol
which fulfills the specific need of using the Electrum wallet with full node
verification and privacy, but without the heavyweight server backend, for a
single user. It allows the user to benefit from all of Bitcoin Core's
resource-saving features like
[pruning](https://bitcoin.org/en/release/v0.12.0#wallet-pruning),
[blocksonly](https://bitcointalk.org/index.php?topic=1377345.0) and disabled
txindex. All of Electrum's feature-richness like hardware wallet integration,
[multisignature wallets](http://docs.electrum.org/en/latest/multisig.html),
[offline signing](http://docs.electrum.org/en/latest/coldstorage.html),
[mnemonic recovery phrases](https://en.bitcoin.it/wiki/Mnemonic_phrase)
and so on can still be used, but backed by the user's own full node.

Full node wallets are important in bitcoin because they are an big part of what
makes the system be trustless. No longer do people have to trust a financial
institution like a bank or paypal, they can run software on their own
computers. If bitcoin is digital gold, then a full node wallet is your own
personal goldsmith who checks for you that received payments are genuine. You
wouldn't accept large amounts of cash or gold coins without checking they are
actually genuine, the same applies for bitcoin.

Full node wallets are also important for privacy. Using Electrum under default
configuration requires it to send all your bitcoin addresses to some server.
That server can then easily spy on you. Full node wallets like Electrum Personal
Server would download the entire blockchain and scan it for the user's own
addresses, and therefore don't reveal to anyone else which bitcoin addresses
they are interested in.

Before Electrum Personal Server, there was no easy way to connect a hardware
wallet to a full node.

For a longer explaination of this project, see the
[mailing list email](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-February/015707.html)
and [bitcointalk thread](https://bitcointalk.org/index.php?topic=2664747.msg27179198). See also the Bitcoin Wiki [pages](https://en.bitcoin.it/wiki/Clearing_Up_Misconceptions_About_Full_Nodes) on [full nodes](https://en.bitcoin.it/wiki/Full_node).

See also the Electrum bitcoin wallet [website](https://electrum.org/).

## How To

* Download and install python3 and a Bitcoin full node version 0.16 or higher. Make sure you
[verify the digital signatures](https://bitcoin.stackexchange.com/questions/50185/how-to-verify-bitcoin-core-release-signing-keys)
of any binaries before running them, or compile from source. The Bitcoin node must have wallet enabled, and must have the RPC server switched on (`server=1` in bitcoin.conf).

* Download the [latest release](https://github.com/chris-belcher/electrum-personal-server/releases) or clone the git repository. Enter the directory
and rename the file `config.cfg_sample` to `config.cfg`.

* Edit the file `config.cfg` to configure everything about the server. Add your
wallet master public keys or watch-only addresses to the `[master-public-keys]`
and `[watch-only-addresses]` sections. Master public keys for an Electrum wallet
can be found in the Electrum client menu `Wallet` -> `Information`.

* Run `./server.py` on Linux or double-click `run-server.bat` on Windows.
The first time the server is run it will import all configured addresses as
watch-only into the Bitcoin node, and then exit. If the wallets contain 
historical transactions you can use the rescan script to make them appear.

* Run the server again which will start Electrum Personal Server. Tell Electrum
wallet to connect to it in `Tools` -> `Server`. By default the server details
are `localhost` if running on the same machine. Make sure the port number
matches what is written in `config.cfg` (port 50002 by default).

A guide for installing Electrum Personal Server on a Raspberry Pi can be found
[here](https://github.com/Stadicus/guides/blob/master/raspibolt/raspibolt_64_electrum.md).

By default Electrum will connect to several Electrum servers to obtain block
headers. This can be avoided by starting Electrum on the command line with the
`--oneserver` flag.

Electrum Personal Server also works on [testnet bitcoin](https://en.bitcoin.it/wiki/Testnet). The Electrum wallet can be started in testnet mode with the command line flag `--testnet`.


#### Exposure to the Internet

Other people should not be connecting to your server. They won't be
able to synchronize their wallet, and they could potentially learn all your
wallet addresses.

By default the server will accept connections only from `localhost` so you
should either run Electrum wallet from the same computer or use a SSH tunnel
from another computer.

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

Definitely check out implementations like [ElectrumX](https://github.com/kyuupichan/electrumx/) if you're interested in this sort of thing.

## Project Readiness

This project is in beta release. It should be usable by any reasonably-technical
bitcoin user.

When trying this, make sure you report any crashes, odd behaviour, transactions
appearing as `Not Verified` or times when Electrum disconnects (which
indicates the server behaved unexpectedly).

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

This is an open source project which happily accepts coding contributions from
anyone. Please keep lines under 80 characters in length and ideally don't add
any external dependencies to keep this as easy to install as possible.

Donate to help make Electrum Personal Server even better: `bc1q5d8l0w33h65e2l5x7ty6wgnvkvlqcz0wfaslpz` or `12LMDTSTWxaUg6dGtuMCVLtr2EyEN6Jimg`.

I can be contacted on freenode IRC on the `#bitcoin` and `#electrum` channels, by email or on [twitter](https://twitter.com/chris_belcher_/).

My PGP key fingerprint is: `0A8B 038F 5E10 CC27 89BF CFFF EF73 4EA6 77F3 1129`.

## Media Coverage

* https://bitcoinmagazine.com/articles/electrum-personal-server-will-give-users-full-node-security-they-need/
