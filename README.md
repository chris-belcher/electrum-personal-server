# Electrum Personal Server

Electrum Personal Server is an implementation of the Electrum server protocol
which fulfills the specific need of using the Electrum UI with full node
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

Using Electrum with Electrum Personal Server is probably the most
resource-efficient way right now to use a hardware wallet connected to your
own full node. 

For a longer explaination of this project and why it's important, see the
[mailing list email](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-February/015707.html)
and [bitcointalk thread](https://bitcointalk.org/index.php?topic=2664747.msg27179198).

See also the Electrum bitcoin wallet [website](https://electrum.org/).

## How To Use

This application requires python3 and a Bitcoin full node version 0.16 or
higher. Make sure you
[verify the digital signatures](https://bitcoin.stackexchange.com/questions/50185/how-to-verify-bitcoin-core-release-signing-keys)
of any binaries before running them, or compile from source.

Download the latest release or clone the git repository. Enter the directory
and rename the file `config.cfg_sample` to `config.cfg`, edit this file to
configure your bitcoin node json-rpc authentication details. Next add your
wallet addresses to the `[wallets]` section.

Finally run `./server.py` on Linux or double-click `run-server.bat` on Windows.
The first time the server is run it will import all configured addresses as
watch-only into the Bitcoin node, and then exit giving you a chance to
rescan if your wallet contains historical transactions.

Tell Electrum to connect to the server in `Tools` -> `Server`, usually
`localhost` if running on the same machine.

Note that you can also try this with on [testnet bitcoin](https://en.bitcoin.it/wiki/Testnet).
Electrum can be started in testnet mode with the command line flag `--testnet`.

#### Exposure to the Internet

You really don't want other people connecting to your server. They won't be
able to synchronize their wallet, and they could potentially learn all your
wallet addresses.

By default the server will bind to and accept connections only from `localhost`
so you should either run Electrum wallet from the same computer or use a SSH
tunnel.

## Project Readiness

This project is in alpha stages as there are several essential missing
features such as:

* Deterministic wallets and master public keys are not supported. Addresses
  must be imported individually.

* The Electrum server protocol has a caveat about multiple transactions included
  in the same block. So there may be weird behaviour if that happens.

* There's no way to turn off debug messages, so the console will be spammed by
  them when used.

When trying this, make sure you report any crashes, odd behaviour or times when
Electrum disconnects (which indicates the server behaved unexpectedly).

Someone should try running this on a Raspberry PI.

## Contributing

I welcome contributions. Please keep lines under 80 characters in length and
ideally don't add any external dependencies to keep this as easy to install as
possible.

I can be contacted on freenode IRC on the `#bitcoin` and `#electrum` channels.

## Media Coverage

* https://bitcoinmagazine.com/articles/electrum-personal-server-will-give-users-full-node-security-they-need/
