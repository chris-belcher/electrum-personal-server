# Electrum Personal Server

Electrum Personal Server aims to make using Electrum bitcoin wallet more secure
and more private. It makes it easy to connect your Electrum wallet to your own
full node.

[Full node](https://en.bitcoin.it/wiki/Full_node) wallets are important in
bitcoin because they are a big part of what makes the system trustless. No
longer do people have to trust a financial institution like a bank or Paypal,
they can run software on their own computers. If bitcoin is digital gold, then
a full node wallet is your own personal goldsmith who checks for you that
received payments are genuine.

Full node wallets are also important for privacy. Using Electrum under default
configuration requires it to send (hashes of) all your bitcoin addresses to some
server. That server can then easily spy on your transactions. Full node
wallets like Electrum Personal Server would download the entire blockchain and
scan it for the user's own addresses, and therefore don't reveal to anyone else
which bitcoin addresses they are interested in.

## Contents

- [Features](#features)
- [Detailed how-to guide](#how-to)
- [Quick start for Debian/Ubuntu](#quick-start-on-a-debianubuntu-machine-with-a-running-bitcoin-full-node)
- [Links to other setup guides](#links-to-other-setup-guides)
- [How to expose the server to the internet](#exposure-to-the-internet)
- [How is this different from other Electrum servers ?](#how-is-this-different-from-other-electrum-servers-)
- [Articles, Discussion and Talks](#articles-discussion-and-talks)
- [Contributing](#contributing)

### Features

- Fully-featured Electrum server for a single user. Combine full node security
  and privacy with all of Electrum's feature-richness: (Hardware wallet
  integration, [Multisignature wallets](http://docs.electrum.org/en/latest/multisig.html),
  [Offline signing](http://docs.electrum.org/en/latest/coldstorage.html),
  [Seed recovery phrases](https://en.bitcoin.it/wiki/Seed_phrase), Coin control,
  Fee-bumping)
- Maximally lightweight. Very low CPU, RAM and disk space requirements. Only a
  full node required.
- Compatible with all Bitcoin Core resource-saving features:
  - [Pruning](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.12.0.md#wallet-pruning)
  - [Blocksonly](https://bitcointalk.org/index.php?topic=1377345.0)
  - Disabled txindex
- Scriptable transaction broadcasting. When the user click "Send" the server
  can be configured to run a system call with the new transaction:
  - Broadcast transactions through Tor, for [resisting traffic analysis](https://en.bitcoin.it/wiki/Privacy#Tor_and_tor_broadcasting).
  - By writing a shell script (eg. `send-tx-over-sms.sh`) the server can
    broadcast transactions via SMS, radio or any other creative way.

## How To

- If you dont already have them, download and install Bitcoin Core version 0.17
  or higher. Make sure you
  [verify the digital signatures](https://bitcoin.stackexchange.com/questions/50185/how-to-verify-bitcoin-core-release-signing-keys)
  of any binaries before running them, or compile from source. The Bitcoin node
  must have wallet functionality enabled, and must have the RPC server switched on (`server=1`
  in bitcoin.conf). Create a wallet dedicated to Electrum Personal Server by adding
  `wallet=electrumpersonalserver` to the bitcoin.conf file.

- If you dont already have it, download and install
  [Electrum bitcoin wallet](https://electrum.org/), and set up your Electrum
  wallet (for example by linking your hardware wallet). To avoid damaging
  privacy by connecting to public Electrum servers, disconnect from the
  internet first or run Electrum with the command line argument
  `--server localhost:50002:s`. To avoid accidentally connecting to public
  electrum servers, also use the command line argument `--offline`.

- Download the [latest release](https://github.com/chris-belcher/electrum-personal-server/releases)
  of Electrum Personal Server. If using Windows OS take the packaged binary
  release build `electrumpersonalserver-windows-release-XXX.zip`.

- Extract and enter the directory, and copy the file `config.ini_sample` to
  `config.ini`. Edit the file `config.ini` to configure everything about the
  server. Add your wallet master public keys or watch-only addresses to the
  `[master-public-keys]` and `[watch-only-addresses]` sections. Master public
  keys for an Electrum wallet (which start with xpub/ypub/zpub/etc) can be found
  in the Electrum client menu `Wallet` -> `Information`. You can add multiple
  master public keys or watch-only addresses by adding separate lines for the
  different keys/addresses:

      wallet1 = xpub661MyMwAqRbcF...
      wallet2 = xpub7712KLsfsg46G...

- If you created a wallet dedicated to Electrum Personal Server in Bitcoin Core,
  you have to modify the line `wallet_filename` in the `[bitcoin-rpc]` section
  with the name of the wallet, for example `wallet_filename = electrumpersonalserver`.

- If using the windows packaged binary release, drag the file `config.ini` onto
  the file `electrum-personal-server.exe` to run the server, or on the command
  line run `electrum-personal-server config.ini`.

- If installing from the source release, install Electrum Personal Server in
  your home directory with `pip3 install --user .`. On Linux the script
  `electrum-personal-server` will be installed in `~/.local/bin`. Please note,
  if for some reason, you want to make a system-wide install, simply run
  `pip3 install .` as root (e.g. if you have `sudo` setup, you could use:
  `sudo pip3 install .`). Run `electrum-personal-server /path/to/config.ini`
  to start Electrum Personal Server.

- The first time the server is run it will import all configured addresses as
  watch-only into the Bitcoin node, and then exit.
  If the wallets contain historical transactions you can use the rescan script
  (`electrum-personal-server --rescan /path/to/config.ini`) to make them appear.
  If using the windows packaged binary release build then drag the file
  `config.ini` onto the file `electrum-personal-server-rescan.bat`.

- Run the server again which will start Electrum Personal Server. Wait until
  the message `Listening for Electrum Wallet ...` appears and then tell
  Electrum to connect to the server in `Tools` -> `Server`. By default the
  server details are `localhost` if running on the same machine. Make sure the
  port number matches what is written in `config.ini` (port 50002 by default).

Pro Tip: run Electrum wallet with the command line arguments `--oneserver --server localhost:50002:s`.
This stops Electrum connecting to other servers to obtain block
headers; and locks Electrum to connect only to your server, disabling the GUI
button to stop accidental connections. This helps avoid a user accidentally
ruining their privacy by connecting to public Electrum servers. Another way
to do this is to open Electrum's config file and edit the lines to
`oneserver=true`.

Pro Tip2: run tor on the same machine as Electrum Personal Server. Then by
default transactions will be broadcast through tor. If running tor, also set
`walletbroadcast=0` in your `bitcoin.conf`. This prevents the node from
rebroadcasting transactions without tor.

### Quick start on a Debian/Ubuntu machine with a running Bitcoin full node

1. Download the [latest release](https://github.com/chris-belcher/electrum-personal-server/releases)
   of Electrum Personal Server. (Not the Windows version, the "Source code" zip or
   tar.gz.)
1. Extract the compressed file
1. Enter the directory
1. `cp config.ini_sample config.ini`
1. Edit the config.ini file:
   1. Add bitcoind back-end RPC auth information
   1. Add wallet master public keys for your wallets
1. Install the server to your home directory with `pip3 install --user .`
1. Make sure `~/.local/bin` is in your \$PATH (`echo $PATH`). If not, add it:
   `echo 'PATH=$HOME/.local/bin:$PATH' >> ~/.profile`, logout, and log in again
1. Run the server: `electrum-personal-server config.ini`
1. Rescan if needed: `electrum-personal-server --rescan config.ini`
1. Restart the server if needed
1. Start your Electrum wallet: `electrum --oneserver --server localhost:50002:s`.

### Links to other setup guides

- [How to setup Electrum Personal Server on a Raspberry Pi](https://github.com/Stadicus/RaspiBolt/blob/master/raspibolt_64_electrum.md)
- [Electrum Personal Server on Windows 10](https://driftwoodpalace.github.io/Hodl-Guide/hodl-guide_63_eps-win.html)
- [Running Electrum Personal Server on Mac OS](https://driftwoodpalace.github.io/Hodl-Guide/hodl-guide_64_eps-mac.html)
- [How to set up your own Bitcoin node, Electrum wallet and Server](https://curiosityoverflow.xyz/posts/bitcoin-electrum-wallet/)
- [How to set up Wireguard to connect to EPS](https://curiosityoverflow.xyz/posts/wireguard-eps/)
- [Linux setup video tutorial on youtube](https://www.youtube.com/watch?v=1JMP4NZCC5g)
- [BTCPay Server integration with Electrum Personal Server](https://docs.btcpayserver.org/ElectrumPersonalServer/)
- [Using Electrum Personal Server with a Bitseed node](https://github.com/john-light/bitcoin/blob/master/eps.md)
- [Spanish language video tutorial / Instalación del servidor Electrum Personal Server](https://www.youtube.com/watch?v=F3idwecYvcU)
- [Japanese language setup guide](https://freefromjp.wordpress.com/2019/07/13/electrum-personal-server-%E3%81%AE%E3%82%A4%E3%83%B3%E3%82%B9%E3%83%88%E3%83%BC%E3%83%AB/)
- [Connect to Electrum Personal Server via Wireguard ](https://curiosityoverflow.xyz/posts/wireguard-eps/#connecting-to-electrum-personal-server)

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

##### Number of connections

Right now Electrum Personal Server can only accept one connection at a time.

##### Lightning Network

Right now Electrum Personal Server does not support Lightning Network which
Electrum wallet 4.0 and above implements.

#### How is this different from other Electrum servers ?

They are different approaches with different tradeoffs. Electrum Personal
Server is compatible with pruning, blocksonly and txindex=0, uses less CPU and
RAM, is suitable for being used intermittently rather than needing to be
always-on, and doesn't require an index of every bitcoin address ever used. The
tradeoff is when recovering an old wallet, you must import your wallet first
and you may need to rescan, so it loses the "instant on" feature of Electrum
wallet. Other Electrum server implementations will be able to sync your wallet
immediately even if you have historical transactions, and they can serve
multiple Electrum connections at once.

Traditional Electrum servers inherently are not very scalable and use many
resources which push people towards using centralized solutions. This is what
we'd like to avoid with Electrum Personal Server.

Definitely check out other implementations:
- [ElectrumX](https://github.com/spesmilo/electrumx) - Full Electrum server maintained by the Electrum project
- [Electrs](https://github.com/romanz/electrs) - Full Electrum server coded in rust
- [Bitcoin Wallet Tracker](https://github.com/bwt-dev/bwt) - Wallet indexer coded in rust
- [Obelisk](https://github.com/parazyd/obelisk) - Minimal Electrum server using zeromq and libbitcoin as backend

#### Further ideas for work

- Allowing connections from more than one Electrum instance at a time. See issue
  [#50](https://github.com/chris-belcher/electrum-personal-server/issues/50). First
  the server code should be separated from the networking code.
- Fix mempool lock/CPU bottleneck issue. See issue [#96](https://github.com/chris-belcher/electrum-personal-server/issues/96).
- Research and develop an easier way of rescanning the wallet when blockchain
  pruning is enabled. See issue [#85](https://github.com/chris-belcher/electrum-personal-server/issues/85).
- Developing some way for Electrum servers to authenticate clients, so that
  Electrum Personal Server can accept connections from the entire internet but
  without a fear of privacy loss.
- Dynamic adding of wallet master public keys. Perhaps by polling for changes
  in the config file.

## Contact

I can be contacted on freenode IRC on the `#bitcoin` and `#electrum` channels,
by email or on [twitter](https://twitter.com/chris_belcher_/).

My PGP key fingerprint is: `0A8B 038F 5E10 CC27 89BF CFFF EF73 4EA6 77F3 1129`.

## Articles, Discussion and Talks

- [BitcoinMagazine.com article](https://bitcoinmagazine.com/articles/electrum-personal-server-will-give-users-full-node-security-they-need/)
- [Electrum Personal Server talk at London Bitcoin Developer Meetup](https://www.youtube.com/watch?v=uKMXYdfm-is)
- Electrum Personal Server used as a building block for systems which use
  bitcoin without internet access. See [here](https://twitter.com/notgrubles/status/1091011511961731073)
  and [here](https://medium.com/hackernoon/completely-offline-bitcoin-transactions-4e58324637bd)
  for information and setup guide.
- [Mailing list email](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-February/015707.html)
- [Bitcointalk thread](https://bitcointalk.org/index.php?topic=2664747.msg27179198)
- [Nasdaq article](https://www.nasdaq.com/article/the-electrum-personal-server-will-give-users-the-full-node-security-they-need-cm920443)
- [Bitcoinnews.ru article (russian)](https://bitcoinnews.ru/novosti/electrum-personal-server-uluchshennaya-versiya-/)
- [bits.media article (russian)](https://bits.media/razrabotchiki-electrum-opublikovali-alfa-versiyu-electrum-personal-server/)

## Contributing

Donate to help improve Electrum Personal Server: `bc1qwt8kh83dpdj4yuquvsf28rhcft2rjh6jvy6678` or `15wAE63DG8RH6xp7nTucgYn1Jb4acR1EvM`. Signed donation addresses can be found [here](/docs/signed-donation-addresses.txt).

This is open source project which happily accepts coding contributions from
anyone. See [developer-notes.md](docs/developer-notes.md).
