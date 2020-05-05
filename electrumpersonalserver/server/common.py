import socket
import time
import datetime
import ssl
import os
import os.path
import logging
import tempfile
import platform
import json
from json.decoder import JSONDecodeError
from configparser import RawConfigParser, NoSectionError, NoOptionError
from ipaddress import ip_network, ip_address

from electrumpersonalserver.server.jsonrpc import JsonRpc, JsonRpcError
import electrumpersonalserver.server.hashes as hashes
import electrumpersonalserver.server.deterministicwallet as deterministicwallet
import electrumpersonalserver.server.transactionmonitor as transactionmonitor
from electrumpersonalserver.server.electrumprotocol import (
    SERVER_VERSION_NUMBER,
    ElectrumProtocol,
    get_block_header,
    get_current_header,
    get_block_headers_hex
)

##python has demented rules for variable scope, so these
## global variables are actually mutable lists
bestblockhash = [None]

def on_heartbeat_listening(txmonitor):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("on heartbeat listening")
    txmonitor.check_for_updated_txes()

def on_heartbeat_connected(rpc, txmonitor, protocol):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("on heartbeat connected")
    is_tip_updated, header = check_for_new_blockchain_tip(rpc,
        protocol.are_headers_raw)
    if is_tip_updated:
        logger.debug("Blockchain tip updated")
        protocol.on_blockchain_tip_updated(header)
    updated_scripthashes = txmonitor.check_for_updated_txes()
    protocol.on_updated_scripthashes(updated_scripthashes)

def check_for_new_blockchain_tip(rpc, raw):
    new_bestblockhash, header = get_current_header(rpc, raw)
    is_tip_new = bestblockhash[0] != new_bestblockhash
    bestblockhash[0] = new_bestblockhash
    return is_tip_new, header

def create_server_socket(hostport):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    server_sock = socket.socket()
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(hostport)
    server_sock.listen(1)
    logger.info("Listening for Electrum Wallet on " + str(hostport))
    return server_sock

def run_electrum_server(rpc, txmonitor, config):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.info("Starting electrum server")

    hostport = (config.get("electrum-server", "host"),
            int(config.get("electrum-server", "port")))
    ip_whitelist = []
    for ip in config.get("electrum-server", "ip_whitelist").split(" "):
        if ip == "*":
            #matches everything
            ip_whitelist.append(ip_network("0.0.0.0/0"))
            ip_whitelist.append(ip_network("::0/0"))
        else:
            ip_whitelist.append(ip_network(ip, strict=False))
    poll_interval_listening = int(config.get("bitcoin-rpc",
        "poll_interval_listening"))
    poll_interval_connected = int(config.get("bitcoin-rpc",
        "poll_interval_connected"))
    certfile, keyfile = get_certs(config)
    logger.info('using cert: {}, key: {}'.format(certfile, keyfile))
    disable_mempool_fee_histogram = config.getboolean("electrum-server",
        "disable_mempool_fee_histogram", fallback=False)
    broadcast_method = config.get("electrum-server", "broadcast_method",
        fallback="own-node")
    tor_host = config.get("electrum-server", "tor_host", fallback="localhost")
    tor_port = int(config.get("electrum-server", "tor_port", fallback="9050"))
    tor_hostport = (tor_host, tor_port)

    protocol = ElectrumProtocol(rpc, txmonitor, logger, broadcast_method,
        tor_hostport, disable_mempool_fee_histogram)

    server_sock = create_server_socket(hostport)
    server_sock.settimeout(poll_interval_listening)
    while True:
        try:
            sock = None
            while sock == None:
                try:
                    sock, addr = server_sock.accept()
                    if not any([ip_address(addr[0]) in ipnet
                            for ipnet in ip_whitelist]):
                        logger.debug(addr[0] + " not in whitelist, closing")
                        raise ConnectionRefusedError()
                    sock = ssl.wrap_socket(sock, server_side=True,
                        certfile=certfile, keyfile=keyfile,
                        ssl_version=ssl.PROTOCOL_SSLv23)
                except socket.timeout:
                    on_heartbeat_listening(txmonitor)
                except (ConnectionRefusedError, ssl.SSLError):
                    sock.close()
                    sock = None
            logger.info('Electrum connected from ' + str(addr[0]))

            def send_reply_fun(reply):
                line = json.dumps(reply)
                sock.sendall(line.encode('utf-8') + b'\n')
                logger.debug('<= ' + line)
            protocol.set_send_reply_fun(send_reply_fun)

            sock.settimeout(poll_interval_connected)
            recv_buffer = bytearray()
            while True:
                try:
                    recv_data = sock.recv(4096)
                    if not recv_data or len(recv_data) == 0:
                        raise EOFError()
                    recv_buffer.extend(recv_data)
                    lb = recv_buffer.find(b'\n')
                    if lb == -1:
                        continue
                    while lb != -1:
                        line = recv_buffer[:lb].rstrip()
                        recv_buffer = recv_buffer[lb + 1:]
                        lb = recv_buffer.find(b'\n')
                        try:
                            line = line.decode("utf-8")
                            query = json.loads(line)
                        except (UnicodeDecodeError, JSONDecodeError) as e:
                            raise IOError(repr(e))
                        logger.debug("=> " + line)
                        protocol.handle_query(query)
                except socket.timeout:
                    on_heartbeat_connected(rpc, txmonitor, protocol)
        except (IOError, EOFError) as e:
            if isinstance(e, (EOFError, ConnectionRefusedError)):
                logger.info("Electrum wallet disconnected")
            else:
                logger.error("IOError: " + repr(e))
            try:
                if sock != None:
                    sock.close()
            except IOError:
                pass
            sock = None
            protocol.on_disconnect()
            time.sleep(0.2)

def get_scriptpubkeys_to_monitor(rpc, config):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    st = time.time()
    try:
        imported_addresses = set(rpc.call("getaddressesbyaccount",
            [transactionmonitor.ADDRESSES_LABEL]))
        logger.debug("using deprecated accounts interface")
    except JsonRpcError:
        #bitcoin core 0.17 deprecates accounts, replaced with labels
        if transactionmonitor.ADDRESSES_LABEL in rpc.call("listlabels", []):
            imported_addresses = set(rpc.call("getaddressesbylabel",
                [transactionmonitor.ADDRESSES_LABEL]).keys())
        else:
            #no label, no addresses imported at all
            imported_addresses = set()
    logger.debug("already-imported addresses = " + str(imported_addresses))

    deterministic_wallets = []
    for key in config.options("master-public-keys"):
        mpk = config.get("master-public-keys", key)
        gaplimit = int(config.get("bitcoin-rpc", "gap_limit"))
        chain = rpc.call("getblockchaininfo", [])["chain"]
        try:
            wal = deterministicwallet.parse_electrum_master_public_key(mpk,
                gaplimit, rpc, chain)
        except ValueError:
            raise ValueError("Bad master public key format. Get it from " +
                "Electrum menu `Wallet` -> `Information`")
        deterministic_wallets.append(wal)

    #check whether these deterministic wallets have already been imported
    import_needed = False
    wallets_imported = 0
    addresses_to_import = []
    TEST_ADDR_COUNT = 3
    logger.info("Displaying first " + str(TEST_ADDR_COUNT) + " addresses of " +
        "each master public key:")
    for config_mpk_key, wal in zip(config.options("master-public-keys"),
            deterministic_wallets):
        first_addrs, first_spk = wal.get_addresses(change=0, from_index=0,
            count=TEST_ADDR_COUNT)
        logger.info("\n" + config_mpk_key + " =>\n\t" + "\n\t".join(
            first_addrs))
        last_addr, last_spk = wal.get_addresses(change=0, from_index=int(
            config.get("bitcoin-rpc", "initial_import_count")) - 1, count=1)
        if not set(first_addrs + last_addr).issubset(imported_addresses):
            import_needed = True
            wallets_imported += 1
            for change in [0, 1]:
                addrs, spks = wal.get_addresses(change, 0,
                    int(config.get("bitcoin-rpc", "initial_import_count")))
                addresses_to_import.extend(addrs)
    logger.info("Obtaining bitcoin addresses to monitor . . .")
    #check whether watch-only addresses have been imported
    watch_only_addresses = []
    for key in config.options("watch-only-addresses"):
        watch_only_addresses.extend(config.get("watch-only-addresses",
            key).split(' '))
    watch_only_addresses = set(watch_only_addresses)
    watch_only_addresses_to_import = []
    if not watch_only_addresses.issubset(imported_addresses):
        import_needed = True
        watch_only_addresses_to_import = (watch_only_addresses -
            imported_addresses)

    if len(deterministic_wallets) == 0 and len(watch_only_addresses) == 0:
        logger.error("No master public keys or watch-only addresses have " +
            "been configured at all. Exiting..")
        #import = true and no addresses means exit
        return (True, [], None)

    #if addresses need to be imported then return them
    if import_needed:
        #TODO minus imported_addresses
        logger.info("Importing " + str(wallets_imported) + " wallets and " +
            str(len(watch_only_addresses_to_import)) + " watch-only " +
            "addresses into the Bitcoin node")
        time.sleep(5)
        return (True, addresses_to_import + list(
            watch_only_addresses_to_import), None)

    #test
    # importing one det wallet and no addrs, two det wallets and no addrs
    # no det wallets and some addrs, some det wallets and some addrs

    #at this point we know we dont need to import any addresses
    #find which index the deterministic wallets are up to
    spks_to_monitor = []
    for wal in deterministic_wallets:
        for change in [0, 1]:
            addrs, spks = wal.get_addresses(change, 0,
                int(config.get("bitcoin-rpc", "initial_import_count")))
            spks_to_monitor.extend(spks)
            #loop until one address found that isnt imported
            while True:
                addrs, spks = wal.get_new_addresses(change, count=1)
                if addrs[0] not in imported_addresses:
                    break
                spks_to_monitor.append(spks[0])
            wal.rewind_one(change)

    spks_to_monitor.extend([hashes.address_to_script(addr, rpc)
        for addr in watch_only_addresses])
    et = time.time()
    logger.info("Obtained list of addresses to monitor in " + str(et - st)
        + "sec")
    return False, spks_to_monitor, deterministic_wallets

def get_certs(config):
    from pkg_resources import resource_filename
    from electrumpersonalserver import __certfile__, __keyfile__

    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    certfile = config.get('electrum-server', 'certfile', fallback=None)
    keyfile = config.get('electrum-server', 'keyfile', fallback=None)
    if (certfile and keyfile) and \
       (os.path.exists(certfile) and os.path.exists(keyfile)):
        return certfile, keyfile
    else:
        certfile = resource_filename('electrumpersonalserver', __certfile__)
        keyfile = resource_filename('electrumpersonalserver', __keyfile__)
        if os.path.exists(certfile) and os.path.exists(keyfile):
            return certfile, keyfile
        else:
            raise ValueError('invalid cert: {}, key: {}'.format(
                certfile, keyfile))

def obtain_rpc_username_password(datadir):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    if len(datadir.strip()) == 0:
        logger.debug("no datadir configuration, checking in default location")
        systemname = platform.system()
        #paths from https://en.bitcoin.it/wiki/Data_directory
        if systemname == "Linux":
            datadir = os.path.expanduser("~/.bitcoin")
        elif systemname == "Windows":
            datadir = os.path.expandvars("%APPDATA%\Bitcoin")
        elif systemname == "Darwin": #mac os
            datadir = os.path.expanduser(
                "~/Library/Application Support/Bitcoin/")
    cookie_path = os.path.join(datadir, ".cookie")
    if not os.path.exists(cookie_path):
        logger.warning("Unable to find .cookie file, try setting `datadir`" +
            " config")
        return None, None
    fd = open(cookie_path)
    username, password = fd.read().strip().split(":")
    fd.close()
    return username, password

def parse_args():
    from argparse import ArgumentParser

    parser = ArgumentParser(description='Electrum Personal Server daemon')
    parser.add_argument('config_file',
                        help='configuration file (mandatory)')
    parser.add_argument("--rescan", action="store_true", help="Start the " +
        " rescan script instead")
    parser.add_argument("--rescan-date", action="store", dest="rescan_date",
        default=None, help="Earliest wallet creation date (DD/MM/YYYY) or "
        + "block height to rescan from")
    parser.add_argument("-v", "--version", action="version", version=
        "%(prog)s " + SERVER_VERSION_NUMBER)
    return parser.parse_args()

#log for checking up/seeing your wallet, debug for when something has gone wrong
def logger_config(logger, config):
    formatter = logging.Formatter(config.get("logging", "log_format",
        fallback="%(levelname)s:%(asctime)s: %(message)s"))
    logstream = logging.StreamHandler()
    logstream.setFormatter(formatter)
    logstream.setLevel(config.get("logging", "log_level_stdout", fallback=
        "INFO"))
    logger.addHandler(logstream)
    filename = config.get("logging", "log_file_location", fallback="")
    if len(filename.strip()) == 0:
        filename= tempfile.gettempdir() + "/electrumpersonalserver.log"
    logfile = logging.FileHandler(filename, mode=('a' if
        config.get("logging", "append_log", fallback="false") else 'w'))
    logfile.setFormatter(formatter)
    logfile.setLevel(logging.DEBUG)
    logger.addHandler(logfile)
    logger.setLevel(logging.DEBUG)
    return logger, filename

def main():
    opts = parse_args()

    try:
        config = RawConfigParser()
        config.read(opts.config_file)
        config.options("master-public-keys")
    except NoSectionError:
        print("ERROR: Non-existant configuration file {}".format(
            opts.config_file))
        return
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger, logfilename = logger_config(logger, config)
    logger.info('Starting Electrum Personal Server v{}'.format(
        SERVER_VERSION_NUMBER))
    logger.info('Logging to ' + logfilename)
    try:
        rpc_u = config.get("bitcoin-rpc", "rpc_user")
        rpc_p = config.get("bitcoin-rpc", "rpc_password")
        logger.debug("obtaining auth from rpc_user/pass")
    except NoOptionError:
        rpc_u, rpc_p = obtain_rpc_username_password(config.get(
            "bitcoin-rpc", "datadir"))
        logger.debug("obtaining auth from .cookie")
    if rpc_u == None:
        return
    rpc = JsonRpc(host = config.get("bitcoin-rpc", "host"),
        port = int(config.get("bitcoin-rpc", "port")),
        user = rpc_u, password = rpc_p,
        wallet_filename=config.get("bitcoin-rpc", "wallet_filename").strip(),
        logger=logger)

    #TODO somewhere here loop until rpc works and fully sync'd, to allow
    # people to run this script without waiting for their node to fully
    # catch up sync'd when getblockchaininfo blocks == headers, or use
    # verificationprogress
    printed_error_msg = False
    while bestblockhash[0] == None:
        try:
            bestblockhash[0] = rpc.call("getbestblockhash", [])
        except JsonRpcError as e:
            if not printed_error_msg:
                logger.error("Error with bitcoin json-rpc: " + repr(e))
                printed_error_msg = True
            time.sleep(5)
    try:
        rpc.call("listunspent", [])
    except JsonRpcError as e:
        logger.error(repr(e))
        logger.error("Wallet related RPC call failed, possibly the " +
            "bitcoin node was compiled with the disable wallet flag")
        return

    test_keydata = (
    "2 tpubD6NzVbkrYhZ4YVMVzC7wZeRfz3bhqcHvV8M3UiULCfzFtLtp5nwvi6LnBQegrkx" +
    "YGPkSzXUEvcPEHcKdda8W1YShVBkhFBGkLxjSQ1Nx3cJ tpubD6NzVbkrYhZ4WjgNYq2nF" +
    "TbiSLW2SZAzs4g5JHLqwQ3AmR3tCWpqsZJJEoZuP5HAEBNxgYQhtWMezszoaeTCg6FWGQB" +
    "T74sszGaxaf64o5s")
    chain = rpc.call("getblockchaininfo", [])["chain"]
    try:
        gaplimit = 5
        deterministicwallet.parse_electrum_master_public_key(test_keydata,
            gaplimit, rpc, chain)
    except ValueError as e:
        logger.error(repr(e))
        logger.error("Descriptor related RPC call failed. Bitcoin Core 0.20.0"
            + " or higher required. Exiting..")
        return
    if opts.rescan:
        rescan_script(logger, rpc, opts.rescan_date)
        return
    while True:
        logger.debug("Checking whether rescan is in progress")
        walletinfo = rpc.call("getwalletinfo", [])
        if "scanning" in walletinfo and walletinfo["scanning"]:
            logger.debug("Waiting for Core wallet rescan to finish")
            time.sleep(300)
            continue
        break
    import_needed, relevant_spks_addrs, deterministic_wallets = \
        get_scriptpubkeys_to_monitor(rpc, config)
    if import_needed:
        if len(relevant_spks_addrs) == 0:
            #import = true and no addresses means exit
            return
        transactionmonitor.import_addresses(rpc, relevant_spks_addrs)
        logger.info("Done.\nIf recovering a wallet which already has existing" +
            " transactions, then\nrun the rescan script. If you're confident" +
            " that the wallets are new\nand empty then there's no need to" +
            " rescan, just restart this script")
    else:
        txmonitor = transactionmonitor.TransactionMonitor(rpc,
            deterministic_wallets, logger)
        if not txmonitor.build_address_history(relevant_spks_addrs):
            return
        try:
            run_electrum_server(rpc, txmonitor, config)
        except KeyboardInterrupt:
            logger.info('Received KeyboardInterrupt, quitting')

def search_for_block_height_of_date(datestr, rpc):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    target_time = datetime.datetime.strptime(datestr, "%d/%m/%Y")
    bestblockhash = rpc.call("getbestblockhash", [])
    best_head = rpc.call("getblockheader", [bestblockhash])
    if target_time > datetime.datetime.fromtimestamp(best_head["time"]):
        logger.error("date in the future")
        return -1
    genesis_block = rpc.call("getblockheader", [rpc.call("getblockhash", [0])])
    if target_time < datetime.datetime.fromtimestamp(genesis_block["time"]):
        logger.warning("date is before the creation of bitcoin")
        return 0
    first_height = 0
    last_height = best_head["height"]
    while True:
        m = (first_height + last_height) // 2
        m_header = rpc.call("getblockheader", [rpc.call("getblockhash", [m])])
        m_header_time = datetime.datetime.fromtimestamp(m_header["time"])
        m_time_diff = (m_header_time - target_time).total_seconds()
        if abs(m_time_diff) < 60*60*2: #2 hours
            return m_header["height"]
        elif m_time_diff < 0:
            first_height = m
        elif m_time_diff > 0:
            last_height = m
        else:
            return -1

def rescan_script(logger, rpc, rescan_date):
    if rescan_date:
        user_input = rescan_date
    else:
        user_input = input("Enter earliest wallet creation date (DD/MM/YYYY) "
            "or block height to rescan from: ")
    try:
        height = int(user_input)
    except ValueError:
        height = search_for_block_height_of_date(user_input, rpc)
        if height == -1:
            return
        height -= 2016 #go back two weeks for safety

    if not rescan_date:
        if input("Rescan from block height " + str(height) + " ? (y/n):") \
                != 'y':
            return
    logger.info("Rescanning. . . for progress indicator see the bitcoin node's"
        + " debug.log file")
    rpc.call("rescanblockchain", [height])
    logger.info("end")

def rescan_main():
    opts = parse_args()

    try:
        config = RawConfigParser()
        config.read(opts.config_file)
        config.options("master-public-keys")
    except NoSectionError:
        print("ERROR: Non-existant configuration file {}".format(
            opts.config_file))
        return
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger, logfilename = logger_config(logger, config)
    logger.info('Starting Electrum Personal Server rescan script')
    logger.info('Logging to ' + logfilename)
    logger.warning("The seperate rescan script is deprecated, use " +
        "`electrum-personal-server --rescan` instead.")
    try:
        rpc_u = config.get("bitcoin-rpc", "rpc_user")
        rpc_p = config.get("bitcoin-rpc", "rpc_password")
    except NoOptionError:
        rpc_u, rpc_p = obtain_rpc_username_password(config.get(
            "bitcoin-rpc", "datadir"))
    if rpc_u == None:
        return
    rpc = JsonRpc(host = config.get("bitcoin-rpc", "host"),
        port = int(config.get("bitcoin-rpc", "port")),
        user = rpc_u, password = rpc_p,
        wallet_filename=config.get("bitcoin-rpc", "wallet_filename").strip())
    rescan_script(logger, rpc)

if __name__ == "__main__":
    #entry point for pyinstaller executable
    main()
    os.system("pause")

