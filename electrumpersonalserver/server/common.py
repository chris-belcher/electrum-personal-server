import socket, time, json, datetime, struct, binascii, ssl, os, os.path
from configparser import RawConfigParser, NoSectionError, NoOptionError
from collections import defaultdict
import traceback, sys, platform
from ipaddress import ip_network, ip_address
import logging
import tempfile

from electrumpersonalserver.server.jsonrpc import JsonRpc, JsonRpcError
import electrumpersonalserver.server.hashes as hashes
import electrumpersonalserver.server.merkleproof as merkleproof
import electrumpersonalserver.server.deterministicwallet as deterministicwallet
import electrumpersonalserver.server.transactionmonitor as transactionmonitor

SERVER_VERSION_NUMBER = "0.1.7"

DONATION_ADDR = "bc1q5d8l0w33h65e2l5x7ty6wgnvkvlqcz0wfaslpz"

BANNER = \
"""Welcome to Electrum Personal Server {serverversion}

Monitoring {detwallets} deterministic wallets, in total {addr} addresses.

Connected bitcoin node: {useragent}
Peers: {peers}
Uptime: {uptime}
Blocksonly: {blocksonly}
Pruning: {pruning}
Download: {recvbytes}
Upload: {sentbytes}

https://github.com/chris-belcher/electrum-personal-server

Donate to help make Electrum Personal Server even better:
{donationaddr}

"""

SERVER_PROTOCOL_VERSION_MAX = 1.4
SERVER_PROTOCOL_VERSION_MIN = 1.1

##python has demented rules for variable scope, so these
## global variables are actually mutable lists
protocol_version = [0]
subscribed_to_headers = [False]
are_headers_raw = [False]
bestblockhash = [None]
txid_blockhash_map = {}

def send_response(sock, query, result):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    response = {"jsonrpc": "2.0", "result": result, "id": query["id"]}
    sock.sendall(json.dumps(response).encode('utf-8') + b'\n')
    logger.debug('<= ' + json.dumps(response))

def send_update(sock, update):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    update["jsonrpc"] = "2.0"
    sock.sendall(json.dumps(update).encode('utf-8') + b'\n')
    logger.debug('<= ' + json.dumps(update))

def send_error(sock, nid, error):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    payload = {"error": error, "jsonrpc": "2.0", "id": nid}
    sock.sendall(json.dumps(payload).encode('utf-8') + b'\n')
    logger.debug('<= ' + json.dumps(payload))

def on_heartbeat_listening(txmonitor):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("on heartbeat listening")
    txmonitor.check_for_updated_txes()

def on_heartbeat_connected(sock, rpc, txmonitor):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("on heartbeat connected")
    is_tip_updated, header = check_for_new_blockchain_tip(rpc,
        are_headers_raw[0])
    if is_tip_updated:
        logger.debug("Blockchain tip updated")
        if subscribed_to_headers[0]:
            update = {"method": "blockchain.headers.subscribe",
                "params": [header]}
            send_update(sock, update)
    updated_scripthashes = txmonitor.check_for_updated_txes()
    for scrhash in updated_scripthashes:
        history_hash = txmonitor.get_electrum_history_hash(scrhash)
        update = {"method": "blockchain.scripthash.subscribe", "params": 
            [scrhash, history_hash]}
        send_update(sock, update)

def on_disconnect(txmonitor):
    subscribed_to_headers[0] = False
    txmonitor.unsubscribe_all_addresses()

def handle_query(sock, line, rpc, txmonitor, disable_mempool_fee_histogram,
        broadcast_method):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("=> " + line)
    try:
        query = json.loads(line)
    except json.decoder.JSONDecodeError as e:
        raise IOError(e)
    method = query["method"]

    #protocol documentation
    #https://github.com/kyuupichan/electrumx/blob/master/docs/PROTOCOL.rst
    if method == "blockchain.transaction.get":
        txid = query["params"][0]
        tx = None
        try:
            tx = rpc.call("gettransaction", [txid])["hex"]
        except JsonRpcError:
            if txid in txid_blockhash_map:
                tx = rpc.call("getrawtransaction", [txid, False,
                    txid_blockhash_map[txid]])
        if tx is not None:
            send_response(sock, query, tx)
        else:
            send_error(sock, query["id"], {"message": "txid not found"})
    elif method == "blockchain.transaction.get_merkle":
        txid = query["params"][0]
        try:
            tx = rpc.call("gettransaction", [txid])
            txheader = get_block_header(rpc, tx["blockhash"], False)
        except JsonRpcError as e:
            send_error(sock, query["id"], {"message": "txid not found"})
        else:
            try:
                core_proof = rpc.call("gettxoutproof", [[txid],
                    tx["blockhash"]])
                electrum_proof = merkleproof.\
                    convert_core_to_electrum_merkle_proof(core_proof)
                implied_merkle_root = hashes.hash_merkle_root(
                    electrum_proof["merkle"], txid, electrum_proof["pos"])
                if implied_merkle_root != electrum_proof["merkleroot"]:
                    raise ValueError
                reply = {"block_height": txheader["block_height"], "pos":
                    electrum_proof["pos"], "merkle": electrum_proof["merkle"]}
            except (ValueError, JsonRpcError) as e:
                logger.notice("merkle proof not found for " + txid + " sending"
                    + " a dummy, Electrum client should be run with "
                    + "--skipmerklecheck")
                #reply with a proof that the client with accept if
                # its configured to not check the merkle proof
                reply = {"block_height": txheader["block_height"], "pos": 0,
                    "merkle": [txid]}
            send_response(sock, query, reply)
    elif method == "blockchain.scripthash.subscribe":
        scrhash = query["params"][0]
        if txmonitor.subscribe_address(scrhash):
            history_hash = txmonitor.get_electrum_history_hash(scrhash)
        else:
            logger.warning("Address not known to server, hash(address) = " +
                scrhash + ".\nThis means Electrum is requesting information " +
                "about addresses that are missing from Electrum Personal " +
                "Server's configuration file.")
            history_hash = hashes.get_status_electrum([])
        send_response(sock, query, history_hash)
    elif method == "blockchain.scripthash.get_history":
        scrhash = query["params"][0]
        history = txmonitor.get_electrum_history(scrhash)
        if history == None:
            history = []
            logger.warning("Address history not known to server, " +
                "hash(address) = " + scrhash)
        send_response(sock, query, history)
    elif method == "blockchain.scripthash.get_balance":
        scrhash = query["params"][0]
        balance = txmonitor.get_address_balance(scrhash)
        if balance == None:
            logger.warning("Address history not known to server, " +
                "hash(address) = " + scrhash)
            balance = {"confirmed": 0, "unconfirmed": 0}
        send_response(sock, query, balance)
    elif method == "server.ping":
        send_response(sock, query, None)
    elif method == "blockchain.headers.subscribe":
        if protocol_version[0] in (1.2, 1.3):
            if len(query["params"]) > 0:
                are_headers_raw[0] = query["params"][0]
            else:
                are_headers_raw[0] = (False if protocol_version[0] == 1.2
                    else True)
        elif protocol_version[0] == 1.4:
            are_headers_raw[0] = True
        logger.debug("are_headers_raw = " + str(are_headers_raw[0]))
        subscribed_to_headers[0] = True
        new_bestblockhash, header = get_current_header(rpc, are_headers_raw[0])
        send_response(sock, query, header)
    elif method == "blockchain.block.get_header":
        height = query["params"][0]
        try:
            blockhash = rpc.call("getblockhash", [height])
            #this deprecated method (as of 1.3) can only return non-raw headers
            header = get_block_header(rpc, blockhash, False)
            send_response(sock, query, header)
        except JsonRpcError:
            error = {"message": "height " + str(height) + " out of range",
                "code": -1}
            send_error(sock, query["id"], error)
    elif method == "blockchain.block.header":
        height = query["params"][0]
        try:
            blockhash = rpc.call("getblockhash", [height])
            header = get_block_header(rpc, blockhash, True)
            send_response(sock, query, header["hex"])
        except JsonRpcError:
            error = {"message": "height " + str(height) + " out of range",
                "code": -1}
            send_error(sock, query["id"], error)
    elif method == "blockchain.block.headers":
        MAX_CHUNK_SIZE = 2016
        start_height = query["params"][0]
        count = query["params"][1]
        count = min(count, MAX_CHUNK_SIZE)
        headers_hex, n = get_block_headers_hex(rpc, start_height, count)
        send_response(sock, query, {'hex': headers_hex, 'count': n, 'max':
            MAX_CHUNK_SIZE})
    elif method == "blockchain.block.get_chunk":
        RETARGET_INTERVAL = 2016
        index = query["params"][0]
        tip_height = rpc.call("getblockchaininfo", [])["headers"]
        #logic copied from kyuupichan's electrumx get_chunk() in controller.py
        next_height = tip_height + 1
        start_height = min(index*RETARGET_INTERVAL, next_height)
        count = min(next_height - start_height, RETARGET_INTERVAL)
        headers_hex, n = get_block_headers_hex(rpc, start_height, count)
        send_response(sock, query, headers_hex)
    elif method == "blockchain.transaction.broadcast":
        txhex = query["params"][0]
        result = None
        txreport = rpc.call("testmempoolaccept", [[txhex]])[0]
        if not txreport["allowed"]:
            result = txreport["reject-reason"]
        else:
            result = txreport["txid"]
            if broadcast_method == "own-node":
                if not rpc.call("getnetworkinfo", [])["localrelay"]:
                    result = "Broadcast disabled when using blocksonly"
                    logger.warning("Transaction broadcasting disabled when " +
                        "blocksonly")
                else:
                    try:
                        rpc.call("sendrawtransaction", [txhex])
                    except JsonRpcError as e:
                        pass
            elif broadcast_method.startswith("system "):
                with tempfile.NamedTemporaryFile() as fd:
                    system_line = broadcast_method[7:].replace("%s", fd.name)
                    fd.write(txhex.encode())
                    fd.flush()
                    logger.debug("running command: " + system_line)
                    os.system(system_line)
            else:
                logger.error("Unrecognized broadcast method = "
                    + broadcast_method)
                result = "Unrecognized broadcast method"
        send_response(sock, query, result)
    elif method == "mempool.get_fee_histogram":
        if disable_mempool_fee_histogram:
            result = [[0, 0]]
            logger.debug("fee histogram disabled, sending back empty mempool")
        else:
            st = time.time()
            mempool = rpc.call("getrawmempool", [True])
            et = time.time()
            MEMPOOL_WARNING_DURATION = 10 #seconds
            if et - st > MEMPOOL_WARNING_DURATION:
                logger.warning("Mempool very large resulting in slow response" +
                    " by server. Consider setting " +
                    "`disable_mempool_fee_histogram = true`")
            #algorithm copied from the relevant place in ElectrumX
            #https://github.com/kyuupichan/electrumx/blob/e92c9bd4861c1e35989ad2773d33e01219d33280/server/mempool.py
            fee_hist = defaultdict(int)
            for txid, details in mempool.items():
                fee_rate = 1e8*details["fee"] // details["size"]
                fee_hist[fee_rate] += details["size"]
            l = list(reversed(sorted(fee_hist.items())))
            out = []
            size = 0
            r = 0
            binsize = 100000
            for fee, s in l:
                size += s
                if size + r > binsize:
                    out.append((fee, size))
                    r += size - binsize
                    size = 0
                    binsize *= 1.1
            result = out
        send_response(sock, query, result)
    elif method == "blockchain.estimatefee":
        estimate = rpc.call("estimatesmartfee", [query["params"][0]])
        feerate = 0.0001
        if "feerate" in estimate:
            feerate = estimate["feerate"]
        send_response(sock, query, feerate)
    elif method == "blockchain.relayfee":
        networkinfo = rpc.call("getnetworkinfo", [])
        send_response(sock, query, networkinfo["relayfee"])
    elif method == "server.banner":
        networkinfo = rpc.call("getnetworkinfo", [])
        blockchaininfo = rpc.call("getblockchaininfo", [])
        uptime = rpc.call("uptime", [])
        nettotals = rpc.call("getnettotals", [])
        send_response(sock, query, BANNER.format(
            serverversion=SERVER_VERSION_NUMBER,
            detwallets=len(txmonitor.deterministic_wallets),
            addr=len(txmonitor.address_history),
            useragent=networkinfo["subversion"],
            peers=networkinfo["connections"],
            uptime=str(datetime.timedelta(seconds=uptime)),
            blocksonly=not networkinfo["localrelay"],
            pruning=blockchaininfo["pruned"],
            recvbytes=hashes.bytes_fmt(nettotals["totalbytesrecv"]),
            sentbytes=hashes.bytes_fmt(nettotals["totalbytessent"]),
            donationaddr=DONATION_ADDR))
    elif method == "server.donation_address":
        send_response(sock, query, DONATION_ADDR)
    elif method == "server.version":
        client_protocol_version = query["params"][1]
        if isinstance(client_protocol_version, list):
            client_min, client_max = float(client_min)
        else:
            client_min = float(query["params"][1])
            client_max = client_min
        protocol_version[0] = min(client_max, SERVER_PROTOCOL_VERSION_MAX)
        if protocol_version[0] < max(client_min, SERVER_PROTOCOL_VERSION_MIN):
            logging.error("*** Client protocol version " + str(
                client_protocol_version) + " not supported, update needed")
            raise ConnectionRefusedError()
        send_response(sock, query, ["ElectrumPersonalServer "
            + SERVER_VERSION_NUMBER, protocol_version[0]])
    elif method == "server.peers.subscribe":
        send_response(sock, query, []) #no peers to report
    elif method == "blockchain.transaction.id_from_pos":
        height = query["params"][0]
        tx_pos = query["params"][1]
        merkle = False
        if len(query["params"]) > 2:
            merkle = query["params"][2]
        try:
            blockhash = rpc.call("getblockhash", [height])
            block = rpc.call("getblock", [blockhash, 1])
            txid = block["tx"][tx_pos]
            txid_blockhash_map[txid] = blockhash
            if not merkle:
                result = txid
            else:
                core_proof = rpc.call("gettxoutproof", [[txid], blockhash])
                electrum_proof =\
                    merkleproof.convert_core_to_electrum_merkle_proof(
                    core_proof)
                result = {"tx_hash": txid, "merkle": electrum_proof["merkle"]}
            send_response(sock, query, result)
        except JsonRpcError as e:
            error = {"message": repr(e)}
            send_error(sock, query["id"], error)
    else:
        logger.error("*** BUG! Not handling method: " + method + " query=" +
            str(query))
        #TODO just send back the same query with result = []

def get_block_header(rpc, blockhash, raw=False):
    rpc_head = rpc.call("getblockheader", [blockhash])
    if "previousblockhash" in rpc_head:
        prevblockhash = rpc_head["previousblockhash"]
    else:
        prevblockhash = "00"*32 #genesis block
    if raw:
        head_hex = struct.pack("<i32s32sIII", rpc_head["version"],
            binascii.unhexlify(prevblockhash)[::-1],
            binascii.unhexlify(rpc_head["merkleroot"])[::-1],
            rpc_head["time"], int(rpc_head["bits"], 16), rpc_head["nonce"])
        head_hex = binascii.hexlify(head_hex).decode("utf-8")
        header = {"hex": head_hex, "height": rpc_head["height"]}
    else:
        header = {"block_height": rpc_head["height"],
                "prev_block_hash": prevblockhash,
                "timestamp": rpc_head["time"],
                "merkle_root": rpc_head["merkleroot"],
                "version": rpc_head["version"],
                "nonce": rpc_head["nonce"],
                "bits": int(rpc_head["bits"], 16)}
    return header

def get_current_header(rpc, raw):
    new_bestblockhash = rpc.call("getbestblockhash", [])
    header = get_block_header(rpc, new_bestblockhash, raw)
    return new_bestblockhash, header

def check_for_new_blockchain_tip(rpc, raw):
    new_bestblockhash, header = get_current_header(rpc, raw)
    is_tip_new = bestblockhash[0] != new_bestblockhash
    bestblockhash[0] = new_bestblockhash
    return is_tip_new, header

def get_block_headers_hex(rpc, start_height, count):
    #read count number of headers starting from start_height
    result = bytearray()
    try:
        the_hash = rpc.call("getblockhash", [start_height])
    except JsonRpcError as e:
        return "", 0
    for i in range(count):
        header = rpc.call("getblockheader", [the_hash])
        #add header hex to result
        if "previousblockhash" in header:
            prevblockhash = header["previousblockhash"]
        else:
            prevblockhash = "00"*32 #genesis block
        h1 = struct.pack("<i32s32sIII", header["version"],
            binascii.unhexlify(prevblockhash)[::-1],
            binascii.unhexlify(header["merkleroot"])[::-1],
            header["time"], int(header["bits"], 16), header["nonce"])
        result.extend(h1)
        if "nextblockhash" not in header:
            break
        the_hash = header["nextblockhash"]
    return binascii.hexlify(result).decode("utf-8"), len(result)//80

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
    disable_mempool_fee_histogram = config.getboolean("electrum-server",
        "disable_mempool_fee_histogram", fallback=False)
    broadcast_method = config.get("electrum-server", "broadcast_method",
        fallback="own-node")

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

            logger.info('Electrum connected from ' + str(addr))
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
                        handle_query(sock, line.decode("utf-8"), rpc,
                            txmonitor, disable_mempool_fee_histogram,
                            broadcast_method)
                except socket.timeout:
                    on_heartbeat_connected(sock, rpc, txmonitor)
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
            on_disconnect(txmonitor)
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
        wal = deterministicwallet.parse_electrum_master_public_key(
            config.get("master-public-keys", key),
            int(config.get("bitcoin-rpc", "gap_limit")))
        deterministic_wallets.append(wal)

    #check whether these deterministic wallets have already been imported
    import_needed = False
    wallets_imported = 0
    spks_to_import = []
    TEST_ADDR_COUNT = 3
    logger.info("Displaying first " + str(TEST_ADDR_COUNT) + " addresses of " +
        "each master public key:")
    for config_mpk_key, wal in zip(config.options("master-public-keys"),
            deterministic_wallets):
        first_spks = wal.get_scriptpubkeys(change=0, from_index=0,
            count=TEST_ADDR_COUNT)
        first_addrs = [hashes.script_to_address(s, rpc) for s in first_spks]
        logger.info("\n" + config_mpk_key + " =>\n\t" + "\n\t".join(
            first_addrs))
        last_spk = wal.get_scriptpubkeys(0, int(config.get("bitcoin-rpc",
            "initial_import_count")) - 1, 1)
        last_addr = [hashes.script_to_address(last_spk[0], rpc)] 
        if not set(first_addrs + last_addr).issubset(imported_addresses):
            import_needed = True
            wallets_imported += 1
            for change in [0, 1]:
                spks_to_import.extend(wal.get_scriptpubkeys(change, 0,
                    int(config.get("bitcoin-rpc", "initial_import_count"))))
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
        addresses_to_import = [hashes.script_to_address(spk, rpc)
            for spk in spks_to_import]
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
            spks_to_monitor.extend(wal.get_scriptpubkeys(change, 0,
                int(config.get("bitcoin-rpc", "initial_import_count"))))
            #loop until one address found that isnt imported
            while True:
                spk = wal.get_new_scriptpubkeys(change, count=1)[0]
                spks_to_monitor.append(spk)
                if hashes.script_to_address(spk, rpc) not in imported_addresses:
                    break
            spks_to_monitor.pop()
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
            logger.debug('using cert: {}, key: {}'.format(certfile, keyfile))
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
    logger.info('Starting Electrum Personal Server')
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
    if opts.rescan:
        rescan_script(logger, rpc)
        return
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

def rescan_script(logger, rpc):
    user_input = input("Enter earliest wallet creation date (DD/MM/YYYY) "
        "or block height to rescan from: ")
    try:
        height = int(user_input)
    except ValueError:
        height = search_for_block_height_of_date(user_input, rpc)
        if height == -1:
            return
        height -= 2016 #go back two weeks for safety

    if input("Rescan from block height " + str(height) + " ? (y/n):") != 'y':
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

