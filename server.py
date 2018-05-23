#! /usr/bin/env python3

import socket, time, json, datetime, struct, binascii, ssl, os, os.path
from configparser import ConfigParser, NoSectionError, NoOptionError
from collections import defaultdict
import traceback, sys, platform
from ipaddress import ip_network, ip_address

from electrumpersonalserver.jsonrpc import JsonRpc, JsonRpcError
import electrumpersonalserver.hashes as hashes
import electrumpersonalserver.merkleproof as merkleproof
import electrumpersonalserver.deterministicwallet as deterministicwallet
import electrumpersonalserver.transactionmonitor as transactionmonitor

VERSION_NUMBER = "0.1"

DONATION_ADDR = "bc1q5d8l0w33h65e2l5x7ty6wgnvkvlqcz0wfaslpz"

BANNER = \
"""Welcome to Electrum Personal Server

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

##python has demented rules for variable scope, so these
## global variables are actually mutable lists
subscribed_to_headers = [False]
bestblockhash = [None]
debug_fd = None

#log for checking up/seeing your wallet, debug for when something has gone wrong
def debugorlog(line, ttype):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S,%f")
    return timestamp + " [" + ttype + "] " + line

def debug(line):
    global debug_fd
    if debug_fd == None:
        return
    debug_fd.write(debugorlog(line, "DEBUG") + "\n")
    debug_fd.flush()

def log(line):
    global debug_fd
    line = debugorlog(line, "  LOG")
    print(line)
    if debug_fd == None:
        return
    debug_fd.write(line + "\n")
    debug_fd.flush()

def send_response(sock, query, result):
    query["result"] = result
    query["jsonrpc"] = "2.0"
    sock.sendall(json.dumps(query).encode('utf-8') + b'\n')
    debug('<= ' + json.dumps(query))

def send_update(sock, update):
    update["jsonrpc"] = "2.0"
    sock.sendall(json.dumps(update).encode('utf-8') + b'\n')
    debug('<= ' + json.dumps(update))

def send_error(sock, nid, error):
    payload = {"error": error, "jsonrpc": "2.0", "id": nid}
    sock.sendall(json.dumps(payload).encode('utf-8') + b'\n')
    debug('<= ' + json.dumps(payload))

def on_heartbeat_listening(txmonitor):
    debug("on heartbeat listening")
    txmonitor.check_for_updated_txes()

def on_heartbeat_connected(sock, rpc, txmonitor):
    debug("on heartbeat connected")
    is_tip_updated, header = check_for_new_blockchain_tip(rpc)
    if is_tip_updated:
        debug("Blockchain tip updated")
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

def handle_query(sock, line, rpc, txmonitor):
    debug("=> " + line)
    try:
        query = json.loads(line)
    except json.decoder.JSONDecodeError as e:
        raise IOError(e)
    method = query["method"]

    #protocol documentation
    #https://github.com/kyuupichan/electrumx/blob/master/docs/PROTOCOL.rst
    if method == "blockchain.transaction.get":
        tx = rpc.call("gettransaction", [query["params"][0]])
        send_response(sock, query, tx["hex"])
    elif method == "blockchain.transaction.get_merkle":
        txid = query["params"][0]
        try:
            tx = rpc.call("gettransaction", [txid])
            core_proof = rpc.call("gettxoutproof", [[txid], tx["blockhash"]])
            electrum_proof = merkleproof.convert_core_to_electrum_merkle_proof(
                core_proof)
            implied_merkle_root = hashes.hash_merkle_root(
                electrum_proof["merkle"], txid, electrum_proof["pos"])
            if implied_merkle_root != electrum_proof["merkleroot"]:
                raise ValueError
            txheader = get_block_header(rpc, tx["blockhash"])
            reply = {"block_height": txheader["block_height"], "pos":
                electrum_proof["pos"], "merkle": electrum_proof["merkle"]}
        except (ValueError, JsonRpcError) as e:
            log("WARNING: merkle proof failed for " + txid + " err=" + repr(e))
            #so reply with an invalid proof which electrum handles without
            # disconnecting us
            #https://github.com/spesmilo/electrum/blob/c8e67e2bd07efe042703bc1368d499c5e555f854/lib/verifier.py#L74
            reply = {"block_height": 1, "pos": 0, "merkle": [txid]}
        send_response(sock, query, reply)
    elif method == "blockchain.scripthash.subscribe":
        scrhash = query["params"][0]
        if txmonitor.subscribe_address(scrhash):
            history_hash = txmonitor.get_electrum_history_hash(scrhash)
        else:
            log("WARNING: address scripthash not known to us: " + scrhash)
            history_hash = hashes.get_status_electrum([])
        send_response(sock, query, history_hash)
    elif method == "blockchain.scripthash.get_history":
        scrhash = query["params"][0]
        history = txmonitor.get_electrum_history(scrhash)
        if history == None:
            history = []
            log("WARNING: address scripthash history not known to us: "
                + scrhash)
        send_response(sock, query, history)
    elif method == "blockchain.headers.subscribe":
        subscribed_to_headers[0] = True
        new_bestblockhash, header = get_current_header(rpc)
        send_response(sock, query, header)
    elif method == "blockchain.block.get_header":
        height = query["params"][0]
        try:
            blockhash = rpc.call("getblockhash", [height])
            header = get_block_header(rpc, blockhash)
            send_response(sock, query, header)
        except JsonRpcError:
            error = {"message": "height " + str(height) + " out of range",
                "code": -1}
            send_error(sock, query["id"], error)
    elif method == "blockchain.block.get_chunk":
        RETARGET_INTERVAL = 2016
        index = query["params"][0]
        tip_height = rpc.call("getblockchaininfo", [])["headers"]
        #logic copied from kyuupichan's electrumx get_chunk() in controller.py
        next_height = tip_height + 1
        start_height = min(index*RETARGET_INTERVAL, next_height)
        count = min(next_height - start_height, RETARGET_INTERVAL)
        #read count number of headers starting from start_height
        result = bytearray()
        the_hash = rpc.call("getblockhash", [start_height])
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
        send_response(sock, query, binascii.hexlify(result).decode("utf-8"))
    elif method == "blockchain.transaction.broadcast":
        try:
            result = rpc.call("sendrawtransaction", [query["params"][0]])
        except JsonRpcError as e:
            result = str(e)
        debug("tx broadcast result = " + str(result))
        send_response(sock, query, result)
    elif method == "mempool.get_fee_histogram":
        mempool = rpc.call("getrawmempool", [True])

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
        send_response(sock, query, ["ElectrumPersonalServer "
            + VERSION_NUMBER, VERSION_NUMBER])
    elif method == "server.peers.subscribe":
        send_response(sock, query, []) #no peers to report
    else:
        log("*** BUG! Not handling method: " + method + " query=" + str(query))
        #TODO just send back the same query with result = []

def get_block_header(rpc, blockhash):
    rpc_head = rpc.call("getblockheader", [blockhash])
    if "previousblockhash" in rpc_head:
        prevblockhash = rpc_head["previousblockhash"]
    else:
        prevblockhash = "00"*32 #genesis block
    header = {"block_height": rpc_head["height"],
            "prev_block_hash": prevblockhash,
            "timestamp": rpc_head["time"],
            "merkle_root": rpc_head["merkleroot"],
            "version": rpc_head["version"],
            "nonce": rpc_head["nonce"],
            "bits": int(rpc_head["bits"], 16)}
    return header

def get_current_header(rpc):
    new_bestblockhash = rpc.call("getbestblockhash", [])
    header = get_block_header(rpc, new_bestblockhash)
    return new_bestblockhash, header

def check_for_new_blockchain_tip(rpc):
    new_bestblockhash, header = get_current_header(rpc)
    is_tip_new = bestblockhash[0] != new_bestblockhash
    bestblockhash[0] = new_bestblockhash
    return is_tip_new, header

def create_server_socket(hostport):
    server_sock = socket.socket()
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(hostport)
    server_sock.listen(1)
    log("Listening for Electrum Wallet on " + str(hostport))
    return server_sock

def run_electrum_server(rpc, txmonitor, hostport, ip_whitelist,
        poll_interval_listening, poll_interval_connected, certfile, keyfile):
    log("Starting electrum server")
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
                        debug(addr[0] + " not in whitelist, closing")
                        raise ConnectionRefusedError()
                    sock = ssl.wrap_socket(sock, server_side=True,
                        certfile=certfile, keyfile=keyfile,
                        ssl_version=ssl.PROTOCOL_SSLv23)
                except socket.timeout:
                    on_heartbeat_listening(txmonitor)
                except (ConnectionRefusedError, ssl.SSLError):
                    sock.close()
                    sock = None

            log('Electrum connected from ' + str(addr))
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
                            txmonitor)
                except socket.timeout:
                    on_heartbeat_connected(sock, rpc, txmonitor)
        except (IOError, EOFError) as e:
            if isinstance(e, EOFError):
                log("Electrum wallet disconnected")
            else:
                log("IOError: " + repr(e))
            try:
                sock.close()
            except IOError:
                pass
            sock = None
            on_disconnect(txmonitor)
            time.sleep(0.2)

def get_scriptpubkeys_to_monitor(rpc, config):
    imported_addresses = set(rpc.call("getaddressesbyaccount",
        [transactionmonitor.ADDRESSES_LABEL]))

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
    for wal in deterministic_wallets:
        first_addr = hashes.script_to_address(wal.get_scriptpubkeys(change=0,
            from_index=0, count=1)[0], rpc)
        if first_addr not in imported_addresses:
            import_needed = True
            wallets_imported += 1
            for change in [0, 1]:
                spks_to_import.extend(wal.get_scriptpubkeys(change, 0,
                    int(config.get("bitcoin-rpc", "initial_import_count"))))
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

    #if addresses need to be imported then return them
    if import_needed:
        addresses_to_import = [hashes.script_to_address(spk, rpc)
            for spk in spks_to_import]
        #TODO minus imported_addresses
        log("Importing " + str(wallets_imported) + " wallets and " +
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
    return False, spks_to_monitor, deterministic_wallets

def obtain_rpc_username_password(datadir):
    if len(datadir.strip()) == 0:
        debug("no datadir configuration, checking in default location")
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
        log("Unable to find .cookie file, try setting `datadir` config")
        return None, None
    fd = open(cookie_path)
    username, password = fd.read().strip().split(":")
    fd.close()
    return username, password

def main():
    global debug_fd
    if len(sys.argv) == 2:
        if sys.argv[1] == "--help":
            print("Usage: ./server.py <path/to/current/working/dir>\nRunning" +
                " without arg defaults to the directory you're in right now")
            return
        else:
            os.chdir(sys.argv[1])
    debug_fd = open("debug.log", "w")
    debug("current working directory is: " + os.getcwd())
    try:
        config = ConfigParser()
        config.read("config.cfg")
        config.options("master-public-keys")
    except NoSectionError:
        log("Non-existant configuration file `config.cfg`")
        return
    try:
        rpc_u = config.get("bitcoin-rpc", "rpc_user")
        rpc_p = config.get("bitcoin-rpc", "rpc_password")
        debug("obtaining auth from rpc_user/pass")
    except NoOptionError:
        rpc_u, rpc_p = obtain_rpc_username_password(config.get(
            "bitcoin-rpc", "datadir"))
        debug("obtaining auth from .cookie")
    if rpc_u == None:
        return
    rpc = JsonRpc(host = config.get("bitcoin-rpc", "host"),
        port = int(config.get("bitcoin-rpc", "port")),
        user = rpc_u, password = rpc_p,
        wallet_filename=config.get("bitcoin-rpc", "wallet_filename").strip())

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
                log("Error with bitcoin json-rpc: " + repr(e))
                printed_error_msg = True
            time.sleep(5)

    import_needed, relevant_spks_addrs, deterministic_wallets = \
        get_scriptpubkeys_to_monitor(rpc, config)
    if import_needed:
        transactionmonitor.import_addresses(rpc, relevant_spks_addrs, debug,
            log)
        log("Done.\nIf recovering a wallet which already has existing " +
            "transactions, then\nrun the rescan script. If you're confident " +
            "that the wallets are new\nand empty then there's no need to " +
            "rescan, just restart this script")
    else:
        txmonitor = transactionmonitor.TransactionMonitor(rpc,
            deterministic_wallets, debug, log)
        if not txmonitor.build_address_history(relevant_spks_addrs):
            return
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
        certfile = config.get("electrum-server", "certfile")
        keyfile = config.get("electrum-server", "keyfile")
        run_electrum_server(rpc, txmonitor, hostport, ip_whitelist,
            poll_interval_listening, poll_interval_connected, certfile, keyfile)

if __name__ == "__main__":
    main()
