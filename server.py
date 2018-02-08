#! /usr/bin/python3

#add a feature where it prints the first 3 addresses from a deterministic
# wallet, so you can check the addresses are correct before importing them
# into the node

#or deterministic wallets
#should figure out what do regarding gap limits, when to import more addresses
# and how many addresses to start with
# maybe have a separate list of later addresses and if one of them get
#  requested then import more

#TODO try to support ssl
#doesnt support ssl yet you you must run ./electrum --nossl
#https://github.com/spesmilo/electrum/commit/dc388d4c7c541fadb9869727e359edace4c9f6f0
#maybe copy from electrumx
#https://github.com/kyuupichan/electrumx/blob/35dd1f61996b02a84691ea71ff50f0900df969bc/server/peers.py#L476
#https://github.com/kyuupichan/electrumx/blob/2d7403f2efed7e8f33c5cb93e2cd9144415cbb9f/server/controller.py#L259

#merkle trees cant be used if bitcoin core has pruning enabled, this will
# probably requires new code to be written for core
#another possible use of merkleproofs in wallet.dat
# https://github.com/JoinMarket-Org/joinmarket/issues/156#issuecomment-231059844

#using core's multiple wallet feature might help, should read up on that

#now that the rescanblockchain rpc call exists in 0.16 which allows specifying
# a starting height, that will cut down the time to rescan as long as the user
# has saved their wallet creation date

#one day there could be a nice GUI which does everything, including converting
# the wallet creation date to a block height and rescanning
'''
<belcher> now that 0.16 has this rpc called rescanblockchain which takes an optional start_height, i wonder what the most practical way of converting date to block height is
<belcher> thinking about the situation where you have a mnemonic recovery phrase + the date you created it, and want to rescan
<belcher> binary search the timestamps in the block headers i guess, then subtract two weeks just in case
<wumpus> belcher: binary search in something that is not strictly increasing seems faulty
<belcher> yes true, so maybe binary search to roughly get to the right block height then linear search +- a few blocks
<wumpus> belcher: though my gut feeling is that subtracting the two weeks would fix it
<belcher> when people write down the wallet creation date they probably wont be precise, you could get away with writing only the year and month i bet
<wumpus> as the mismatch is at most 2 hours
<Sentineo> wumpus: 2 hours for the clock scew allowed by peers? (when they throw away a block which is older than 2 hours from their actual time)?
<wumpus> Sentineo: that's what I remember, I might be off though
<Sentineo> I am not sure if it s 2 or 4 :D
<Sentineo> lazyness :)
<wumpus> in any case it is a bounded value, which means binary search might work within that precision, too lazy to look for proof though :)
'''

##### good things

# well placed to take advantage of dandelion private tx broadcasting
# and broadcasting through tor

import socket, time, json, datetime, struct, binascii, math, pprint
from configparser import ConfigParser, NoSectionError
from decimal import Decimal

from jsonrpc import JsonRpc, JsonRpcError
import util
import bitcoin as btc

ADDRESSES_LABEL = "electrum-watchonly-addresses"

VERSION_NUMBER = "0.1"

BANNER = \
"""Welcome to Electrum Personal Server
gitub.com/whatever

Monitoring {addr} addresses

Connected bitcoin node: {useragent}
Peers: {peers}
Uptime: {uptime}
Blocksonly: {blocksonly}
Pruning: {pruning}
"""

##python has demented rules for variable scope, so these
## global variables are actually mutable lists
subscribed_to_headers = [False]
bestblockhash = [None]
last_known_recent_txid = [None]

#log for checking up/seeing your wallet, debug for when something has gone wrong
def debugorlog(line, ttype):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S,%f")
    print(timestamp + " [" + ttype + "] " + line)

def debug(line):
    debugorlog(line, "DEBUG")

def log(line):
    debugorlog(line, "  LOG")

def send_response(sock, query, result):
    query["result"] = result
    query["jsonrpc"] = "2.0"
    sock.sendall(json.dumps(query).encode('utf-8') + b'\n')
    debug('<= ' + json.dumps(query))

def send_update(sock, update):
    update["jsonrpc"] = "2.0"
    sock.sendall(json.dumps(update).encode('utf-8') + b'\n')
    debug('<= ' + json.dumps(update))

def on_heartbeat_listening(rpc, address_history, unconfirmed_txes):
    debug("on heartbeat listening")
    check_for_updated_txes(rpc, address_history, unconfirmed_txes)

def on_heartbeat_connected(sock, rpc, address_history, unconfirmed_txes):
    debug("on heartbeat connected")
    is_tip_updated, header = check_for_new_blockchain_tip(rpc)
    if is_tip_updated:
        log("Blockchain tip updated")
        if subscribed_to_headers[0]:
            update = {"method": "blockchain.headers.subscribe",
                "params": [header]}
            send_update(sock, update)
    updated_scripthashes = check_for_updated_txes(rpc, address_history,
        unconfirmed_txes)
    for scrhash in updated_scripthashes:
        if not address_history[scrhash]["subscribed"]:
            continue
        history_hash = util.get_status_electrum( ((h["tx_hash"], h["height"])
            for h in address_history[scrhash]["history"]) )
        update = {"method": "blockchain.scripthash.subscribe", "params": 
            [scrhash, history_hash]}
        send_update(sock, update)

def on_disconnect(address_history):
    subscribed_to_headers[0] = False
    for srchash, his in address_history.items():
        his["subscribed"] = False

def handle_query(sock, line, rpc, address_history):
    debug("=> " + line)
    try:
        query = json.loads(line)
    except json.decoder.JSONDecodeError as e:
        raise IOError(e)
    method = query["method"]

    #protocol documentation
    #https://github.com/kyuupichan/electrumx/blob/master/docs/PROTOCOL.rst
    if method == "blockchain.transaction.get":
        try:
            tx = rpc.call("gettransaction", [query["params"][0]])
            send_response(sock, query, tx["hex"])
        except JsonRpcError:
            debug("Unable to get tx " + query["params"][0])
    elif method == "blockchain.transaction.get_merkle":
        #we dont support merkle proofs yet, but we must reply with
        #something otherwise electrum will disconnect from us
        #so reply with an invalid proof
        #https://github.com/spesmilo/electrum/blob/c8e67e2bd07efe042703bc1368d499c5e555f854/lib/verifier.py#L74
        txid = query["params"][0]
        reply = {"block_height": 1, "pos": 0, "merkle": [txid]}
        send_response(sock, query, reply)
    elif method == "blockchain.scripthash.subscribe":
        scrhash = query["params"][0]
        if scrhash in address_history:
            address_history[scrhash]["subscribed"] = True
            history_hash = util.get_status_electrum((
                (h["tx_hash"], h["height"])
                for h in address_history[scrhash]["history"]))
        else:
            log("WARNING: address scripthash not known to us: " + scrhash)
            history_hash = util.get_status_electrum([])
        send_response(sock, query, history_hash)
    elif method == "blockchain.scripthash.get_history":
        scrhash = query["params"][0]
        if scrhash in address_history:
            history = address_history[scrhash]["history"]
        else:
            history = []
            log("WARNING: address scripthash history not known to us: "
                + scrhash)
        send_response(sock, query, history)
    elif method == "blockchain.headers.subscribe":
        subscribed_to_headers[0] = True
        new_bestblockhash, header = get_current_header(rpc)
        send_response(sock, query, header)
    elif method == "blockchain.block.get_header":
        blockhash = rpc.call("getblockhash", [query["params"][0]])
        header = get_block_header(rpc, blockhash)
        send_response(sock, query, header)
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
            h1 = struct.pack("<i32s32sIII", header["version"],
                binascii.unhexlify(header["previousblockhash"])[::-1],
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
            result = e.message
        debug("tx broadcast result = " + str(result))
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
        send_response(sock, query, BANNER.format(
            addr=len(address_history),
            useragent=networkinfo["subversion"],
            peers=networkinfo["connections"],
            uptime=str(datetime.timedelta(seconds=uptime)),
            blocksonly=not networkinfo["localrelay"],
            pruning=blockchaininfo["pruned"]))
    elif method == "server.donation_address":
        send_response(sock, query, "bc1q5d8l0w33h65e2l5x7ty6wgnvkvlqcz0wfaslpz")
    elif method == "server.version":
        send_response(sock, query, ["ElectrumPersonalServer "
            + VERSION_NUMBER, VERSION_NUMBER])
    elif method == "server.peers.subscribe":
        send_response(sock, query, []) #no peers to report
    else:
        log("*** BUG! Not handling method: " + method + " query=" + str(query))

def get_block_header(rpc, blockhash):
    rpc_head = rpc.call("getblockheader", [blockhash])
    header = {"block_height": rpc_head["height"],
            "prev_block_hash": rpc_head["previousblockhash"],
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
    #TODO might not handle more than one block appearing, might need to
    # use a "last known block" similar to the transaction code
    new_bestblockhash, header = get_current_header(rpc)
    is_tip_new = bestblockhash[0] != new_bestblockhash
    bestblockhash[0] = new_bestblockhash
    return is_tip_new, header

def create_server_socket(hostport):
    server_sock = socket.socket()
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(hostport)
    log("Listening on " + str(hostport))
    return server_sock

def run_electrum_server(hostport, rpc, address_history, unconfirmed_txes,
        poll_interval_listening, poll_interval_connected):
    log("Starting electrum server")
    while True:
        try:
            server_sock = create_server_socket(hostport)
            server_sock.settimeout(poll_interval_listening)
            while True:
                try:
                    server_sock.listen(1)
                    sock, addr = server_sock.accept()
                    break
                except socket.timeout:
                    on_heartbeat_listening(rpc, address_history,
                        unconfirmed_txes)
            server_sock.close()
            sock.settimeout(poll_interval_connected)
            log('Electrum connected from ' + str(addr))
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
                            address_history)
                except socket.timeout:
                    on_heartbeat_connected(sock, rpc, address_history,
                        unconfirmed_txes)
        except (IOError, EOFError) as e:
            if isinstance(e, EOFError):
                log("Electrum wallet disconnected")
            else:
                log("IOError: " + repr(e))
            on_disconnect(address_history)
            time.sleep(0.2)
            try:
                server_sock.close()
            except IOError:
                pass

def get_input_and_output_scriptpubkeys(rpc, txid):
    gettx = rpc.call("gettransaction", [txid])
    txd = btc.deserialize(gettx["hex"])
    output_scriptpubkeys = [sc['script'] for sc in txd['outs']]
    input_scriptpubkeys = []
    for ins in txd["ins"]:
        try:
            wallet_tx = rpc.call("gettransaction", [ins["outpoint"][
                "hash"]])
        except JsonRpcError:
            #wallet doesnt know about this tx, so the input isnt ours
            continue
        script = btc.deserialize(str(wallet_tx["hex"]))["outs"][ins[
            "outpoint"]["index"]]["script"]
        input_scriptpubkeys.append(script)
    return output_scriptpubkeys, input_scriptpubkeys, txd

def generate_new_history_element(rpc, tx, txd):
    if tx["confirmations"] == 0:
        unconfirmed_input = False
        total_input_value = 0
        for ins in txd["ins"]:
            utxo = rpc.call("gettxout", [ins["outpoint"]["hash"],
                ins["outpoint"]["index"], True])
            if utxo is None:
                utxo = rpc.call("gettxout", [ins["outpoint"]["hash"],
                    ins["outpoint"]["index"], False])
                if utxo is None:
                    debug("utxo not found(!)")
                    #TODO detect this and figure out how to tell
                    # electrum that we dont know the fee
            total_input_value += int(Decimal(utxo["value"]) * Decimal(1e8))
            unconfirmed_input = unconfirmed_input or utxo["confirmations"] == 0
        debug("total_input_value = " + str(total_input_value))

        fee = total_input_value - sum([sc["value"] for sc in txd["outs"]])
        height = -1 if unconfirmed_input else 0
        new_history_element = ({"tx_hash": tx["txid"], "height": height,
            "fee": fee})
    else:
        blockheader = rpc.call("getblockheader", [tx['blockhash']])
        new_history_element = ({"tx_hash": tx["txid"],
            "height": blockheader["height"]})
    return new_history_element

def sort_address_history_list(his):
    unconfirm_txes = list(filter(lambda h:h["height"] == 0, his["history"]))
    confirm_txes = filter(lambda h:h["height"] != 0, his["history"])
    #TODO txes must be "in blockchain order"
    # the order they appear in the block
    # it might be "blockindex" in listtransactions and gettransaction
    #so must sort with key height+':'+blockindex
    #perhaps check if any heights are the same then get the pos only for those
    #a better way to do this is to have a separate dict that isnt in history
    # which maps txid => blockindex
    # and then sort by key height+":"+idx[txid]
    his["history"] = sorted(confirm_txes, key=lambda h:h["height"])
    his["history"].extend(unconfirm_txes)
    return unconfirm_txes

def check_for_updated_txes(rpc, address_history, unconfirmed_txes):
    updated_srchashes1 = check_for_unconfirmed_txes(rpc, address_history,
        unconfirmed_txes)
    updated_srchashes2 = check_for_confirmations(rpc, address_history,
        unconfirmed_txes)
    updated_srchashes = updated_srchashes1 | updated_srchashes2
    for ush in updated_srchashes:
        his = address_history[ush]
        sort_address_history_list(his)
    if len(updated_srchashes) > 0:
        debug("new tx address_history =\n" + pprint.pformat(address_history))
        debug("unconfirmed txes = " + pprint.pformat(unconfirmed_txes))
        debug("updated_scripthashes = " + str(updated_srchashes))
    else:
        debug("no updated txes")
    return updated_srchashes

def check_for_confirmations(rpc, address_history, unconfirmed_txes):
    confirmed_txes_srchashes = []
    debug("check4con unconfirmed_txes = " + pprint.pformat(unconfirmed_txes))
    for uc_txid, srchashes in unconfirmed_txes.items():
        tx = rpc.call("gettransaction", [uc_txid])
        debug("uc_txid=" + uc_txid + " => " + str(tx))
        if tx["confirmations"] == 0:
            continue #still unconfirmed
        log("A transaction confirmed: " + uc_txid)
        confirmed_txes_srchashes.append((uc_txid, srchashes))
        block = rpc.call("getblockheader", [tx["blockhash"]])
        for srchash in srchashes:
            #delete the old unconfirmed entry in address_history
            deleted_entries = [h for h in address_history[srchash][
                "history"] if h["tx_hash"] == uc_txid]
            for d_his in deleted_entries:
                address_history[srchash]["history"].remove(d_his)
            #create the new confirmed entry in address_history
            address_history[srchash]["history"].append({"height":
                block["height"], "tx_hash": uc_txid})
    updated_srchashes = set()
    for tx, srchashes in confirmed_txes_srchashes:
        del unconfirmed_txes[tx]
        updated_srchashes.update(set(srchashes))
    return updated_srchashes

def check_for_unconfirmed_txes(rpc, address_history, unconfirmed_txes):
    MAX_TX_REQUEST_COUNT = 256 
    tx_request_count = 2
    max_attempts = int(math.log(MAX_TX_REQUEST_COUNT, 2))
    for i in range(max_attempts):
        debug("listtransactions tx_request_count=" + str(tx_request_count))
        ret = rpc.call("listtransactions", ["*", tx_request_count, 0, True])
        ret = ret[::-1]
        if last_known_recent_txid[0] == None:
            recent_tx_index = len(ret) #=0 means no new txes
            break
        else:
            txid_list = [(tx["txid"], tx["address"]) for tx in ret]
            recent_tx_index = next((i for i, (txid, addr)
                in enumerate(txid_list) if
                txid == last_known_recent_txid[0][0] and
                addr == last_known_recent_txid[0][1]), -1)
            if recent_tx_index != -1:
                break
            tx_request_count *= 2

    #TODO low priority: handle a user getting more than 255 new
    # transactions in 15 seconds
    debug("recent tx index = " + str(recent_tx_index) + " ret = " + str(ret))
    #    str([(t["txid"], t["address"]) for t in ret]))
    if len(ret) > 0:
        last_known_recent_txid[0] = (ret[0]["txid"], ret[0]["address"])
        debug("last_known_recent_txid = " + str(last_known_recent_txid[0]))
    assert(recent_tx_index != -1)
    if recent_tx_index == 0:
        return set()
    new_txes = ret[:recent_tx_index][::-1]
    debug("new txes = " + str(new_txes))
    #tests: finding one unconfirmed tx, finding one confirmed tx
    #sending a tx that has nothing to do with our wallets
    #getting a new tx on a completely empty wallet
    #finding a confirmed and unconfirmed tx, in that order, then both confirm
    #finding an unconfirmed and confirmed tx, in that order, then both confirm
    #send a tx to an address which hasnt been used before
    obtained_txids = set()
    updated_scripthashes = []
    for tx in new_txes:
        if "txid" not in tx or "category" not in tx:
            continue
        if tx["category"] not in ("receive", "send"):
            continue
        if tx["txid"] in obtained_txids:
            continue
        obtained_txids.add(tx["txid"])
        output_scriptpubkeys, input_scriptpubkeys, txd = \
            get_input_and_output_scriptpubkeys(rpc, tx["txid"])

        matching_scripthashes = []
        for spk in (output_scriptpubkeys + input_scriptpubkeys):
            scripthash = util.script_to_scripthash(spk)
            if scripthash in address_history:
                matching_scripthashes.append(scripthash)
        if len(matching_scripthashes) == 0:
            continue
        updated_scripthashes.extend(matching_scripthashes)
        new_history_element = generate_new_history_element(rpc, tx, txd)
        log("Found new unconfirmed tx: " + str(new_history_element))
        for srchash in matching_scripthashes:
            address_history[srchash]["history"].append(new_history_element)
            if new_history_element["height"] == 0:
                if tx["txid"] in unconfirmed_txes:
                    unconfirmed_txes[tx["txid"]].append(srchash)
                else:
                    unconfirmed_txes[tx["txid"]] = [srchash]
    return set(updated_scripthashes)

def build_address_history_index(rpc, wallet_addresses):
    log("Building history index with " + str(len(wallet_addresses)) +
        " addresses")
    st = time.time()
    address_history = {}
    for addr in wallet_addresses:
        scripthash = util.address_to_scripthash(addr)
        address_history[scripthash] = {'addr': addr, 'history': [],
            'subscribed': False}
    wallet_addr_scripthashes = set(address_history.keys())
    #populate history
    #which is a blockheight-ordered list of ("txhash", height)
    #unconfirmed transactions go at the end as ("txhash", 0, fee)
    # 0=unconfirmed -1=unconfirmed with unconfirmed parents

    BATCH_SIZE = 1000
    ret = list(range(BATCH_SIZE))
    t = 0
    count = 0
    obtained_txids = set()
    while len(ret) == BATCH_SIZE:
        ret = rpc.call("listtransactions", ["*", BATCH_SIZE, t, True])
        debug("listtransactions skip=" + str(t) + " len(ret)=" + str(len(ret)))
        t += len(ret)
        for tx in ret:
            if "txid" not in tx or "category" not in tx:
                continue
            if tx["category"] not in ("receive", "send"):
                continue
            if tx["txid"] in obtained_txids:
                continue
            obtained_txids.add(tx["txid"])

            #obtain all the addresses this transaction is involved with
            output_scriptpubkeys, input_scriptpubkeys, txd = \
                get_input_and_output_scriptpubkeys(rpc, tx["txid"])
            output_scripthashes = [util.script_to_scripthash(sc)
                for sc in output_scriptpubkeys]
            sh_to_add = wallet_addr_scripthashes.intersection(set(
                output_scripthashes))
            input_scripthashes = [util.script_to_scripthash(sc)
                for sc in input_scriptpubkeys]
            sh_to_add |= wallet_addr_scripthashes.intersection(set(
                input_scripthashes))
            if len(sh_to_add) == 0:
                continue

            new_history_element = generate_new_history_element(rpc, tx, txd)
            for scripthash in sh_to_add:
                address_history[scripthash][
                    "history"].append(new_history_element)
            count += 1

    unconfirmed_txes = {}
    for srchash, his in address_history.items():
        uctx = sort_address_history_list(his)
        for u in uctx:
            if u["tx_hash"] in unconfirmed_txes:
                unconfirmed_txes[u["tx_hash"]].append(srchash)
            else:
                unconfirmed_txes[u["tx_hash"]] = [srchash]
    debug("unconfirmed_txes = " + str(unconfirmed_txes))
    if len(ret) > 0:
        #txid doesnt uniquely identify transactions from listtransactions
        #but the tuple (txid, address) does
        last_known_recent_txid[0] = (ret[-1]["txid"], ret[-1]["address"])
    else:
        last_known_recent_txid[0] = None
    debug("last_known_recent_txid = " + str(last_known_recent_txid[0]))

    et = time.time()
    log("Found " + str(count) + " txes. Address history index built in "
        + str(et - st) + "sec")
    debug("address_history =\n" + pprint.pformat(address_history))

    return address_history, unconfirmed_txes

def import_watchonly_addresses(rpc, addrs):
    log("Importing " + str(len(addrs)) + " watch-only addresses into the"
        + " Bitcoin node after 5 seconds . . .")
    debug("addrs = " + str(addrs))
    time.sleep(5)
    for a in addrs:
        rpc.call("importaddress", [a, ADDRESSES_LABEL, False])
    #TODO tell people about the `rescanblockchain` call which allows a range
    log("Done.\nIf recovering a wallet which already has existing " +
        "transactions, then\nrestart Bitcoin with -rescan. If your wallet " +
        "is new and empty then just restart this script")

def main():
    try:
        config = ConfigParser()
        config.read(["config.cfg"])
        config.options("wallets")
    except NoSectionError:
        log("Non-existant configuration file `config.cfg`")
        return
    rpc = JsonRpc(host = config.get("bitcoin-rpc", "host"),
                port = int(config.get("bitcoin-rpc", "port")),
                user = config.get("bitcoin-rpc", "user"),
                password = config.get("bitcoin-rpc", "password"))
    #TODO somewhere here loop until rpc works and fully sync'd, to allow
    # people to run this script without waiting for their node to fully
    # catch up sync'd when getblockchaininfo blocks == headers, or use
    # verificationprogress
    printed_error_msg = False
    while bestblockhash[0] == None:
        try:
            bestblockhash[0] = rpc.call("getbestblockhash", [])
        except TypeError:
            if not printed_error_msg:
                log("Error with bitcoin rpc, check host/port/username/password")
                printed_error_msg = True
            time.sleep(5)
    wallet_addresses = []
    for key in config.options("wallets"):
        addrs = config.get("wallets", key).replace(' ', ',').split(',')
        wallet_addresses.extend(addrs)
    wallet_addresses = set(wallet_addresses)
    imported_addresses = set(rpc.call("getaddressesbyaccount",
        [ADDRESSES_LABEL]))
    if not wallet_addresses.issubset(imported_addresses):
        import_watchonly_addresses(rpc, wallet_addresses - imported_addresses)
    else:
        address_history, unconfirmed_txes = build_address_history_index(
            rpc, wallet_addresses)
        hostport = (config.get("electrum-server", "host"),
                int(config.get("electrum-server", "port")))
        run_electrum_server(hostport, rpc, address_history, unconfirmed_txes,
            int(config.get("bitcoin-rpc", "poll_interval_listening")),
            int(config.get("bitcoin-rpc", "poll_interval_connected")))

main()
