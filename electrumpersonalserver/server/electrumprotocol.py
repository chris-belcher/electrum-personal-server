import json
import datetime
import time
import binascii
import os
import struct
import tempfile
import socket
from collections import defaultdict

from electrumpersonalserver.server.hashes import (
    hash_merkle_root,
    get_status_electrum,
    bytes_fmt
)
from .jsonrpc import JsonRpc, JsonRpcError
from electrumpersonalserver.server.peertopeer import tor_broadcast_tx
from electrumpersonalserver.server.merkleproof import (
    convert_core_to_electrum_merkle_proof
)

#protocol documentation
#https://github.com/kyuupichan/electrumx/blob/master/docs/protocol-methods.rst

SERVER_VERSION_NUMBER = "0.2.0"

SERVER_PROTOCOL_VERSION_MAX = 1.4
SERVER_PROTOCOL_VERSION_MIN = 1.1

DONATION_ADDR = "bc1q5d8l0w33h65e2l5x7ty6wgnvkvlqcz0wfaslpz"

BANNER = \
"""Welcome to Electrum Personal Server {serverversion}

Monitoring {detwallets} deterministic wallets, in total {addr} addresses.

Connected bitcoin node: {useragent}
Uptime: {uptime}
Peers: {peers}
Download: {recvbytes} ({recvbytesperday} per day)
Upload: {sentbytes} ({sentbytesperday} per day)
Blocksonly: {blocksonly}
Pruning: {pruning}
Blockchain size: {blockchainsizeondisk}
{firstunprunedblock}
https://github.com/chris-belcher/electrum-personal-server

Donate to help make Electrum Personal Server even better:
{donationaddr}

"""

class UnknownScripthashError(Exception):
    pass

def get_tor_hostport():
    # Probable ports for Tor to listen at
    host = "127.0.0.1"
    ports = [9050, 9150]
    for port in ports:
        try:
            s = (socket._socketobject if hasattr(socket, "_socketobject")
                 else socket.socket)(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((host, port))
            # Tor responds uniquely to HTTP-like requests
            s.send(b"GET\n")
            if b"Tor is not an HTTP Proxy" in s.recv(1024):
                return (host, port)
        except socket.error:
            pass
    return None


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
    bestblockhash = rpc.call("getbestblockhash", [])
    header = get_block_header(rpc, bestblockhash, raw)
    return bestblockhash, header

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

class ElectrumProtocol(object):
    """
    Class which implements the electrum protocol for one single connection. It
    does not handle the actual sockets, which could be any combination of 
    blocking/non-blocking, asyncio, twisted, etc
    This class may be instantized multiple times if the server accepts multiple
    client connections at once
    """

    def __init__(self, rpc, txmonitor, logger, broadcast_method,
            tor_hostport, disable_mempool_fee_histogram):
        self.rpc = rpc
        self.txmonitor = txmonitor
        self.logger = logger
        self.broadcast_method = broadcast_method
        self.tor_hostport = tor_hostport
        self.disable_mempool_fee_histogram = disable_mempool_fee_histogram

        self.protocol_version = 0   
        self.subscribed_to_headers = False
        self.are_headers_raw = False
        self.txid_blockhash_map = {}
        self.printed_slow_mempool_warning = False

    def set_send_reply_fun(self, send_reply_fun):
        self.send_reply_fun = send_reply_fun

    def on_blockchain_tip_updated(self, header):
        if self.subscribed_to_headers:
            update = {"method": "blockchain.headers.subscribe", "params":
                [header]}
            self._send_update(update)

    def on_updated_scripthashes(self, updated_scripthashes):
        for scrhash in updated_scripthashes:
            history_hash = self.txmonitor.get_electrum_history_hash(scrhash)
            update = {"method": "blockchain.scripthash.subscribe", "params": 
                [scrhash, history_hash]}
            self._send_update(update)

    def on_disconnect(self):
        self.subscribed_to_headers = False
        self.txmonitor.unsubscribe_all_addresses()

    def _send_response(self, query, result):
        response = {"jsonrpc": "2.0", "result": result, "id": query["id"]}
        self.send_reply_fun(response)

    def _send_update(self, update):
        update["jsonrpc"] = "2.0"
        self.send_reply_fun(update)

    def _send_error(self, nid, error):
        payload = {"error": error, "jsonrpc": "2.0", "id": nid}
        self.send_reply_fun(payload)

    def handle_query(self, query):
        if "method" not in query:
            raise IOError("Bad client query, no \"method\"")
        method = query["method"]

        if method == "blockchain.transaction.get":
            txid = query["params"][0]
            tx = None
            try:
                tx = self.rpc.call("gettransaction", [txid])["hex"]
            except JsonRpcError:
                if txid in self.txid_blockhash_map:
                    tx = self.rpc.call("getrawtransaction", [txid, False,
                        self.txid_blockhash_map[txid]])
            if tx is not None:
                self._send_response(query, tx)
            else:
                self._send_error(query["id"], {"message": "txid not found"})
        elif method == "blockchain.transaction.get_merkle":
            txid = query["params"][0]
            try:
                tx = self.rpc.call("gettransaction", [txid])
                txheader = get_block_header(self.rpc, tx["blockhash"], False)
            except JsonRpcError as e:
                self._send_error(query["id"], {"message": "txid not found"})
            else:
                try:
                    core_proof = self.rpc.call("gettxoutproof", [[txid],
                        tx["blockhash"]])
                    electrum_proof = \
                        convert_core_to_electrum_merkle_proof(core_proof)
                    implied_merkle_root = hash_merkle_root(
                        electrum_proof["merkle"], txid, electrum_proof["pos"])
                    if implied_merkle_root != electrum_proof["merkleroot"]:
                        raise ValueError
                    reply = {"block_height": txheader["block_height"], "pos":
                        electrum_proof["pos"], "merkle":
                        electrum_proof["merkle"]}
                except (ValueError, JsonRpcError) as e:
                    self.logger.info("merkle proof not found for " + txid
                        + " sending a dummy, Electrum client should be run "
                        + "with --skipmerklecheck")
                    #reply with a proof that the client with accept if
                    # its configured to not check the merkle proof
                    reply = {"block_height": txheader["block_height"], "pos": 0,
                        "merkle": [txid]}
                self._send_response(query, reply)
        elif method == "blockchain.scripthash.subscribe":
            scrhash = query["params"][0]
            if self.txmonitor.subscribe_address(scrhash):
                history_hash = self.txmonitor.get_electrum_history_hash(scrhash)
            else:
                self.logger.warning("Address not known to server, hash(address)"
                    + " = " + scrhash + ".\nCheck that you've imported the "
                    + "master public key(s) correctly. The first three "
                    + "addresses of each key are printed out on startup,\nso "
                    + "check that they really are addresses you expect. In "
                    + "Electrum go to Wallet -> Information to get the right "
                    + "master public key.")
                raise UnknownScripthashError(scrhash)
            self._send_response(query, history_hash)
        elif method == "blockchain.scripthash.get_history":
            scrhash = query["params"][0]
            history = self.txmonitor.get_electrum_history(scrhash)
            if history == None:
                self.logger.warning("Address history not known to server, "
                    + "hash(address) = " + scrhash)
                raise UnknownScripthashError(scrhash)
            self._send_response(query, history)
        elif method == "blockchain.scripthash.get_balance":
            scrhash = query["params"][0]
            balance = self.txmonitor.get_address_balance(scrhash)
            if balance == None:
                self.logger.warning("Address history not known to server, "
                    + "hash(address) = " + scrhash)
                raise UnknownScripthashError(scrhash)
            self._send_response(query, balance)
        elif method == "server.ping":
            self._send_response(query, None)
        elif method == "blockchain.headers.subscribe":
            if self.protocol_version in (1.2, 1.3):
                if len(query["params"]) > 0:
                    self.are_headers_raw = query["params"][0]
                else:
                    self.are_headers_raw = (False if self.protocol_version ==
                        1.2 else True)
            elif self.protocol_version == 1.4:
                self.are_headers_raw = True
            self.logger.debug("are_headers_raw = " + str(self.are_headers_raw))
            self.subscribed_to_headers = True
            new_bestblockhash, header = get_current_header(self.rpc,
                self.are_headers_raw)
            self._send_response(query, header)
        elif method == "blockchain.block.get_header":
            height = query["params"][0]
            try:
                blockhash = self.rpc.call("getblockhash", [height])
                #this deprecated method (as of 1.3) can only
                # return non-raw headers
                header = get_block_header(self.rpc, blockhash, False)
                self._send_response(query, header)
            except JsonRpcError:
                error = {"message": "height " + str(height) + " out of range",
                    "code": -1}
                self._send_error(query["id"], error)
        elif method == "blockchain.block.header":
            height = query["params"][0]
            try:
                blockhash = self.rpc.call("getblockhash", [height])
                header = get_block_header(self.rpc, blockhash, True)
                self._send_response(query, header["hex"])
            except JsonRpcError:
                error = {"message": "height " + str(height) + " out of range",
                    "code": -1}
                self._send_error(query["id"], error)
        elif method == "blockchain.block.headers":
            MAX_CHUNK_SIZE = 2016
            start_height = query["params"][0]
            count = query["params"][1]
            count = min(count, MAX_CHUNK_SIZE)
            headers_hex, n = get_block_headers_hex(self.rpc, start_height,
                count)
            self._send_response(query, {'hex': headers_hex, 'count': n, 'max':
                MAX_CHUNK_SIZE})
        elif method == "blockchain.block.get_chunk":
            RETARGET_INTERVAL = 2016
            index = query["params"][0]
            tip_height = self.rpc.call("getblockchaininfo", [])["headers"]
            #logic copied from electrumx get_chunk() in controller.py
            next_height = tip_height + 1
            start_height = min(index*RETARGET_INTERVAL, next_height)
            count = min(next_height - start_height, RETARGET_INTERVAL)
            headers_hex, n = get_block_headers_hex(self.rpc, start_height,
                count)
            self._send_response(query, headers_hex)
        elif method == "blockchain.transaction.broadcast":
            txhex = query["params"][0]
            result = None
            error = None
            txreport = self.rpc.call("testmempoolaccept", [[txhex]])[0]
            if not txreport["allowed"]:
                error = txreport["reject-reason"]
            else:
                result = txreport["txid"]
                broadcast_method = self.broadcast_method
                self.logger.info('Broadcasting tx ' + txreport["txid"]
                    + " with broadcast method: " + broadcast_method)
                if broadcast_method == "tor-or-own-node":
                    tor_hostport = get_tor_hostport()
                    if tor_hostport is not None:
                        self.logger.info("Tor detected at " + str(tor_hostport)
                            + ". Broadcasting through tor.")
                        broadcast_method = "tor"
                        self.tor_hostport = tor_hostport
                    else:
                        self.logger.info("Could not detect tor. Broadcasting "
                            + "through own node.")
                        broadcast_method = "own-node"
                if broadcast_method == "own-node":
                    if not self.rpc.call("getnetworkinfo", [])["localrelay"]:
                        error = "Broadcast disabled when using blocksonly"
                        result = None
                        self.logger.warning("Transaction broadcasting disabled"
                            + " when blocksonly")
                    else:
                        try:
                            self.rpc.call("sendrawtransaction", [txhex])
                        except JsonRpcError as e:
                            self.logger.error("Error broadcasting: " + repr(e))
                elif broadcast_method == "tor":
                    network = "mainnet"
                    chaininfo = self.rpc.call("getblockchaininfo", [])
                    if chaininfo["chain"] == "test":
                        network = "testnet"
                    elif chaininfo["chain"] == "regtest":
                        network = "regtest"
                    self.logger.debug("broadcasting to network: " + network)
                    tor_broadcast_tx(txhex, self.tor_hostport, network,
                        self.rpc, self.logger)
                elif broadcast_method.startswith("system "):
                    with tempfile.NamedTemporaryFile() as fd:
                        system_line = broadcast_method[7:].replace("%s",
                            fd.name)
                        fd.write(txhex.encode())
                        fd.flush()
                        self.logger.debug("running command: " + system_line)
                        os.system(system_line)
                else:
                    self.logger.error("Unrecognized broadcast method = "
                        + broadcast_method)
                    result = None
                    error = "Unrecognized broadcast method"
            if result != None:
                self._send_response(query, result)
            else:
                self._send_error(query["id"], error)
        elif method == "mempool.get_fee_histogram":
            if self.disable_mempool_fee_histogram:
                result = [[0, 0]]
                self.logger.debug("fee histogram disabled, sending back empty "
                    + "mempool")
            else:
                st = time.time()
                mempool = self.rpc.call("getrawmempool", [True])
                et = time.time()
                MEMPOOL_WARNING_DURATION = 10 #seconds
                if et - st > MEMPOOL_WARNING_DURATION:
                    if not self.printed_slow_mempool_warning:
                        self.logger.warning("Mempool very large resulting in"
                            + " slow response by server ("
                            + str(round(et-st, 1)) + "sec). Consider setting "
                            + "`disable_mempool_fee_histogram = true`")
                    self.printed_slow_mempool_warning = True
                #algorithm copied from the relevant place in ElectrumX
                #https://github.com/kyuupichan/electrumx/blob/e92c9bd4861c1e35989ad2773d33e01219d33280/server/mempool.py
                fee_hist = defaultdict(int)
                for txid, details in mempool.items():
                    size = (details["size"] if "size" in details else
                        details["vsize"])
                    fee_rate = 1e8*details["fee"] // size
                    fee_hist[fee_rate] += size
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
            self._send_response(query, result)
        elif method == "blockchain.estimatefee":
            estimate = self.rpc.call("estimatesmartfee", [query["params"][0]])
            feerate = 0.0001
            if "feerate" in estimate:
                feerate = estimate["feerate"]
            self._send_response(query, feerate)
        elif method == "blockchain.relayfee":
            networkinfo = self.rpc.call("getnetworkinfo", [])
            self._send_response(query, networkinfo["relayfee"])
        elif method == "server.banner":
            networkinfo = self.rpc.call("getnetworkinfo", [])
            blockchaininfo = self.rpc.call("getblockchaininfo", [])
            uptime = self.rpc.call("uptime", [])
            nettotals = self.rpc.call("getnettotals", [])
            uptime_days = uptime / 60.0 / 60 / 24
            first_unpruned_block_text = ""
            if blockchaininfo["pruned"]:
                first_unpruned_block_time = self.rpc.call("getblockheader", [
                    self.rpc.call("getblockhash", [blockchaininfo[
                    "pruneheight"]])])["time"]
                first_unpruned_block_text = ("First unpruned block: "
                    + str(blockchaininfo["pruneheight"]) + " ("
                    + str(
                    datetime.datetime.fromtimestamp(first_unpruned_block_time))
                    + ")\n")
            self._send_response(query, BANNER.format(
                serverversion=SERVER_VERSION_NUMBER,
                detwallets=len(self.txmonitor.deterministic_wallets),
                addr=len(self.txmonitor.address_history),
                useragent=networkinfo["subversion"],
                uptime=str(datetime.timedelta(seconds=uptime)),
                peers=networkinfo["connections"],
                recvbytes=bytes_fmt(nettotals["totalbytesrecv"]),
                recvbytesperday=bytes_fmt(
                    nettotals["totalbytesrecv"]/uptime_days),
                sentbytes=bytes_fmt(nettotals["totalbytessent"]),
                sentbytesperday=bytes_fmt(
                    nettotals["totalbytessent"]/uptime_days),
                blocksonly=not networkinfo["localrelay"],
                pruning=blockchaininfo["pruned"],
                blockchainsizeondisk=bytes_fmt(
                    blockchaininfo["size_on_disk"]),
                firstunprunedblock=first_unpruned_block_text,
                donationaddr=DONATION_ADDR))
        elif method == "server.donation_address":
            self._send_response(query, DONATION_ADDR)
        elif method == "server.version":
            client_protocol_version = query["params"][1]
            if isinstance(client_protocol_version, list):
                client_min, client_max = float(client_min)
            else:
                client_min = float(query["params"][1])
                client_max = client_min
            self.protocol_version = min(client_max, SERVER_PROTOCOL_VERSION_MAX)
            if self.protocol_version < max(client_min,
                    SERVER_PROTOCOL_VERSION_MIN):
                logging.error("*** Client protocol version " + str(
                    client_protocol_version) + " not supported, update needed")
                raise ConnectionRefusedError()
            self._send_response(query, ["ElectrumPersonalServer "
                + SERVER_VERSION_NUMBER, str(self.protocol_version)])
        elif method == "server.peers.subscribe":
            self._send_response(query, []) #no peers to report
        elif method == "blockchain.transaction.id_from_pos":
            height = query["params"][0]
            tx_pos = query["params"][1]
            merkle = False
            if len(query["params"]) > 2:
                merkle = query["params"][2]
            try:
                blockhash = self.rpc.call("getblockhash", [height])
                block = self.rpc.call("getblock", [blockhash, 1])
                txid = block["tx"][tx_pos]
                self.txid_blockhash_map[txid] = blockhash
                if not merkle:
                    result = txid
                else:
                    core_proof = self.rpc.call("gettxoutproof", [[txid],
                        blockhash])
                    electrum_proof =\
                        convert_core_to_electrum_merkle_proof(core_proof)
                    result = {"tx_hash": txid, "merkle": electrum_proof[
                        "merkle"]}
                self._send_response(query, result)
            except JsonRpcError as e:
                error = {"message": repr(e)}
                self._send_error(query["id"], error)
        else:
            self.logger.error("*** BUG! Not handling method: " + method
                + " query=" + str(query))

