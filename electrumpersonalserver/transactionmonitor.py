
import time, pprint, math, sys
from decimal import Decimal

from electrumpersonalserver.jsonrpc import JsonRpcError
import electrumpersonalserver.hashes as hashes

#internally this code uses scriptPubKeys, it only converts to bitcoin addresses
# when importing to bitcoind or checking whether enough addresses have been
# imported
#the electrum protocol uses sha256(scriptpubkey) as a key for lookups
# this code calls them scripthashes

#code will generate the first address from each deterministic wallet
# and check whether they have been imported into the bitcoin node
# if no then initial_import_count addresses will be imported, then exit
# if yes then initial_import_count addresses will be generated and extra
# addresses will be generated one-by-one, each time checking whether they have
# been imported into the bitcoin node
# when an address has been reached that has not been imported, that means
# we've reached the end, then rewind the deterministic wallet index by one

#when a transaction happens paying to an address from a deterministic wallet
# lookup the position of that address, if its less than gap_limit then
# import more addresses

ADDRESSES_LABEL = "electrum-watchonly-addresses"

def import_addresses(rpc, addrs, debug, log):
    debug("importing addrs = " + str(addrs))
    log("Importing " + str(len(addrs)) + " addresses in total")
    addr_i = iter(addrs)
    notifications = 10
    for i in range(notifications):
        pc = int(100.0 * i / notifications)
        sys.stdout.write("[" + str(pc) + "%]... ")
        sys.stdout.flush()
        for j in range(int(len(addrs) / notifications)):
            rpc.call("importaddress", [next(addr_i), ADDRESSES_LABEL, False])
    for a in addr_i: #import the reminder of addresses
        rpc.call("importaddress", [a, ADDRESSES_LABEL, False])
    print("[100%]")
    log("Importing done")

class TransactionMonitor(object):
    """
    Class which monitors the bitcoind wallet for new transactions
    and builds a history datastructure for sending to electrum
    """
    def __init__(self, rpc, deterministic_wallets, debug, log):
        self.rpc = rpc
        self.deterministic_wallets = deterministic_wallets
        self.debug = debug
        self.log = log
        self.last_known_wallet_txid = None
        self.address_history = None
        self.unconfirmed_txes = None

    def get_electrum_history_hash(self, scrhash):
        return hashes.get_status_electrum( ((h["tx_hash"], h["height"])
            for h in self.address_history[scrhash]["history"]) )

    def get_electrum_history(self, scrhash):
        if scrhash in self.address_history:
            return self.address_history[scrhash]["history"]
        else:
            return None

    def subscribe_address(self, scrhash):
        if scrhash in self.address_history:
            self.address_history[scrhash]["subscribed"] = True
            return True
        else:
            return False

    def unsubscribe_all_addresses(self):
        for scrhash, his in self.address_history.items():
            his["subscribed"] = False

    def build_address_history(self, monitored_scriptpubkeys):
        self.log("Building history with " + str(len(monitored_scriptpubkeys)) +
            " addresses")
        st = time.time()
        address_history = {}
        for spk in monitored_scriptpubkeys:
            address_history[hashes.script_to_scripthash(spk)] = {'history': [],
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
            ret = self.rpc.call("listtransactions", ["*", BATCH_SIZE, t, True])
            self.debug("listtransactions skip=" + str(t) + " len(ret)="
                + str(len(ret)))
            t += len(ret)
            for tx in ret:
                if "txid" not in tx or "category" not in tx:
                    continue
                if tx["category"] not in ("receive", "send"):
                    continue
                if tx["confirmations"] == -1:
                    continue #conflicted
                if tx["txid"] in obtained_txids:
                    continue
                self.debug("adding obtained tx=" + str(tx["txid"]))
                obtained_txids.add(tx["txid"])

                #obtain all the addresses this transaction is involved with
                output_scriptpubkeys, input_scriptpubkeys, txd = \
                    self.get_input_and_output_scriptpubkeys(tx["txid"])
                output_scripthashes = [hashes.script_to_scripthash(sc)
                    for sc in output_scriptpubkeys]
                sh_to_add = wallet_addr_scripthashes.intersection(set(
                    output_scripthashes))
                input_scripthashes = [hashes.script_to_scripthash(sc)
                    for sc in input_scriptpubkeys]
                sh_to_add |= wallet_addr_scripthashes.intersection(set(
                    input_scripthashes))
                if len(sh_to_add) == 0:
                    continue

                for wal in self.deterministic_wallets:
                    overrun_depths = wal.have_scriptpubkeys_overrun_gaplimit(
                        output_scriptpubkeys)
                    if overrun_depths != None:
                        self.log("ERROR: Not enough addresses imported.")
                        self.log("Delete wallet.dat and increase the value " +
                            "of `initial_import_count` in the file " + 
                            "`config.cfg` then reimport and rescan")
                        #TODO make it so users dont have to delete wallet.dat
                        # check whether all initial_import_count addresses are
                        # imported rather than just the first one
                        return False
                new_history_element = self.generate_new_history_element(tx, txd)
                for scripthash in sh_to_add:
                    address_history[scripthash][
                        "history"].append(new_history_element)
                count += 1

        unconfirmed_txes = {}
        for scrhash, his in address_history.items():
            uctx = self.sort_address_history_list(his)
            for u in uctx:
                if u["tx_hash"] in unconfirmed_txes:
                    unconfirmed_txes[u["tx_hash"]].append(scrhash)
                else:
                    unconfirmed_txes[u["tx_hash"]] = [scrhash]
        self.debug("unconfirmed_txes = " + str(unconfirmed_txes))
        if len(ret) > 0:
            #txid doesnt uniquely identify transactions from listtransactions
            #but the tuple (txid, address) does
            self.last_known_wallet_txid = (ret[-1]["txid"], ret[-1]["address"])
        else:
            self.last_known_wallet_txid = None
        self.debug("last_known_wallet_txid = " + str(
            self.last_known_wallet_txid))

        et = time.time()
        self.debug("address_history =\n" + pprint.pformat(address_history))
        self.log("Found " + str(count) + " txes. History built in " +
            str(et - st) + "sec")
        self.address_history = address_history
        self.unconfirmed_txes = unconfirmed_txes
        return True

    def get_input_and_output_scriptpubkeys(self, txid):
        gettx = self.rpc.call("gettransaction", [txid])
        txd = self.rpc.call("decoderawtransaction", [gettx["hex"]])
        output_scriptpubkeys = [out["scriptPubKey"]["hex"]
            for out in txd["vout"]]
        input_scriptpubkeys = []
        for inn in txd["vin"]:
            try:
                wallet_tx = self.rpc.call("gettransaction", [inn["txid"]])
            except JsonRpcError:
                #wallet doesnt know about this tx, so the input isnt ours
                continue
            input_decoded = self.rpc.call("decoderawtransaction", [wallet_tx[
                "hex"]])
            script = input_decoded["vout"][inn["vout"]]["scriptPubKey"]["hex"]
            input_scriptpubkeys.append(script)
        return output_scriptpubkeys, input_scriptpubkeys, txd

    def generate_new_history_element(self, tx, txd):
        if tx["confirmations"] == 0:
            unconfirmed_input = False
            total_input_value = 0
            for inn in txd["vin"]:
                utxo = self.rpc.call("gettxout", [inn["txid"], inn["vout"],
                    True])
                if utxo is None:
                    utxo = self.rpc.call("gettxout", [inn["txid"], inn["vout"],
                        False])
                    if utxo is None:
                        self.debug("utxo not found(!)")
                        #TODO detect this and figure out how to tell
                        # electrum that we dont know the fee
                total_input_value += int(Decimal(utxo["value"]) * Decimal(1e8))
                unconfirmed_input = (unconfirmed_input or
                    utxo["confirmations"] == 0)
            self.debug("total_input_value = " + str(total_input_value))

            fee = total_input_value - sum([int(Decimal(out["value"])
                * Decimal(1e8)) for out in txd["vout"]])
            height = -1 if unconfirmed_input else 0
            new_history_element = ({"tx_hash": tx["txid"], "height": height,
                "fee": fee})
        else:
            blockheader = self.rpc.call("getblockheader", [tx['blockhash']])
            new_history_element = ({"tx_hash": tx["txid"],
                "height": blockheader["height"]})
        return new_history_element

    def sort_address_history_list(self, his):
        unconfirm_txes = list(filter(lambda h:h["height"] == 0, his["history"]))
        confirm_txes = filter(lambda h:h["height"] != 0, his["history"])
        #TODO txes must be "in blockchain order"
        # the order they appear in the block
        # it might be "blockindex" in listtransactions and gettransaction
        #so must sort with key height+':'+blockindex
        #maybe check if any heights are the same then get the pos only for those
        #better way to do this is to have a separate dict that isnt in history
        # which maps txid => blockindex
        # and then sort by key height+":"+idx[txid]
        his["history"] = sorted(confirm_txes, key=lambda h:h["height"])
        his["history"].extend(unconfirm_txes)
        return unconfirm_txes

    def check_for_updated_txes(self):
        updated_scrhashes1 = self.check_for_new_txes()
        updated_scrhashes2 = self.check_for_confirmations()
        updated_scrhashes = updated_scrhashes1 | updated_scrhashes2
        for ush in updated_scrhashes:
            his = self.address_history[ush]
            self.sort_address_history_list(his)
        if len(updated_scrhashes) > 0:
            self.debug("new tx address_history =\n"
                + pprint.pformat(self.address_history))
            self.debug("unconfirmed txes = " +
                pprint.pformat(self.unconfirmed_txes))
            self.debug("updated_scripthashes = " + str(updated_scrhashes))
        updated_scrhashes = filter(lambda sh:self.address_history[sh][
            "subscribed"], updated_scrhashes)
        return updated_scrhashes

    def check_for_confirmations(self):
        tx_scrhashes_removed_from_mempool = []
        self.debug("check4con unconfirmed_txes = "
            + pprint.pformat(self.unconfirmed_txes))
        for uc_txid, scrhashes in self.unconfirmed_txes.items():
            tx = self.rpc.call("gettransaction", [uc_txid])
            self.debug("uc_txid=" + uc_txid + " => " + str(tx))
            if tx["confirmations"] == 0:
                continue #still unconfirmed
            tx_scrhashes_removed_from_mempool.append((uc_txid, scrhashes))
            if tx["confirmations"] > 0:
                self.log("A transaction confirmed: " + uc_txid)
                block = self.rpc.call("getblockheader", [tx["blockhash"]])
            elif tx["confirmations"] == -1:
                self.log("A transaction became conflicted: " + uc_txid)
            for scrhash in scrhashes:
                #delete the old unconfirmed entry in address_history
                deleted_entries = [h for h in self.address_history[scrhash][
                    "history"] if h["tx_hash"] == uc_txid]
                for d_his in deleted_entries:
                    self.address_history[scrhash]["history"].remove(d_his)
                if tx["confirmations"] > 0:
                    #create the new confirmed entry in address_history
                    self.address_history[scrhash]["history"].append({"height":
                        block["height"], "tx_hash": uc_txid})
        updated_scrhashes = set()
        for tx, scrhashes in tx_scrhashes_removed_from_mempool:
            del self.unconfirmed_txes[tx]
            updated_scrhashes.update(set(scrhashes))
        return updated_scrhashes

    def check_for_new_txes(self):
        MAX_TX_REQUEST_COUNT = 256 
        tx_request_count = 2
        max_attempts = int(math.log(MAX_TX_REQUEST_COUNT, 2))
        for i in range(max_attempts):
            self.debug("listtransactions tx_request_count="
                + str(tx_request_count))
            ret = self.rpc.call("listtransactions", ["*", tx_request_count, 0,
                True])
            ret = ret[::-1]
            if self.last_known_wallet_txid == None:
                recent_tx_index = len(ret) #=0 means no new txes
                break
            else:
                txid_list = [(tx["txid"], tx["address"]) for tx in ret]
                recent_tx_index = next((i for i, (txid, addr)
                    in enumerate(txid_list) if
                    txid == self.last_known_wallet_txid[0] and
                    addr == self.last_known_wallet_txid[1]), -1)
                if recent_tx_index != -1:
                    break
                tx_request_count *= 2

        #TODO low priority: handle a user getting more than 255 new
        # transactions in 15 seconds
        self.debug("recent tx index = " + str(recent_tx_index) + " ret = " +
            str([(t["txid"], t["address"]) for t in ret]))
        if len(ret) > 0:
            self.last_known_wallet_txid = (ret[0]["txid"], ret[0]["address"])
            self.debug("last_known_wallet_txid = " + str(
                self.last_known_wallet_txid))
        assert(recent_tx_index != -1)
        if recent_tx_index == 0:
            return set()
        new_txes = ret[:recent_tx_index][::-1]
        self.debug("new txes = " + str(new_txes))
        obtained_txids = set()
        updated_scripthashes = []
        for tx in new_txes:
            if "txid" not in tx or "category" not in tx:
                continue
            if tx["category"] not in ("receive", "send"):
                continue
            if tx["confirmations"] == -1:
                continue #conflicted
            if tx["txid"] in obtained_txids:
                continue
            obtained_txids.add(tx["txid"])
            output_scriptpubkeys, input_scriptpubkeys, txd = \
                self.get_input_and_output_scriptpubkeys(tx["txid"])
            matching_scripthashes = []
            for spk in (output_scriptpubkeys + input_scriptpubkeys):
                scripthash = hashes.script_to_scripthash(spk)
                if scripthash in self.address_history:
                    matching_scripthashes.append(scripthash)
            if len(matching_scripthashes) == 0:
                continue

            for wal in self.deterministic_wallets:
                overrun_depths = wal.have_scriptpubkeys_overrun_gaplimit(
                    output_scriptpubkeys)
                if overrun_depths != None:
                    for change, import_count in overrun_depths.items():
                        spks = wal.get_new_scriptpubkeys(change, import_count)
                        for spk in spks:
                            self.address_history[hashes.script_to_scripthash(
                                spk)] =  {'history': [], 'subscribed': False}
                        new_addrs = [hashes.script_to_address(s, self.rpc)
                            for s in spks]
                        self.debug("importing " + str(len(spks)) +
                            " into change=" + str(change))
                        import_addresses(self.rpc, new_addrs, self.debug,
                            self.log)

            updated_scripthashes.extend(matching_scripthashes)
            new_history_element = self.generate_new_history_element(tx, txd)
            self.log("Found new tx: " + str(new_history_element))
            for scrhash in matching_scripthashes:
                self.address_history[scrhash]["history"].append(
                    new_history_element)
                if new_history_element["height"] == 0:
                    if tx["txid"] in self.unconfirmed_txes:
                        self.unconfirmed_txes[tx["txid"]].append(scrhash)
                    else:
                        self.unconfirmed_txes[tx["txid"]] = [scrhash]
            #check whether gap limits have been overrun and import more addrs
        return set(updated_scripthashes)


## start tests here

class TestJsonRpc(object):
    def __init__(self, txlist, utxoset, block_heights):
        self.txlist = txlist
        self.utxoset = utxoset
        self.block_heights = block_heights
        self.imported_addresses = []

    def call(self, method, params):
        if method == "listtransactions":
            count = int(params[1])
            skip = int(params[2])
            return self.txlist[skip:skip + count]
        elif method == "gettransaction":
            for t in self.txlist:
                if t["txid"] == params[0]:
                    return t
            raise JsonRpcError({"code": None, "message": None})
        elif method == "decoderawtransaction":
            for t in self.txlist:
                if t["hex"] == params[0]:
                    return t
            assert 0
        elif method == "gettxout":
            for u in self.utxoset:
                if u["txid"] == params[0] and u["vout"] == params[1]:
                    return u
            assert 0
        elif method == "getblockheader":
            if params[0] not in self.block_heights:
                assert 0
            return {"height": self.block_heights[params[0]]}
        elif method == "decodescript":
            return {"addresses": [test_spk_to_address(params[0])]}
        elif method == "importaddress":
            self.imported_addresses.append(params[0])
        else:
            raise ValueError("unknown method in test jsonrpc")

    def add_transaction(self, tx):
        self.txlist.append(tx)

    def get_imported_addresses(self):
        return self.imported_addresses

from electrumpersonalserver.deterministicwallet import DeterministicWallet

class TestDeterministicWallet(DeterministicWallet):
    """Empty deterministic wallets"""
    def __init__(self):
        pass

    def have_scriptpubkeys_overrun_gaplimit(self, scriptpubkeys):
        return None #not overrun

    def get_new_scriptpubkeys(self, change, count):
        pass

def test_spk_to_address(spk):
    return spk + "-address"

def assert_address_history_tx(address_history, spk, height, txid, subscribed):
    history_element = address_history[hashes.script_to_scripthash(spk)]
    assert history_element["history"][0]["height"] == height
    assert history_element["history"][0]["tx_hash"] == txid
    #fee always zero, its easier to test because otherwise you have
    # to use Decimal to stop float weirdness
    if height == 0:
        assert history_element["history"][0]["fee"] == 0
    assert history_element["subscribed"] == subscribed

def test():
    #debugf = lambda x: print("[DEBUG] " + x)
    #logf = lambda x: print("[  LOG] " + x)
    debugf = lambda x: x
    logf = debugf

    #empty deterministic wallets
    deterministic_wallets = [TestDeterministicWallet()]
    test_spk1 = "deadbeefdeadbeefdeadbeefdeadbeef"
    test_containing_block1 = "blockhash-placeholder1"
    test_paying_in_tx1 = {
        "txid": "placeholder-test-txid1",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk1}}],
        "address": test_spk_to_address(test_spk1),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block1,
        "hex": "placeholder-test-txhex1"
    }
    test_spk2 = "deadbeefdeadbeefdeadbeef"
    test_containing_block2 = "blockhash-placeholder2"
    test_paying_in_tx2 = {
        "txid": "placeholder-test-txid2",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk2}}],
        "address": test_spk_to_address(test_spk2),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block2,
        "hex": "placeholder-test-txhex2"
    }

    ###single confirmed tx in wallet belonging to us, address history built
    rpc = TestJsonRpc([test_paying_in_tx1], [],
        {test_containing_block1: 420000})
    txmonitor1 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor1.build_address_history([test_spk1])
    assert len(txmonitor1.address_history) == 1
    assert_address_history_tx(txmonitor1.address_history, spk=test_spk1,
        height=420000, txid=test_paying_in_tx1["txid"], subscribed=False)

    ###two confirmed txes in wallet belonging to us, addr history built
    rpc = TestJsonRpc([test_paying_in_tx1, test_paying_in_tx2], [],
        {test_containing_block1: 1, test_containing_block2: 2})
    deterministic_wallets = [TestDeterministicWallet()]
    txmonitor2 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor2.build_address_history([test_spk1, test_spk2])
    assert len(txmonitor2.address_history) == 2
    assert_address_history_tx(txmonitor2.address_history, spk=test_spk1,
        height=1, txid=test_paying_in_tx1["txid"], subscribed=False)
    assert_address_history_tx(txmonitor2.address_history, spk=test_spk2,
        height=2, txid=test_paying_in_tx2["txid"], subscribed=False)

    ###one unconfirmed tx in wallet belonging to us, with confirmed inputs,
    ### addr history built, then tx confirms, not subscribed to address
    test_spk3 = "deadbeefdeadbeef"
    test_containing_block3 = "blockhash-placeholder3"
    input_utxo3 = {"txid": "placeholder-unknown-input-txid", "vout": 0,
        "value": 1, "confirmations": 1}
    test_paying_in_tx3 = {
        "txid": "placeholder-test-txid3",
        "vin": [input_utxo3],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk3}}],
        "address": test_spk_to_address(test_spk3),
        "category": "receive",
        "confirmations": 0,
        "blockhash": test_containing_block3,
        "hex": "placeholder-test-txhex3"
    }
    rpc = TestJsonRpc([test_paying_in_tx3], [input_utxo3],
        {test_containing_block3: 10})
    txmonitor3 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor3.build_address_history([test_spk3])
    assert len(txmonitor3.address_history) == 1
    assert_address_history_tx(txmonitor3.address_history, spk=test_spk3,
        height=0, txid=test_paying_in_tx3["txid"], subscribed=False)
    assert len(list(txmonitor3.check_for_updated_txes())) == 0
    test_paying_in_tx3["confirmations"] = 1 #tx confirms
    #not subscribed so still only returns an empty list
    assert len(list(txmonitor3.check_for_updated_txes())) == 0
    assert_address_history_tx(txmonitor3.address_history, spk=test_spk3,
        height=10, txid=test_paying_in_tx3["txid"], subscribed=False)

    ###build empty address history, subscribe one address
    ### an unconfirmed tx appears, then confirms
    test_spk4 = "deadbeefdeadbeefaa"
    test_containing_block4 = "blockhash-placeholder4"
    input_utxo4 = {"txid": "placeholder-unknown-input-txid", "vout": 0,
        "value": 1, "confirmations": 1}
    test_paying_in_tx4 = {
        "txid": "placeholder-test-txid4",
        "vin": [input_utxo4],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk4}}],
        "address": test_spk_to_address(test_spk4),
        "category": "receive",
        "confirmations": 0,
        "blockhash": test_containing_block4,
        "hex": "placeholder-test-txhex4"
    }
    rpc = TestJsonRpc([], [input_utxo4], {test_containing_block4: 10})
    txmonitor4 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor4.build_address_history([test_spk4])
    assert len(txmonitor4.address_history) == 1
    sh4 = hashes.script_to_scripthash(test_spk4)
    assert len(txmonitor4.get_electrum_history(sh4)) == 0
    txmonitor4.subscribe_address(sh4)
    # unconfirm transaction appears
    assert len(list(txmonitor4.check_for_updated_txes())) == 0
    rpc.add_transaction(test_paying_in_tx4)
    assert len(list(txmonitor4.check_for_updated_txes())) == 1
    assert_address_history_tx(txmonitor4.address_history, spk=test_spk4,
        height=0, txid=test_paying_in_tx4["txid"], subscribed=True)
    # transaction confirms
    test_paying_in_tx4["confirmations"] = 1
    assert len(list(txmonitor4.check_for_updated_txes())) == 1
    assert_address_history_tx(txmonitor4.address_history, spk=test_spk4,
        height=10, txid=test_paying_in_tx4["txid"], subscribed=True)

    ###transaction that has nothing to do with our wallet
    test_spk5 = "deadbeefdeadbeefbb"
    test_containing_block5 = "blockhash-placeholder5"
    test_paying_in_tx5 = {
        "txid": "placeholder-test-txid5",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk5}}],
        "address": test_spk_to_address(test_spk5),
        "category": "receive",
        "confirmations": 0,
        "blockhash": test_containing_block5,
        "hex": "placeholder-test-txhex5"
    }
    test_spk5_1 = "deadbeefdeadbeefcc"
    rpc = TestJsonRpc([test_paying_in_tx5], [], {test_containing_block4: 10})
    txmonitor5 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor5.build_address_history([test_spk5_1])
    assert len(txmonitor5.address_history) == 1
    assert len(txmonitor5.get_electrum_history(hashes.script_to_scripthash(
        test_spk5_1))) == 0

    ###transaction which arrives to an address which already has a tx on it
    test_spk6 = "deadbeefdeadbeefdd"
    test_containing_block6 = "blockhash-placeholder6"
    test_paying_in_tx6 = {
        "txid": "placeholder-test-txid6",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk6}}],
        "address": test_spk_to_address(test_spk6),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block6,
        "hex": "placeholder-test-txhex6"
    }
    test_paying_in_tx6_1 = {
        "txid": "placeholder-test-txid6_1",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk6}}],
        "address": test_spk_to_address(test_spk6),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block6,
        "hex": "placeholder-test-txhex6"
    }
    rpc = TestJsonRpc([test_paying_in_tx6], [], {test_containing_block6: 10})
    txmonitor6 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor6.build_address_history([test_spk6])
    sh = hashes.script_to_scripthash(test_spk6)
    assert len(txmonitor6.get_electrum_history(sh)) == 1
    rpc.add_transaction(test_paying_in_tx6_1)
    assert len(txmonitor6.get_electrum_history(sh)) == 1
    txmonitor6.check_for_updated_txes()
    assert len(txmonitor6.get_electrum_history(sh)) == 2

    ###transaction spending FROM one of our addresses
    test_spk7 = "deadbeefdeadbeefee"
    test_input_containing_block7 = "blockhash-input-placeholder7"
    test_input_tx7 = {
        "txid": "placeholder-input-test-txid7",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk7}}],
        "address": test_spk_to_address(test_spk7),
        "category": "send",
        "confirmations": 2,
        "blockhash": test_input_containing_block7,
        "hex": "placeholder-input-test-txhex7"
    }
    test_containing_block7 = "blockhash-placeholder7"
    test_paying_from_tx7 = {
        "txid": "placeholder-test-txid7",
        "vin": [{"txid": test_input_tx7["txid"], "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": "deadbeef"}}],
        "address": test_spk_to_address(test_spk7),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block7,
        "hex": "placeholder-test-txhex7"
    }
    rpc = TestJsonRpc([test_input_tx7, test_paying_from_tx7], [],
        {test_containing_block7: 9, test_input_containing_block7: 8})
    txmonitor7 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor7.build_address_history([test_spk7])
    sh = hashes.script_to_scripthash(test_spk7)
    assert len(txmonitor7.get_electrum_history(sh)) == 2

    ###transaction from one address to the other, both addresses in wallet
    test_spk8 = "deadbeefdeadbeefee"
    test_spk8_1 = "deadbeefdeadbeefff"
    test_input_containing_block8 = "blockhash-input-placeholder8"
    test_input_tx8 = {
        "txid": "placeholder-input-test-txid8",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk8}}],
        "address": test_spk_to_address(test_spk8),
        "category": "send",
        "confirmations": 2,
        "blockhash": test_input_containing_block8,
        "hex": "placeholder-input-test-txhex8"
    }
    test_containing_block8 = "blockhash-placeholder8"
    test_paying_from_tx8 = {
        "txid": "placeholder-test-txid8",
        "vin": [{"txid": test_input_tx8["txid"], "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk8_1}}],
        "address": test_spk_to_address(test_spk8),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block8,
        "hex": "placeholder-test-txhex8"
    }
    rpc = TestJsonRpc([test_input_tx8, test_paying_from_tx8], [],
        {test_containing_block8: 9, test_input_containing_block8: 8})
    txmonitor8 = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitor8.build_address_history([test_spk8, test_spk8_1])
    assert len(txmonitor8.get_electrum_history(hashes.script_to_scripthash(
        test_spk8))) == 2
    assert len(txmonitor8.get_electrum_history(hashes.script_to_scripthash(
        test_spk8_1))) == 1

    ###overrun gap limit so import address is needed
    test_spk9 = "deadbeefdeadbeef00"
    test_containing_block9 = "blockhash-placeholder9"
    test_paying_in_tx9 = {
        "txid": "placeholder-test-txid9",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spk9}}],
        "address": test_spk_to_address(test_spk9),
        "category": "receive",
        "confirmations": 1,
        "blockhash": test_containing_block9,
        "hex": "placeholder-test-txhex9"
    }
    test_spk9_imported = "deadbeefdeadbeef11"
    class TestImportDeterministicWallet(DeterministicWallet):
        def __init__(self):
            pass

        def have_scriptpubkeys_overrun_gaplimit(self, scriptpubkeys):
            return {0: 1} #overrun by one

        def get_new_scriptpubkeys(self, change, count):
            return [test_spk9_imported]

    rpc = TestJsonRpc([], [], {test_containing_block9: 10})
    txmonitor9 = TransactionMonitor(rpc, [TestImportDeterministicWallet()],
        debugf, logf)
    assert txmonitor9.build_address_history([test_spk9])
    assert len(txmonitor9.address_history) == 1
    assert len(list(txmonitor9.check_for_updated_txes())) == 0
    assert len(txmonitor9.get_electrum_history(hashes.script_to_scripthash(
        test_spk9))) == 0
    rpc.add_transaction(test_paying_in_tx9)
    assert len(list(txmonitor9.check_for_updated_txes())) == 0
    assert len(txmonitor9.get_electrum_history(hashes.script_to_scripthash(
        test_spk9))) == 1
    assert len(txmonitor9.get_electrum_history(hashes.script_to_scripthash(
        test_spk9_imported))) == 0
    assert len(rpc.get_imported_addresses()) == 1
    assert rpc.get_imported_addresses()[0] == test_spk_to_address(
        test_spk9_imported)

    ###conflicted transaction in history being sync'd
    test_spkA = "deadbeefdeadbeefcccc"
    test_paying_in_txA = {
        "txid": "placeholder-test-txidA",
        "vin": [{"txid": "placeholder-unknown-input-txid", "vout": 0}],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spkA}}],
        "address": test_spk_to_address(test_spkA),
        "category": "receive",
        "confirmations": -1,
        "hex": "placeholder-test-txhexA"
    }
    rpc = TestJsonRpc([test_paying_in_txA], [], {})
    txmonitorA = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitorA.build_address_history([test_spkA])
    assert len(txmonitorA.address_history) == 1
    assert len(txmonitorA.get_electrum_history(hashes.script_to_scripthash(
        test_spkA))) == 0 #shouldnt show up after build history
    rpc.add_transaction(test_paying_in_txA)
    assert len(list(txmonitorA.check_for_updated_txes())) == 0
    assert len(txmonitorA.get_electrum_history(hashes.script_to_scripthash(
        test_spkA))) == 0 #shouldnt show up after tx is added

    ###an unconfirmed tx being broadcast, another conflicting tx being
    ### confirmed, the first tx then becomes conflicted
    test_spkB = "deadbeefdeadbeefbb"
    test_containing_blockB = "blockhash-placeholderB"
    input_utxoB = {"txid": "placeholder-unknown-input-txid", "vout": 0,
        "value": 1, "confirmations": 1}
    test_paying_in_txB = {
        "txid": "placeholder-test-txidB",
        "vin": [input_utxoB],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spkB}}],
        "address": test_spk_to_address(test_spkB),
        "category": "receive",
        "confirmations": 0,
        "blockhash": test_containing_blockB,
        "hex": "placeholder-test-txhexB"
    }
    test_paying_in_txB_2 = {
        "txid": "placeholder-test-txidB_2",
        "vin": [input_utxoB],
        "vout": [{"value": 1, "scriptPubKey": {"hex": test_spkB}}],
        "address": test_spk_to_address(test_spkB),
        "category": "receive",
        "confirmations": 0,
        "blockhash": test_containing_blockB,
        "hex": "placeholder-test-txhexB"
    }
    rpc = TestJsonRpc([test_paying_in_txB], [input_utxoB],
        {test_containing_blockB: 10})
    txmonitorB = TransactionMonitor(rpc, deterministic_wallets, debugf, logf)
    assert txmonitorB.build_address_history([test_spkB])
    assert len(txmonitorB.address_history) == 1
    shB = hashes.script_to_scripthash(test_spkB)
    assert len(txmonitorB.get_electrum_history(shB)) == 1
    assert_address_history_tx(txmonitorB.address_history, spk=test_spkB,
        height=0, txid=test_paying_in_txB["txid"], subscribed=False)
    # a conflicting transaction confirms
    rpc.add_transaction(test_paying_in_txB_2)
    test_paying_in_txB["confirmations"] = -1
    test_paying_in_txB_2["confirmations"] = 1
    assert len(list(txmonitorB.check_for_updated_txes())) == 0
    assert len(txmonitorB.get_electrum_history(shB)) == 1
    assert_address_history_tx(txmonitorB.address_history, spk=test_spkB,
        height=10, txid=test_paying_in_txB_2["txid"], subscribed=False)

    #other possible stuff to test:
    #finding confirmed and unconfirmed tx, in that order, then both confirm
    #finding unconfirmed and confirmed tx, in that order, then both confirm

    print("\nAll tests passed")

if __name__ == "__main__":
    test()

