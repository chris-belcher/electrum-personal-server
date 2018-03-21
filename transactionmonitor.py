
import time, pprint, math
from decimal import Decimal

from jsonrpc import JsonRpcError
from server import debug, log, import_addresses
import hashes

class TransactionMonitor(object):
    def __init__(self, rpc, deterministic_wallets):
        self.rpc = rpc
        self.deterministic_wallets = deterministic_wallets
        self.last_known_recent_txid = None
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
        for srchash, his in self.address_history.items():
            his["subscribed"] = False

    def build_address_history(self, monitored_scriptpubkeys):
        log("Building history with " + str(len(monitored_scriptpubkeys)) +
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
            debug("listtransactions skip=" + str(t) + " len(ret)="
                + str(len(ret)))
            t += len(ret)
            for tx in ret:
                if "txid" not in tx or "category" not in tx:
                    continue
                if tx["category"] not in ("receive", "send"):
                    continue
                if tx["txid"] in obtained_txids:
                    continue
                debug("adding obtained tx=" + str(tx["txid"]))
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
                        log("ERROR: Not enough addresses imported.")
                        log("Delete wallet.dat and increase the value " +
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
        for srchash, his in address_history.items():
            uctx = self.sort_address_history_list(his)
            for u in uctx:
                if u["tx_hash"] in unconfirmed_txes:
                    unconfirmed_txes[u["tx_hash"]].append(srchash)
                else:
                    unconfirmed_txes[u["tx_hash"]] = [srchash]
        debug("unconfirmed_txes = " + str(unconfirmed_txes))
        if len(ret) > 0:
            #txid doesnt uniquely identify transactions from listtransactions
            #but the tuple (txid, address) does
            self.last_known_recent_txid = (ret[-1]["txid"], ret[-1]["address"])
        else:
            self.last_known_recent_txid = None
        debug("last_known_recent_txid = " + str(self.last_known_recent_txid))

        et = time.time()
        log("Found " + str(count) + " txes. History built in " +
            str(et - st) + "sec")
        debug("address_history =\n" + pprint.pformat(address_history))
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
                        debug("utxo not found(!)")
                        #TODO detect this and figure out how to tell
                        # electrum that we dont know the fee
                total_input_value += int(Decimal(utxo["value"]) * Decimal(1e8))
                unconfirmed_input = (unconfirmed_input or
                    utxo["confirmations"] == 0)
            debug("total_input_value = " + str(total_input_value))

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
        updated_srchashes1 = self.check_for_new_txes()
        updated_srchashes2 = self.check_for_confirmations()
        updated_srchashes = updated_srchashes1 | updated_srchashes2
        for ush in updated_srchashes:
            his = self.address_history[ush]
            self.sort_address_history_list(his)
        if len(updated_srchashes) > 0:
            debug("new tx address_history =\n"
                + pprint.pformat(self.address_history))
            debug("unconfirmed txes = " + pprint.pformat(self.unconfirmed_txes))
            debug("updated_scripthashes = " + str(updated_srchashes))
        else:
            debug("no updated txes")
        updated_srchashes = filter(lambda sh:self.address_history[sh][
            "subscribed"], updated_srchashes)
        #TODO srchashes is misspelled, should be scrhashes
        return updated_srchashes

    def check_for_confirmations(self):
        confirmed_txes_srchashes = []
        debug("check4con unconfirmed_txes = "
            + pprint.pformat(self.unconfirmed_txes))
        for uc_txid, srchashes in self.unconfirmed_txes.items():
            tx = self.rpc.call("gettransaction", [uc_txid])
            debug("uc_txid=" + uc_txid + " => " + str(tx))
            if tx["confirmations"] == 0:
                continue #still unconfirmed
            log("A transaction confirmed: " + uc_txid)
            confirmed_txes_srchashes.append((uc_txid, srchashes))
            block = self.rpc.call("getblockheader", [tx["blockhash"]])
            for srchash in srchashes:
                #delete the old unconfirmed entry in address_history
                deleted_entries = [h for h in self.address_history[srchash][
                    "history"] if h["tx_hash"] == uc_txid]
                for d_his in deleted_entries:
                    self.address_history[srchash]["history"].remove(d_his)
                #create the new confirmed entry in address_history
                self.address_history[srchash]["history"].append({"height":
                    block["height"], "tx_hash": uc_txid})
        updated_srchashes = set()
        for tx, srchashes in confirmed_txes_srchashes:
            del self.unconfirmed_txes[tx]
            updated_srchashes.update(set(srchashes))
        return updated_srchashes

    def check_for_new_txes(self):
        MAX_TX_REQUEST_COUNT = 256 
        tx_request_count = 2
        max_attempts = int(math.log(MAX_TX_REQUEST_COUNT, 2))
        for i in range(max_attempts):
            debug("listtransactions tx_request_count=" + str(tx_request_count))
            ret = self.rpc.call("listtransactions", ["*", tx_request_count, 0,
                True])
            ret = ret[::-1]
            if self.last_known_recent_txid == None:
                recent_tx_index = len(ret) #=0 means no new txes
                break
            else:
                txid_list = [(tx["txid"], tx["address"]) for tx in ret]
                recent_tx_index = next((i for i, (txid, addr)
                    in enumerate(txid_list) if
                    txid == self.last_known_recent_txid[0] and
                    addr == self.last_known_recent_txid[1]), -1)
                if recent_tx_index != -1:
                    break
                tx_request_count *= 2

        #TODO low priority: handle a user getting more than 255 new
        # transactions in 15 seconds
        debug("recent tx index = " + str(recent_tx_index) + " ret = " +
            str(ret))
        #    str([(t["txid"], t["address"]) for t in ret]))
        if len(ret) > 0:
            self.last_known_recent_txid = (ret[0]["txid"], ret[0]["address"])
            debug("last_known_recent_txid = " + str(
                self.last_known_recent_txid))
        assert(recent_tx_index != -1)
        if recent_tx_index == 0:
            return set()
        new_txes = ret[:recent_tx_index][::-1]
        debug("new txes = " + str(new_txes))
        #tests: finding one unconfirmed tx, finding one confirmed tx
        #sending a tx that has nothing to do with our wallets
        #getting a new tx on a completely empty wallet
        #finding confirmed and unconfirmed tx, in that order, then both confirm
        #finding unconfirmed and confirmed tx, in that order, then both confirm
        #send a tx to an address which hasnt been used before
        #import two addresses, transaction from one to the other
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
                        new_addrs = [hashes.script_to_address(s, rpc)
                            for s in spks]
                        debug("Importing " + str(len(spks)) + " into change="
                            + str(change))
                        import_addresses(rpc, new_addrs)

            updated_scripthashes.extend(matching_scripthashes)
            new_history_element = self.generate_new_history_element(tx, txd)
            log("Found new tx: " + str(new_history_element))
            for srchash in matching_scripthashes:
                self.address_history[srchash]["history"].append(
                    new_history_element)
                if new_history_element["height"] == 0:
                    if tx["txid"] in self.unconfirmed_txes:
                        self.unconfirmed_txes[tx["txid"]].append(srchash)
                    else:
                        self.unconfirmed_txes[tx["txid"]] = [srchash]
            #check whether gap limits have been overrun and import more addrs
        return set(updated_scripthashes)

