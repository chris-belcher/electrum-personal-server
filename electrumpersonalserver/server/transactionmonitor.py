
import time, pprint, math, sys
from decimal import Decimal
from collections import defaultdict
import logging

from electrumpersonalserver.server.jsonrpc import JsonRpcError
from electrumpersonalserver.server.hashes import (
    get_status_electrum,
    script_to_scripthash,
    script_to_address
)

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
CONFIRMATIONS_SAFE_FROM_REORG = 100

def import_addresses(rpc, addrs, logger=None):
    logger = logger if logger else logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("importing addrs = " + str(addrs))
    logger.info("Importing " + str(len(addrs)) + " addresses in total")
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
    logger.info("Importing done")

class TransactionMonitor(object):
    """
    Class which monitors the bitcoind wallet for new transactions
    and builds a history datastructure for sending to electrum
    """
    def __init__(self, rpc, deterministic_wallets, logger=None):
        self.rpc = rpc
        self.deterministic_wallets = deterministic_wallets
        self.last_known_wallet_txid = None
        self.address_history = None
        self.unconfirmed_txes = None
        self.reorganizable_txes = None
        self.logger = logger if logger else logging.getLogger('ELECTRUMPERSONALSERVER')

    def get_electrum_history_hash(self, scrhash):
        return get_status_electrum( [(h["tx_hash"], h["height"])
            for h in self.address_history[scrhash]["history"]] )

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
        logger = self.logger
        logger.info("Building history with " + str(len(monitored_scriptpubkeys)) +
            " addresses . . .")
        st = time.time()
        address_history = {}
        for spk in monitored_scriptpubkeys:
            address_history[script_to_scripthash(spk)] = {'history': [],
                'subscribed': False}
        wallet_addr_scripthashes = set(address_history.keys())
        self.reorganizable_txes = []
        #populate history
        #which is a blockheight-ordered list of ("txhash", height)
        #unconfirmed transactions go at the end as ("txhash", 0, fee)
        # 0=unconfirmed -1=unconfirmed with unconfirmed parents

        BATCH_SIZE = 1000
        ret = list(range(BATCH_SIZE))
        t = 0
        count = 0
        obtained_txids = set()
        last_tx = None
        while len(ret) == BATCH_SIZE:
            ret = self.rpc.call("listtransactions", ["*", BATCH_SIZE, t, True])
            logger.debug("listtransactions skip=" + str(t) + " len(ret)="
                + str(len(ret)))
            if t == 0 and len(ret) > 0:
                last_tx = ret[-1]
            t += len(ret)
            for tx in ret:
                if "txid" not in tx or "category" not in tx:
                    continue
                if tx["category"] not in ("receive", "send", "generate", "immature"):
                    continue
                if tx["confirmations"] < 0:
                    continue #conflicted
                if tx["txid"] in obtained_txids:
                    continue
                logger.debug("adding obtained tx=" + str(tx["txid"]))
                obtained_txids.add(tx["txid"])

                #obtain all the addresses this transaction is involved with
                output_scriptpubkeys, input_scriptpubkeys, txd = \
                    self.get_input_and_output_scriptpubkeys(tx["txid"])
                output_scripthashes = [script_to_scripthash(sc)
                    for sc in output_scriptpubkeys]
                sh_to_add = wallet_addr_scripthashes.intersection(set(
                    output_scripthashes))
                input_scripthashes = [script_to_scripthash(sc)
                    for sc in input_scriptpubkeys]
                sh_to_add |= wallet_addr_scripthashes.intersection(set(
                    input_scripthashes))
                if len(sh_to_add) == 0:
                    continue

                for wal in self.deterministic_wallets:
                    overrun_depths = wal.have_scriptpubkeys_overrun_gaplimit(
                        output_scriptpubkeys)
                    if overrun_depths != None:
                        logger.error("Not enough addresses imported.")
                        logger.error("Delete wallet.dat and increase the value " +
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
                if tx["confirmations"] > 0 and (tx["confirmations"] <
                        CONFIRMATIONS_SAFE_FROM_REORG):
                    self.reorganizable_txes.append((tx["txid"], tx["blockhash"],
                        new_history_element["height"], sh_to_add))
                count += 1

        unconfirmed_txes = defaultdict(list)
        for scrhash, his in address_history.items():
            uctx = self.sort_address_history_list(his)
            for u in uctx:
                unconfirmed_txes[u["tx_hash"]].append(scrhash)
        logger.debug("unconfirmed_txes = " + str(unconfirmed_txes))
        logger.debug("reorganizable_txes = " + str(self.reorganizable_txes))
        if len(ret) > 0:
            #txid doesnt uniquely identify transactions from listtransactions
            #but the tuple (txid, address) does
            self.last_known_wallet_txid = (last_tx["txid"],
                last_tx.get("address", None))
        else:
            self.last_known_wallet_txid = None
        logger.debug("last_known_wallet_txid = " + str(
            self.last_known_wallet_txid))

        et = time.time()
        logger.debug("address_history =\n" + pprint.pformat(address_history))
        logger.info("Found " + str(count) + " txes. History built in "
            + str(et - st) + "sec")
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
            if "coinbase" in inn:
                break
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
        logger = self.logger
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
                        rawtx = self.rpc.call("getrawtransaction", [inn["txid"],
                            True])
                        if rawtx is not None:
                            utxo = {"confirmations": 0,
                                "value": rawtx["vout"][inn["vout"]]["value"]}
                if utxo is not None:
                    total_input_value += int(Decimal(utxo["value"]) *
                        Decimal(1e8))
                    unconfirmed_input = (unconfirmed_input or
                        utxo["confirmations"] == 0)
                else:
                    # Electrum will now display a weird negative fee
                    logger.warning("input utxo not found(!)")

            logger.debug("total_input_value = " + str(total_input_value))
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
        logger = self.logger
        updated_scrhashes1 = self.check_for_new_txes()
        updated_scrhashes2 = self.check_for_confirmations()
        updated_scrhashes3 = self.check_for_reorganizations()
        updated_scrhashes = (updated_scrhashes1 | updated_scrhashes2
            | updated_scrhashes3)
        for ush in updated_scrhashes:
            his = self.address_history[ush]
            self.sort_address_history_list(his)
        if len(updated_scrhashes) > 0:
            logger.debug("new tx address_history =\n"
                + pprint.pformat(self.address_history))
            logger.debug("unconfirmed txes = "
                + pprint.pformat(self.unconfirmed_txes))
            logger.debug("self.reorganizable_txes = "
                + pprint.pformat(self.reorganizable_txes))
            logger.debug("updated_scripthashes = " + str(updated_scrhashes))
        updated_scrhashes = filter(lambda sh:self.address_history[sh][
            "subscribed"], updated_scrhashes)
        return updated_scrhashes

    def check_for_reorganizations(self):
        logger = self.logger
        elements_removed = []
        elements_added = []
        updated_scrhashes = set()
        logger.debug("reorganizable_txes = " + str(self.reorganizable_txes))
        for reorgable_tx in self.reorganizable_txes:
            txid, blockhash, height, scrhashes = reorgable_tx
            tx = self.rpc.call("gettransaction", [txid])
            if tx["confirmations"] >= CONFIRMATIONS_SAFE_FROM_REORG:
                elements_removed.append(reorgable_tx)
                logger.debug("Transaction considered safe from reorg: " + txid)
                continue
            if tx["confirmations"] < 1:
                updated_scrhashes.update(scrhashes)
                if tx["confirmations"] == 0:
                    #transaction became unconfirmed in a reorg
                    logger.warning("A transaction was reorg'd out: " + txid)
                    elements_removed.append(reorgable_tx)
                    self.unconfirmed_txes[txid].extend(scrhashes)

                    #add to history as unconfirmed
                    txd = self.rpc.call("decoderawtransaction", [tx["hex"]])
                    new_history_element = self.generate_new_history_element(tx,
                        txd)
                    for scrhash in scrhashes:
                        self.address_history[scrhash]["history"].append(
                            new_history_element)

                elif tx["confirmations"] < 0:
                    #tx became conflicted in reorg i.e. a double spend
                    logger.error("A transaction was double spent! " + txid)
                    elements_removed.append(reorgable_tx)
            elif tx["blockhash"] != blockhash:
                block = self.rpc.call("getblockheader", [tx["blockhash"]])
                if block["height"] == height: #reorg but height is the same
                    logger.warning("A transaction was reorg'd but still confirmed " +
                        "at same height: " + txid)
                    continue
                #reorged but still confirmed at a different height
                updated_scrhashes.update(scrhashes)
                logger.warning("A transaction was reorg'd but still confirmed to " +
                    "a new block and different height: " + txid)
                #update history with the new height
                for scrhash in scrhashes:
                    for h in self.address_history[scrhash]["history"]:
                        if h["tx_hash"] == txid:
                            h["height"] = block["height"]
                #modify the reorgable tx with new hash and height
                elements_removed.append(reorgable_tx)
                elements_added.append((txid, tx["blockhash"], block["height"],
                    scrhashes))
                continue
            else:
                continue #no change to reorgable tx
            #remove tx from history
            for scrhash in scrhashes:
                deleted_entries = [h for h in self.address_history[scrhash][
                    "history"] if h["tx_hash"] == txid and
                    h["height"] == height]
                for d_his in deleted_entries:
                    self.address_history[scrhash]["history"].remove(d_his)

        for reorged_tx in elements_removed:
            self.reorganizable_txes.remove(reorged_tx)
        self.reorganizable_txes.extend(elements_added)
        return updated_scrhashes

    def check_for_confirmations(self):
        logger = self.logger
        tx_scrhashes_removed_from_mempool = []
        logger.debug("check4con unconfirmed_txes = "
            + pprint.pformat(self.unconfirmed_txes))
        for uc_txid, scrhashes in self.unconfirmed_txes.items():
            tx = self.rpc.call("gettransaction", [uc_txid])
            logger.debug("uc_txid=" + uc_txid + " => " + str(tx))
            if tx["confirmations"] == 0:
                continue #still unconfirmed
            tx_scrhashes_removed_from_mempool.append((uc_txid, scrhashes))
            if tx["confirmations"] > 0:
                logger.info("A transaction confirmed: " + uc_txid)
                block = self.rpc.call("getblockheader", [tx["blockhash"]])
            elif tx["confirmations"] < 0:
                logger.warning("A transaction became conflicted: " + uc_txid)
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
            if tx["confirmations"] > 0:
                self.reorganizable_txes.append((tx["txid"], tx["blockhash"],
                    block["height"], scrhashes))
        updated_scrhashes = set()
        for tx, scrhashes in tx_scrhashes_removed_from_mempool:
            del self.unconfirmed_txes[tx]
            updated_scrhashes.update(set(scrhashes))
        return updated_scrhashes

    def check_for_new_txes(self):
        logger = self.logger
        MAX_TX_REQUEST_COUNT = 256 
        tx_request_count = 2
        max_attempts = int(math.log(MAX_TX_REQUEST_COUNT, 2))
        for i in range(max_attempts):
            logger.debug("listtransactions tx_request_count="
                + str(tx_request_count))
            ##how listtransactions works
            ##skip and count parameters take most-recent txes first
            ## so skip=0 count=1 will return the most recent tx
            ##and skip=0 count=3 will return the 3 most recent txes
            ##but the actual list returned has the REVERSED order
            ##skip=0 count=3 will return a list with the most recent tx LAST
            ret = self.rpc.call("listtransactions", ["*", tx_request_count, 0,
                True])
            ret = ret[::-1]
            if self.last_known_wallet_txid == None:
                recent_tx_index = len(ret) #=0 means no new txes
                break
            else:
                txid_list = [(tx["txid"], tx.get("address", None))
                    for tx in ret]
                recent_tx_index = next((i for i, (txid, addr)
                    in enumerate(txid_list) if
                    txid == self.last_known_wallet_txid[0] and
                    addr == self.last_known_wallet_txid[1]), -1)
                if recent_tx_index != -1:
                    break
                tx_request_count *= 2

        #TODO low priority: handle a user getting more than 255 new
        # transactions in 15 seconds
        logger.debug("recent tx index = " + str(recent_tx_index) + " ret = " +
            str([(t["txid"], t.get("address", None)) for t in ret]))
        if len(ret) > 0:
            self.last_known_wallet_txid = (ret[0]["txid"],
                ret[0].get("address", None))
            logger.debug("last_known_wallet_txid = " + str(
                self.last_known_wallet_txid))
        assert(recent_tx_index != -1)
        if recent_tx_index == 0:
            return set()
        new_txes = ret[:recent_tx_index][::-1]
        logger.debug("new txes = " + str(new_txes))
        obtained_txids = set()
        updated_scripthashes = []
        for tx in new_txes:
            if "txid" not in tx or "category" not in tx:
                continue
            if tx["category"] not in ("receive", "send", "generate", "immature"):
                continue
            if tx["confirmations"] < 0:
                continue #conflicted
            if tx["txid"] in obtained_txids:
                continue
            obtained_txids.add(tx["txid"])
            output_scriptpubkeys, input_scriptpubkeys, txd = \
                self.get_input_and_output_scriptpubkeys(tx["txid"])
            matching_scripthashes = []
            for spk in (output_scriptpubkeys + input_scriptpubkeys):
                scripthash = script_to_scripthash(spk)
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
                            self.address_history[script_to_scripthash(
                                spk)] =  {'history': [], 'subscribed': False}
                        new_addrs = [script_to_address(s, self.rpc)
                            for s in spks]
                        logger.debug("importing " + str(len(spks)) +
                            " into change=" + str(change))
                        import_addresses(self.rpc, new_addrs, logger)

            updated_scripthashes.extend(matching_scripthashes)
            new_history_element = self.generate_new_history_element(tx, txd)
            logger.info("Found new tx: " + str(new_history_element))
            for scrhash in matching_scripthashes:
                self.address_history[scrhash]["history"].append(
                    new_history_element)
                if new_history_element["height"] == 0:
                    self.unconfirmed_txes[tx["txid"]].append(scrhash)
            if tx["confirmations"] > 0:
                self.reorganizable_txes.append((tx["txid"], tx["blockhash"],
                    new_history_element["height"], matching_scripthashes))
        return set(updated_scripthashes)

