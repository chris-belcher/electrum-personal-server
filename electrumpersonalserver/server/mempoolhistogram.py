
import time
from collections import defaultdict
from datetime import datetime
from enum import Enum

from electrumpersonalserver.server.jsonrpc import JsonRpcError

def calc_histogram(mempool):
    #algorithm copied from the relevant place in ElectrumX
    #https://github.com/kyuupichan/electrumx/blob/e92c9bd4861c1e35989ad2773d33e01219d33280/server/mempool.py
    fee_hist = defaultdict(int)
    for fee_rate, size in mempool.values():
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
    return out

class PollIntervalChange(Enum):
    UNCHANGED = "unchanged"
    FAST_POLLING = "fastpolling"
    NORMAL_POLLING = "normalpolling"

class MempoolSync(object):
    def __init__(self, rpc, disabled, polling_interval):
        self.rpc = rpc
        self.disabled = disabled
        self.polling_interval = polling_interval
        self.mempool = dict()
        self.cached_fee_histogram = [[0, 0]]
        self.added_txids = None
        self.last_poll = None
        self.state = "gettxids"

    def set_polling_interval(self, polling_interval):
        self.polling_interval = polling_interval

    def get_fee_histogram(self):
        return self.cached_fee_histogram

    def initial_sync(self, logger):
        if self.disabled:
            return
        logger.info("Synchronizing mempool . . .")
        st = time.time()
        for _ in range(2):
            self.poll_update(-1)
        self.state = "gettxids"
        for _ in range(2):
            self.poll_update(-1)
        #run once for the getrawmempool
        #again for the getmempoolentry
        #and all that again because the first time will take so long
        # that new txes could arrive in that time
        et = time.time()
        logger.info("Found " + str(len(self.mempool)) + " mempool entries. "
            + "Synchronized mempool in " + str(et - st) + "sec")

    #-1 for no timeout
    def poll_update(self, timeout):
        poll_interval_change = PollIntervalChange.UNCHANGED
        if self.disabled:
            return poll_interval_change
        if self.state == "waiting":
            if ((datetime.now() - self.last_poll).total_seconds()
                    > self.polling_interval):
                poll_interval_change = PollIntervalChange.FAST_POLLING
                self.state = "gettxids"
        elif self.state == "gettxids":
            mempool_txids = self.rpc.call("getrawmempool", [])
            self.last_poll = datetime.now()
            mempool_txids = set(mempool_txids)

            removed_txids = set(self.mempool.keys()).difference(mempool_txids)
            self.added_txids = iter(mempool_txids.difference(
                set(self.mempool.keys())))

            for txid in removed_txids:
                del self.mempool[txid]

            self.state = "getfeerates"
        elif self.state == "getfeerates":
            if timeout == -1:
                timeout = 2**32
            start_time = datetime.now()
            while self.state != "waiting" and ((datetime.now() - start_time
                    ).total_seconds() < timeout):
                try:
                    txid = next(self.added_txids)
                except StopIteration:
                    self.cached_fee_histogram = calc_histogram(self.mempool)
                    self.state = "waiting"
                    poll_interval_change = \
                        PollIntervalChange.NORMAL_POLLING
                    self.last_poll = datetime.now()
                    continue
                try:
                    mempool_tx = self.rpc.call("getmempoolentry", [txid])
                except JsonRpcError:
                    continue
                fee_rate = 1e8*mempool_tx["fee"] // mempool_tx["vsize"]
                self.mempool[txid] = (fee_rate, mempool_tx["vsize"])

        return poll_interval_change
