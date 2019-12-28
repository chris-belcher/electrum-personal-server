
import pytest
import logging
import json

from electrumpersonalserver.server import (
    TransactionMonitor,
    JsonRpcError,
    ElectrumProtocol,
    get_block_header,
    get_current_header,
    get_block_headers_hex,
    JsonRpcError,
    get_status_electrum
)

logger = logging.getLogger('ELECTRUMPERSONALSERVER-TEST')
logger.setLevel(logging.DEBUG)

DUMMY_JSONRPC_BLOCKCHAIN_HEIGHT = 100000

def get_dummy_hash_from_height(height):
    if height == 0:
        return "00"*32
    return str(height) + "a"*(64 - len(str(height)))

def get_height_from_dummy_hash(hhash):
    if hhash == "00"*32:
        return 0
    return int(hhash[:hhash.index("a")])

class DummyJsonRpc(object):
    def __init__(self):
        self.calls = {}
        self.blockchain_height = DUMMY_JSONRPC_BLOCKCHAIN_HEIGHT

    def call(self, method, params):
        if method not in self.calls:
            self.calls[method] = [0, []]
        self.calls[method][0] += 1
        self.calls[method][1].append(params)
        if method == "getbestblockhash":
            return get_dummy_hash_from_height(self.blockchain_height)
        elif method == "getblockhash":
            height = params[0]
            if height > self.blockchain_height:
                raise JsonRpcError()
            return get_dummy_hash_from_height(height)
        elif method == "getblockheader":
            blockhash = params[0]
            height = get_height_from_dummy_hash(blockhash)
            header = {
                "hash": blockhash,
                "confirmations": self.blockchain_height - height + 1,
                "height": height,
                "version": 536870912,
                "versionHex": "20000000",
                "merkleroot": "aa"*32,
                "time": height*100,
                "mediantime": height*100,
                "nonce": 1,
                "bits": "207fffff",
                "difficulty": 4.656542373906925e-10,
                "chainwork": "000000000000000000000000000000000000000000000"
                    + "00000000000000000da",
                "nTx": 1,
            }
            if height > 1:
                header["previousblockhash"] = get_dummy_hash_from_height(
                    height - 1)
            elif height == 1:
                header["previousblockhash"] = "00"*32 #genesis block
            elif height == 0:
                pass #no prevblock for genesis
            else:
                assert 0
            if height < self.blockchain_height:
                header["nextblockhash"] = get_dummy_hash_from_height(height + 1)
            return header
        elif method == "gettransaction":
            for t in self.txlist:
                if t["txid"] == params[0]:
                    return t
            raise JsonRpcError()
        else:
            raise ValueError("unknown method in dummy jsonrpc")

def test_get_block_header():
    rpc = DummyJsonRpc()
    for height in [0, 1000]:
        for raw in [True, False]:
            blockhash = rpc.call("getblockhash", [height])
            ret = get_block_header(rpc, blockhash, raw)
            if raw:
                assert type(ret) == dict
                assert "hex" in ret
                assert "height" in ret
                assert len(ret["hex"]) == 160
            else:
                assert type(ret) == dict
                assert len(ret) == 7

def test_get_current_header():
    rpc = DummyJsonRpc()
    for raw in [True, False]:
        ret = get_current_header(rpc, raw)
        assert type(ret[0]) == str
        assert len(ret[0]) == 64
        if raw:
            assert type(ret[1]) == dict
            assert "hex" in ret[1]
            assert "height" in ret[1]
            assert len(ret[1]["hex"]) == 160
        else:
            assert type(ret[1]) == dict
            assert len(ret[1]) == 7

@pytest.mark.parametrize(
    "start_height, count",
    [(100, 200),
    (DUMMY_JSONRPC_BLOCKCHAIN_HEIGHT + 10, 5),
    (DUMMY_JSONRPC_BLOCKCHAIN_HEIGHT - 10, 15),
    (0, 250)
    ]
)
def test_get_block_headers_hex(start_height, count):
    rpc = DummyJsonRpc()
    ret = get_block_headers_hex(rpc, start_height, count)
    print("start_height=" + str(start_height) + " count=" + str(count))
    assert len(ret) == 2
    available_blocks = -min(0, start_height - DUMMY_JSONRPC_BLOCKCHAIN_HEIGHT
        - 1)
    expected_count = min(available_blocks, count)
    assert len(ret[0]) == expected_count*80*2 #80 bytes/header, 2 chars/byte
    assert ret[1] == expected_count

@pytest.mark.parametrize(
    "invalid_json_query",
    [
        {"valid-json-no-method": 5}
    ]
) 
def test_invalid_json_query_line(invalid_json_query):
    protocol = ElectrumProtocol(None, None, logger, None, None, None)
    with pytest.raises(IOError) as e:
        protocol.handle_query(invalid_json_query)

def create_electrum_protocol_instance(broadcast_method="own-node",
        tor_hostport=("127.0.0.1", 9050),
        disable_mempool_fee_histogram=False):
    protocol = ElectrumProtocol(DummyJsonRpc(), DummyTransactionMonitor(),
        logger, broadcast_method, tor_hostport, disable_mempool_fee_histogram)
    sent_replies = []
    protocol.set_send_reply_fun(lambda l: sent_replies.append(l))
    assert len(sent_replies) == 0
    return protocol, sent_replies

def dummy_script_hash_to_history(scrhash):
    index = int(scrhash[:scrhash.index("s")])
    tx_count = (index+2) % 5
    height = 500
    return [(index_to_dummy_txid(i), height) for i in range(tx_count)]

def index_to_dummy_script_hash(index):
    return str(index) + "s"*(64 - len(str(index)))

def index_to_dummy_txid(index):
    return str(index) + "t"*(64 - len(str(index)))

def dummy_txid_to_dummy_tx(txid):
    return txid[::-1] * 6

class DummyTransactionMonitor(object):
    def __init__(self):
        self.deterministic_wallets = list(range(5))
        self.address_history = list(range(5))
        self.subscribed_addresses = []
        self.history_hashes = {}

    def get_electrum_history_hash(self, scrhash):
        history = dummy_script_hash_to_history(scrhash)
        hhash = get_status_electrum(history)
        self.history_hashes[scrhash] = history
        return hhash

    def get_electrum_history(self, scrhash):
        return self.history_hashes[scrhash]

    def unsubscribe_all_addresses(self):
        self.subscribed_addresses = []

    def subscribe_address(self, scrhash):
        self.subscribed_addresses.append(scrhash)
        return True

    def get_address_balance(self, scrhash):
        pass

def test_script_hash_sync():
    protocol, sent_replies = create_electrum_protocol_instance()
    scrhash_index = 0
    scrhash = index_to_dummy_script_hash(scrhash_index)
    protocol.handle_query({"method": "blockchain.scripthash.subscribe",
        "params": [scrhash], "id": 0})
    assert len(sent_replies) == 1
    assert len(protocol.txmonitor.subscribed_addresses) == 1
    assert protocol.txmonitor.subscribed_addresses[0] == scrhash
    assert len(sent_replies) == 1
    assert len(sent_replies[0]["result"]) == 64
    history_hash = sent_replies[0]["result"]

    protocol.handle_query({"method": "blockchain.scripthash.get_history",
        "params": [scrhash], "id": 0})
    assert len(sent_replies) == 2
    assert get_status_electrum(sent_replies[1]["result"]) == history_hash

    #updated scripthash but actually nothing changed, history_hash unchanged
    protocol.on_updated_scripthashes([scrhash])
    assert len(sent_replies) == 3
    assert sent_replies[2]["method"] == "blockchain.scripthash.subscribe"
    assert sent_replies[2]["params"][0] == scrhash
    assert sent_replies[2]["params"][1] == history_hash

    protocol.on_disconnect()
    assert len(protocol.txmonitor.subscribed_addresses) == 0

def test_headers_subscribe():
    protocol, sent_replies = create_electrum_protocol_instance()

    protocol.handle_query({"method": "server.version", "params": ["test-code",
        1.4], "id": 0}) #protocol version of 1.4 means only raw headers used
    assert len(sent_replies) == 1

    protocol.handle_query({"method": "blockchain.headers.subscribe", "params":
        [], "id": 0})
    assert len(sent_replies) == 2
    assert "height" in sent_replies[1]["result"]
    assert sent_replies[1]["result"]["height"] == protocol.rpc.blockchain_height
    assert "hex" in sent_replies[1]["result"]
    assert len(sent_replies[1]["result"]["hex"]) == 80*2 #80 b/header, 2 b/char

    protocol.rpc.blockchain_height += 1
    new_bestblockhash, header = get_current_header(protocol.rpc,
        protocol.are_headers_raw)
    protocol.on_blockchain_tip_updated(header)
    assert len(sent_replies) == 3
    assert "method" in sent_replies[2]
    assert sent_replies[2]["method"] == "blockchain.headers.subscribe"
    assert "params" in sent_replies[2]
    assert "height" in sent_replies[2]["params"][0]
    assert sent_replies[2]["params"][0]["height"]\
        == protocol.rpc.blockchain_height
    assert "hex" in sent_replies[2]["params"][0]
    assert len(sent_replies[2]["params"][0]["hex"]) == 80*2 #80 b/header, 2 b/c

def test_server_ping():
    protocol, sent_replies = create_electrum_protocol_instance()
    idd = 1
    protocol.handle_query({"method": "server.ping", "id": idd})
    assert len(sent_replies) == 1
    assert sent_replies[0]["result"] == None
    assert sent_replies[0]["id"] == idd

#test scripthash.subscribe, scripthash.get_history transaction.get
# transaction.get_merkle

