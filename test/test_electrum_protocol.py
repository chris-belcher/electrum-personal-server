
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
    JsonRpcError
)

logger = logging.getLogger('ELECTRUMPERSONALSERVER-TEST')
logger.setLevel(logging.DEBUG)

def get_dummy_hash_from_height(height):
    return str(height) + "a"*(64 - len(str(height)))

def get_height_from_dummy_hash(hhash):
    return int(hhash[:hhash.index("a")])

class DummyJsonRpc(object):
    def __init__(self):
        self.calls = {}
        self.blockchain_height = 100000

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
            if height > 0:
                header["previousblockhash"] = get_dummy_hash_from_height(
                    height - 1)
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

def test_get_block_headers_hex_out_of_bounds():
    rpc = DummyJsonRpc()
    ret = get_block_headers_hex(rpc, rpc.blockchain_height + 10, 5)
    assert len(ret) == 2
    assert ret[0] == ""
    assert ret[1] == 0

def test_get_block_headers_hex():
    rpc = DummyJsonRpc()
    count = 200
    ret = get_block_headers_hex(rpc, 100, count)
    assert len(ret) == 2
    assert ret[1] == count
    assert len(ret[0]) == count*80*2 #80 bytes per header, 2 chars per byte

@pytest.mark.parametrize(
    "invalid_json_query",
    [
        "{\"invalid-json\":}",
        "{\"valid-json-no-method\": 5}"
    ]
) 
def test_invalid_json_query_line(invalid_json_query):
    protocol = ElectrumProtocol(None, None, logger, None, None, None)
    with pytest.raises(IOError) as e:
        protocol.handle_query(invalid_json_query)

class DummyTransactionMonitor(object):
    def __init__(self):
        self.deterministic_wallets = list(range(5))
        self.address_history = list(range(5))

    def get_electrum_history_hash(self, scrhash):
        pass

    def get_electrum_history(self, scrhash):
        pass

    def unsubscribe_all_addresses(self):
        pass

    def subscribe_address(self, scrhash):
        pass

    def get_address_balance(self, scrhash):
        pass

def create_electrum_protocol_instance(broadcast_method="own-node",
        tor_hostport=("127.0.0.01", 9050),
        disable_mempool_fee_histogram=False):
    protocol = ElectrumProtocol(DummyJsonRpc(), DummyTransactionMonitor(),
        logger, broadcast_method, tor_hostport, disable_mempool_fee_histogram)
    sent_lines = []
    protocol.set_send_line_fun(lambda l: sent_lines.append(json.loads(
        l.decode())))
    return protocol, sent_lines

def test_server_ping():
    protocol, sent_lines = create_electrum_protocol_instance()
    idd = 1
    protocol.handle_query(json.dumps({"method": "server.ping", "id": idd}))
    assert len(sent_lines) == 1
    assert sent_lines[0]["result"] == None
    assert sent_lines[0]["id"] == idd



