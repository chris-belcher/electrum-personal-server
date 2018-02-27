
import bitcoin as btc
import hashlib, binascii

## stuff copied from electrum's source

def to_bytes(something, encoding='utf8'):
    """
    cast string to bytes() like object, but for python2 support
    it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")

def sha256(x):
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())

def bh2u(x):
    return binascii.hexlify(x).decode('ascii')

def script_to_scripthash(script):
    """Electrum uses a format hash(scriptPubKey) as the index keys"""
    h = sha256(bytes.fromhex(script))[0:32]
    return bh2u(bytes(reversed(h)))

#the 'result' field in the blockchain.scripthash.subscribe method
# reply uses this as a summary of the address
def get_status_electrum(h):
    if not h:
        return None
    status = ''
    for tx_hash, height in h:
        status += tx_hash + ':%d:' % height
    return bh2u(hashlib.sha256(status.encode('ascii')).digest())

bfh = bytes.fromhex
hash_encode = lambda x: bh2u(x[::-1])
hash_decode = lambda x: bfh(x)[::-1]

def Hash(x):
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out

def hash_merkle_root(merkle_s, target_hash, pos):
    h = hash_decode(target_hash)
    for i in range(len(merkle_s)):
        item = merkle_s[i]
        h = Hash(hash_decode(item) + h) if ((pos >> i) & 1) else Hash(
            h + hash_decode(item))
    return hash_encode(h)

## end of electrum copypaste

def script_to_address(script):
    #TODO why is this even here? its not used anywhere, maybe old code
    #TODO bech32 addresses
    #TODO testnet, although everything uses scripthash so the address
    #     vbyte doesnt matter
    return btc.script_to_address(script, 0x00)

def address_to_script(addr, rpc):
    return rpc.call("validateaddress", [addr])["scriptPubKey"]

def address_to_scripthash(addr, rpc):
    return script_to_scripthash(address_to_script(addr, rpc))

