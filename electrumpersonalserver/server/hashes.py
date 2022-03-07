
import hashlib
import binascii
import math

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
    if len(h) == 0:
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

def hash_160(public_key):
    try:
        md = hashlib.new('ripemd160')
        md.update(sha256(public_key))
        return md.digest()
    except BaseException:
        from . import ripemd
        md = ripemd.new(sha256(public_key))
        return md.digest()

## end of electrum copypaste

def script_to_address(scriptPubKey, rpc):
    return rpc.call("decodescript", [scriptPubKey])["address"]

def address_to_script(addr, rpc):
    return rpc.call("validateaddress", [addr])["scriptPubKey"]

def address_to_scripthash(addr, rpc):
    return script_to_scripthash(address_to_script(addr, rpc))

# doesnt really fit here but i dont want to clutter up server.py

unit_list = list(zip(['B', 'kB', 'MB', 'GB', 'TB', 'PB'], [0, 0, 1, 2, 2, 2]))

def bytes_fmt(num):
    """Human friendly file size"""
    if num > 1:
        exponent = min(int(math.log(num, 1000)), len(unit_list) - 1)
        quotient = float(num) / 1000**exponent
        unit, num_decimals = unit_list[exponent]
        format_string = '{:.%sf} {}' % (num_decimals)
        return format_string.format(quotient, unit)
    if num == 0:
        return '0 bytes'
    if num == 1:
        return '1 byte'

