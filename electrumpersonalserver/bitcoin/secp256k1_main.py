#!/usr/bin/python
from .py2specials import *
from .py3specials import *
import binascii
import hashlib
import re
import sys
import os
import base64
import time
import random
import hmac
import secp256k1


def privkey_to_address(priv, from_hex=True, magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv, from_hex), magicbyte)

privtoaddr = privkey_to_address

# Hashes
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    return hashlib.new('ripemd160', intermed).digest()

def hash160(string):
    return safe_hexlify(bin_hash160(string))

def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string,
                                                                 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bytes_to_hex_string(bin_sha256(string))

def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def dbl_sha256(string):
    return safe_hexlify(bin_dbl_sha256(string))

def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)

def num_to_var_int(x):
    x = int(x)
    if x < 253: return from_int_to_byte(x)
    elif x < 65536: return from_int_to_byte(253) + encode(x, 256, 2)[::-1]
    elif x < 4294967296: return from_int_to_byte(254) + encode(x, 256, 4)[::-1]
    else: return from_int_to_byte(255) + encode(x, 256, 8)[::-1]

# WTF, Electrum?
def electrum_sig_hash(message):
    padded = b"\x18Bitcoin Signed Message:\n" + num_to_var_int(len(
        message)) + from_string_to_bytes(message)
    return bin_dbl_sha256(padded)

# Encodings
def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def get_version_byte(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return ord(data[0])

def hex_to_b58check(inp, magicbyte=0):
    return bin_to_b58check(binascii.unhexlify(inp), magicbyte)

def b58check_to_hex(inp):
    return safe_hexlify(b58check_to_bin(inp))

def pubkey_to_address(pubkey, magicbyte=0):
    if len(pubkey) in [66, 130]:
        return bin_to_b58check(
            bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey), magicbyte)

pubtoaddr = pubkey_to_address

def wif_compressed_privkey(priv, vbyte=0):
    """Convert privkey in hex compressed to WIF compressed
    """
    if len(priv) != 66:
        raise Exception("Wrong length of compressed private key")
    if priv[-2:] != '01':
        raise Exception("Private key has wrong compression byte")
    return bin_to_b58check(binascii.unhexlify(priv), 128 + int(vbyte))


def from_wif_privkey(wif_priv, compressed=True, vbyte=0):
    """Convert WIF compressed privkey to hex compressed.
    Caller specifies the network version byte (0 for mainnet, 0x6f
    for testnet) that the key should correspond to; if there is
    a mismatch an error is thrown. WIF encoding uses 128+ this number.
    """
    bin_key = b58check_to_bin(wif_priv)
    claimed_version_byte = get_version_byte(wif_priv)
    if not 128+vbyte == claimed_version_byte:
        raise Exception(
            "WIF key version byte is wrong network (mainnet/testnet?)")
    if compressed and not len(bin_key) == 33:
        raise Exception("Compressed private key is not 33 bytes")
    if compressed and not bin_key[-1] == '\x01':
        raise Exception("Private key has incorrect compression byte")
    return safe_hexlify(bin_key)

def ecdsa_sign(msg, priv, usehex=True):
    #Compatibility issue: old bots will be confused
    #by different msg hashing algo; need to keep electrum_sig_hash, temporarily.
    hashed_msg = electrum_sig_hash(msg)
    if usehex:
        #arguments to raw sign must be consistently hex or bin
        hashed_msg = binascii.hexlify(hashed_msg)
    dersig = ecdsa_raw_sign(hashed_msg, priv, usehex, rawmsg=True)
    #see comments to legacy* functions
    #also, note those functions only handles binary, not hex
    if usehex:
        dersig = binascii.unhexlify(dersig)
    sig = legacy_ecdsa_sign_convert(dersig)
    return base64.b64encode(sig)

def ecdsa_verify(msg, sig, pub, usehex=True):
    #See note to ecdsa_sign
    hashed_msg = electrum_sig_hash(msg)
    sig = base64.b64decode(sig)
    #see comments to legacy* functions
    sig = legacy_ecdsa_verify_convert(sig)
    if usehex:
        #arguments to raw_verify must be consistently hex or bin
        hashed_msg = binascii.hexlify(hashed_msg)
        sig = binascii.hexlify(sig)
    return ecdsa_raw_verify(hashed_msg, pub, sig, usehex, rawmsg=True)

#A sadly necessary hack until all joinmarket bots are running secp256k1 code.
#pybitcointools *message* signatures (not transaction signatures) used an old signature
#format, basically: [27+y%2] || 32 byte r || 32 byte s,
#instead of DER. These two functions translate the new version into the old so that
#counterparty bots can verify successfully.
def legacy_ecdsa_sign_convert(dersig):
    #note there is no sanity checking of DER format (e.g. leading length byte)
    dersig = dersig[2:]  #e.g. 3045
    rlen = ord(dersig[1])  #ignore leading 02
    #length of r and s: ALWAYS <=33, USUALLY >=32 but can be shorter
    if rlen > 33:
        raise Exception("Incorrectly formatted DER sig:" + binascii.hexlify(
            dersig))
    if dersig[2] == '\x00':
        r = dersig[3:2 + rlen]
        ssig = dersig[2 + rlen:]
    else:
        r = dersig[2:2 + rlen]
        ssig = dersig[2 + rlen:]

    slen = ord(ssig[1])  #ignore leading 02
    if slen > 33:
        raise Exception("Incorrectly formatted DER sig:" + binascii.hexlify(
            dersig))
    if len(ssig) != 2 + slen:
        raise Exception("Incorrectly formatted DER sig:" + binascii.hexlify(
            dersig))
    if ssig[2] == '\x00':
        s = ssig[3:2 + slen]
    else:
        s = ssig[2:2 + slen]

        #the legacy version requires padding of r and s to 32 bytes with leading zeros
    r = '\x00' * (32 - len(r)) + r
    s = '\x00' * (32 - len(s)) + s

    #note: in the original pybitcointools implementation,
    #verification ignored the leading byte (it's only needed for pubkey recovery)
    #so we just ignore parity here.
    return chr(27) + r + s

def legacy_ecdsa_verify_convert(sig):
    sig = sig[1:]  #ignore parity byte
    r, s = sig[:32], sig[32:]
    if not len(s) == 32:
        #signature is invalid.
        return False
    #legacy code can produce high S. Need to reintroduce N ::cry::
    N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    s_int = decode(s, 256)
    # note // is integer division operator in both 2.7 and 3
    s_int = N - s_int if s_int > N // 2 else s_int  #enforce low S.

    #on re-encoding, don't use the minlen parameter, because
    #DER does not used fixed (32 byte) length values, so we
    #don't prepend zero bytes to shorter numbers.
    s = encode(s_int, 256)

    #as above, remove any front zero padding from r.
    r = encode(decode(r, 256), 256)

    #canonicalize r and s
    r, s = ['\x00' + x if ord(x[0]) > 127 else x for x in [r, s]]
    rlen = chr(len(r))
    slen = chr(len(s))
    total_len = 2 + len(r) + 2 + len(s)
    return '\x30' + chr(total_len) + '\x02' + rlen + r + '\x02' + slen + s

#Use secp256k1 to handle all EC and ECDSA operations.
#Data types: only hex and binary.
#Compressed and uncompressed private and public keys.
def hexbin(func):
    '''To enable each function to 'speak' either hex or binary,
    requires that the decorated function's final positional argument
    is a boolean flag, True for hex and False for binary.
    '''

    def func_wrapper(*args, **kwargs):
        if args[-1]:
            newargs = []
            for arg in args[:-1]:
                if isinstance(arg, (list, tuple)):
                    newargs += [[x.decode('hex') for x in arg]]
                else:
                    newargs += [arg.decode('hex')]
            newargs += [False]
            returnval = func(*newargs, **kwargs)
            if isinstance(returnval, bool):
                return returnval
            else:
                return binascii.hexlify(returnval)
        else:
            return func(*args, **kwargs)

    return func_wrapper

def read_privkey(priv):
    if len(priv) == 33:
        if priv[-1] == '\x01':
            compressed = True
        else:
            raise Exception("Invalid private key")
    elif len(priv) == 32:
        compressed = False
    else:
        raise Exception("Invalid private key")
    return (compressed, priv[:32])

@hexbin
def privkey_to_pubkey_inner(priv, usehex):
    '''Take 32/33 byte raw private key as input.
    If 32 bytes, return compressed (33 byte) raw public key.
    If 33 bytes, read the final byte as compression flag,
    and return compressed/uncompressed public key as appropriate.'''
    compressed, priv = read_privkey(priv)
    #secp256k1 checks for validity of key value.
    newpriv = secp256k1.PrivateKey(privkey=priv)
    return newpriv.pubkey.serialize(compressed=compressed)

def privkey_to_pubkey(priv, usehex=True):
    '''To avoid changing the interface from the legacy system,
    allow an *optional* hex argument here (called differently from
    maker/taker code to how it's called in bip32 code), then
    pass to the standard hexbin decorator under the hood.
    '''
    return privkey_to_pubkey_inner(priv, usehex)

privtopub = privkey_to_pubkey

@hexbin
def multiply(s, pub, usehex, rawpub=True):
    '''Input binary compressed pubkey P(33 bytes)
    and scalar s(32 bytes), return s*P.
    The return value is a binary compressed public key.
    Note that the called function does the type checking
    of the scalar s.
    ('raw' options passed in)
    '''
    newpub = secp256k1.PublicKey(pub, raw=rawpub)
    res = newpub.tweak_mul(s)
    return res.serialize()

@hexbin
def add_pubkeys(pubkeys, usehex):
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    r = secp256k1.PublicKey()  #dummy holding object
    pubkey_list = [secp256k1.PublicKey(x,
                                       raw=True).public_key for x in pubkeys]
    r.combine(pubkey_list)
    return r.serialize()

@hexbin
def add_privkeys(priv1, priv2, usehex):
    '''Add privkey 1 to privkey 2.
    Input keys must be in binary either compressed or not.
    Returned key will have the same compression state.
    Error if compression state of both input keys is not the same.'''
    y, z = [read_privkey(x) for x in [priv1, priv2]]
    if y[0] != z[0]:
        raise Exception("cannot add privkeys, mixed compression formats")
    else:
        compressed = y[0]
    newpriv1, newpriv2 = (y[1], z[1])
    p1 = secp256k1.PrivateKey(newpriv1, raw=True)
    res = p1.tweak_add(newpriv2)
    if compressed:
        res += '\x01'
    return res

@hexbin
def ecdsa_raw_sign(msg,
                   priv,
                   usehex,
                   rawpriv=True,
                   rawmsg=False,
                   usenonce=None):
    '''Take the binary message msg and sign it with the private key
    priv.
    By default priv is just a 32 byte string, if rawpriv is false
    it is assumed to be DER encoded.
    If rawmsg is True, no sha256 hash is applied to msg before signing.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 signing algo.
    If usenonce is not None, its value is passed to the secp256k1 library
    sign() function as the ndata value, which is then used in conjunction
    with a custom nonce generating function, such that the nonce used in the ECDSA
    sign algorithm is exactly that value (ndata there, usenonce here). 32 bytes.
    Return value: the calculated signature.'''
    if rawmsg and len(msg) != 32:
        raise Exception("Invalid hash input to ECDSA raw sign.")
    if rawpriv:
        compressed, p = read_privkey(priv)
        newpriv = secp256k1.PrivateKey(p, raw=True)
    else:
        newpriv = secp256k1.PrivateKey(priv, raw=False)
    if usenonce and len(usenonce) != 32:
        raise ValueError("Invalid nonce passed to ecdsa_sign: " + str(usenonce))

    sig = newpriv.ecdsa_sign(msg, raw=rawmsg)
    return newpriv.ecdsa_serialize(sig)

@hexbin
def ecdsa_raw_verify(msg, pub, sig, usehex, rawmsg=False):
    '''Take the binary message msg and binary signature sig,
    and verify it against the pubkey pub.
    If rawmsg is True, no sha256 hash is applied to msg before verifying.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 verification algo.
    Return value: True if the signature is valid for this pubkey, False
    otherwise. '''
    if rawmsg and len(msg) != 32:
        raise Exception("Invalid hash input to ECDSA raw sign.")
    newpub = secp256k1.PublicKey(pubkey=pub, raw=True)
    sigobj = newpub.ecdsa_deserialize(sig)
    return newpub.ecdsa_verify(msg, sigobj, raw=rawmsg)

def estimate_tx_size(ins, outs, txtype='p2pkh'):
    '''Estimate transaction size.
    Assuming p2pkh:
    out: 8+1+3+2+20=34, in: 1+32+4+1+1+~73+1+1+33=147,
    ver:4,seq:4, +2 (len in,out)
    total ~= 34*len_out + 147*len_in + 10 (sig sizes vary slightly)
    '''
    if txtype == 'p2pkh':
        return 10 + ins * 147 + 34 * outs
    else:
        raise NotImplementedError("Non p2pkh transaction size estimation not" +
                                  "yet implemented")
