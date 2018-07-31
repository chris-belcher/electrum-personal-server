from electrumpersonalserver.bitcoin.main import *
import hmac
import hashlib
from binascii import hexlify

# Below code ASSUMES binary inputs and compressed pubkeys
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
#MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
#TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
#PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]

#updated for electrum's bip32 version bytes
#only public keys because electrum personal server only needs them
#https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst
PUBLIC = [  b'\x04\x88\xb2\x1e', #mainnet p2pkh or p2sh xpub
            b'\x04\x9d\x7c\xb2', #mainnet p2wpkh-p2sh ypub
            b'\x02\x95\xb4\x3f', #mainnet p2wsh-p2sh Ypub
            b'\x04\xb2\x47\x46', #mainnet p2wpkh zpub
            b'\x02\xaa\x7e\xd3', #mainnet p2wsh Zpub
            b'\x04\x35\x87\xcf', #testnet p2pkh or p2sh tpub
            b'\x04\x4a\x52\x62', #testnet p2wpkh-p2sh upub
            b'\x02\x42\x89\xef', #testnet p2wsh-p2sh Upub
            b'\x04\x5f\x1c\xf6', #testnet p2wpkh vpub
            b'\x02\x57\x54\x83' #testnet p2wsh Vpub
        ]

# BIP32 child key derivation

def raw_bip32_ckd(rawtuple, i):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    if vbytes in PRIVATE:
        priv = key
        pub = privtopub(key)
    else:
        pub = key

    if i >= 2**31:
        if vbytes in PUBLIC:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode, b'\x00' + priv[:32] + encode(i, 256, 4),
                     hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode, pub + encode(i, 256, 4),
                     hashlib.sha512).digest()

    if vbytes in PRIVATE:
        newkey = add_privkeys(I[:32] + B'\x01', priv)
        fingerprint = bin_hash160(privtopub(key))[:4]
    if vbytes in PUBLIC:
        newkey = add_pubkeys(compress(privtopub(I[:32])), key)
        fingerprint = bin_hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)


def bip32_serialize(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    i = encode(i, 256, 4)
    chaincode = encode(hash_to_int(chaincode), 256, 32)
    keydata = b'\x00' + key[:-1] if vbytes in PRIVATE else key
    bindata = vbytes + from_int_to_byte(
        depth % 256) + fingerprint + i + chaincode + keydata
    return changebase(bindata + bin_dbl_sha256(bindata)[:4], 256, 58)


def bip32_deserialize(data):
    dbin = changebase(data, 58, 256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = from_byte_to_int(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78] + b'\x01' if vbytes in PRIVATE else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)


def raw_bip32_privtopub(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    newvbytes = MAINNET_PUBLIC if vbytes == MAINNET_PRIVATE else TESTNET_PUBLIC
    return (newvbytes, depth, fingerprint, i, chaincode, privtopub(key))


def bip32_privtopub(data):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))


def bip32_ckd(data, i):
    return bip32_serialize(raw_bip32_ckd(bip32_deserialize(data), i))


def bip32_master_key(seed, vbytes=MAINNET_PRIVATE):
    I = hmac.new(
        from_string_to_bytes("Bitcoin seed"), seed, hashlib.sha512).digest()
    return bip32_serialize((vbytes, 0, b'\x00' * 4, 0, I[32:], I[:32] + b'\x01'
                           ))


def bip32_bin_extract_key(data):
    return bip32_deserialize(data)[-1]


def bip32_extract_key(data):
    return safe_hexlify(bip32_deserialize(data)[-1])

# Exploits the same vulnerability as above in Electrum wallets
# Takes a BIP32 pubkey and one of the child privkeys of its corresponding
# privkey and returns the BIP32 privkey associated with that pubkey

def raw_crack_bip32_privkey(parent_pub, priv):
    vbytes, depth, fingerprint, i, chaincode, key = priv
    pvbytes, pdepth, pfingerprint, pi, pchaincode, pkey = parent_pub
    i = int(i)

    if i >= 2**31:
        raise Exception("Can't crack private derivation!")

    I = hmac.new(pchaincode, pkey + encode(i, 256, 4), hashlib.sha512).digest()

    pprivkey = subtract_privkeys(key, I[:32] + b'\x01')

    newvbytes = MAINNET_PRIVATE if vbytes == MAINNET_PUBLIC else TESTNET_PRIVATE
    return (newvbytes, pdepth, pfingerprint, pi, pchaincode, pprivkey)


def crack_bip32_privkey(parent_pub, priv):
    dsppub = bip32_deserialize(parent_pub)
    dspriv = bip32_deserialize(priv)
    return bip32_serialize(raw_crack_bip32_privkey(dsppub, dspriv))

def bip32_descend(*args):
    if len(args) == 2:
        key, path = args
    else:
        key, path = args[0], map(int, args[1:])
    for p in path:
        key = bip32_ckd(key, p)
    return bip32_extract_key(key)

# electrum
def electrum_stretch(seed):
    return slowsha(seed)

# Accepts seed or stretched seed, returns master public key

def electrum_mpk(seed):
    if len(seed) == 32:
        seed = electrum_stretch(seed)
    return privkey_to_pubkey(seed)[2:]

# Accepts (seed or stretched seed), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns privkey


def electrum_privkey(seed, n, for_change=0):
    if len(seed) == 32:
        seed = electrum_stretch(seed)
    mpk = electrum_mpk(seed)
    offset = dbl_sha256(from_int_representation_to_bytes(n)+b':'+
        from_int_representation_to_bytes(for_change)+b':'+
        binascii.unhexlify(mpk))
    return add_privkeys(seed, offset)

# Accepts (seed or stretched seed or master pubkey), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns pubkey

def electrum_pubkey(masterkey, n, for_change=0):
    if len(masterkey) == 32:
        mpk = electrum_mpk(electrum_stretch(masterkey))
    elif len(masterkey) == 64:
        mpk = electrum_mpk(masterkey)
    else:
        mpk = masterkey
    bin_mpk = encode_pubkey(mpk, 'bin_electrum')
    offset = bin_dbl_sha256(from_int_representation_to_bytes(n)+b':'+
        from_int_representation_to_bytes(for_change)+b':'+bin_mpk)
    return add_pubkeys('04'+mpk, privtopub(offset))

