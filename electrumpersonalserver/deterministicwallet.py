
import bitcoin as btc
from electrumpersonalserver.hashes import bh2u, hash_160, bfh, sha256

# the class hierarchy for deterministic wallets in this file:
# subclasses are written towards the right
# each class knows how to create the scriptPubKeys of that wallet
#
#                                       |-- SingleSigOldMnemonicWallet
#                                       |-- SingleSigP2PKHWallet
#                                       |-- SingleSigP2WPKHWallet
#                     SingleSigWallet --|
#                    /                  |-- SingleSigP2WPKH_P2SHWallet
# DeterministicWallet
#                    \                 |-- MultisigP2SHWallet
#                     MultisigWallet --|
#                                      |-- MultisigP2WSHWallet
#                                      |-- MultisigP2WSH_P2SHWallet

#the wallet types are here
#https://github.com/spesmilo/electrum/blob/3.0.6/RELEASE-NOTES
#and
#https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst

def is_string_parsable_as_hex_int(s):
    try:
        int(s, 16)
        return True
    except:
        return False

def parse_electrum_master_public_key(keydata, gaplimit):
    if keydata[:4] in ("xpub", "tpub"):
        wallet = SingleSigP2PKHWallet(keydata)
    elif keydata[:4] in ("zpub", "vpub"):
        wallet = SingleSigP2WPKHWallet(keydata)
    elif keydata[:4] in ("ypub", "upub"):
        wallet = SingleSigP2WPKH_P2SHWallet(keydata)
    elif keydata.find(" ") != -1: #multiple keys = multisig
        chunks = keydata.split(" ")
        try:
            m = int(chunks[0])
        except ValueError:
            raise ValueError("Unable to parse m in multisig key data: "
                + chunks[0])
        pubkeys = chunks[1:]
        if not all([pubkeys[0][:4] == pub[:4] for pub in pubkeys[1:]]):
            raise ValueError("inconsistent bip32 pubkey types")
        if pubkeys[0][:4] in ("xpub", "tpub"):
            wallet = MultisigP2SHWallet(m, pubkeys)
        elif pubkeys[0][:4] in ("Zpub", "Vpub"):
            wallet = MultisigP2WSHWallet(m, pubkeys)
        elif pubkeys[0][:4] in ("Ypub", "Upub"):
            wallet = MultisigP2WSH_P2SHWallet(m, pubkeys)
    elif is_string_parsable_as_hex_int(keydata) and len(keydata) == 128:
        wallet = SingleSigOldMnemonicWallet(keydata)
    else:
        raise ValueError("Unrecognized electrum mpk format: " + keydata[:4])
    wallet.gaplimit = gaplimit
    return wallet

class DeterministicWallet(object):
    def __init__(self):
        self.gaplimit = 0
        self.next_index = [0, 0]
        self.scriptpubkey_index = {}

    def get_new_scriptpubkeys(self, change, count):
        """Returns newly-generated addresses from this deterministic wallet"""
        return self.get_scriptpubkeys(change, self.next_index[change],
            count)

    def get_scriptpubkeys(self, change, from_index, count):
        """Returns addresses from this deterministic wallet"""
        pass

    #called in check_for_new_txes() when a new tx of ours arrives
    #to see if we need to import more addresses
    def have_scriptpubkeys_overrun_gaplimit(self, scriptpubkeys):
        """Return None if they havent, or how many addresses to
           import if they have"""
        result = {}
        for spk in scriptpubkeys:
            if spk not in self.scriptpubkey_index:
                continue
            change, index = self.scriptpubkey_index[spk]
            distance_from_next = self.next_index[change] - index
            if distance_from_next > self.gaplimit:
                continue
            #need to import more
            if change in result:
                result[change] = max(result[change], self.gaplimit
                    - distance_from_next + 1)
            else:
                result[change] = self.gaplimit - distance_from_next + 1
        if len(result) > 0:
            return result
        else:
            return None

    def rewind_one(self, change):
        """Go back one pubkey in a branch"""
        self.next_index[change] -= 1

class SingleSigWallet(DeterministicWallet):
    def __init__(self, mpk):
        super(SingleSigWallet, self).__init__()
        try:
            self.branches = (btc.bip32_ckd(mpk, 0), btc.bip32_ckd(mpk, 1))
        except Exception:
            raise ValueError("Bad master public key format. Get it from " +
                "Electrum menu `Wallet` -> `Information`")
        #m/change/i

    def pubkey_to_scriptpubkey(self, pubkey):
        raise RuntimeError()

    def get_pubkey(self, change, index):
        return btc.bip32_extract_key(btc.bip32_ckd(self.branches[change],
            index))

    def get_scriptpubkeys(self, change, from_index, count):
        result = []
        for index in range(from_index, from_index + count):
            pubkey = self.get_pubkey(change, index)
            scriptpubkey = self.pubkey_to_scriptpubkey(pubkey)
            self.scriptpubkey_index[scriptpubkey] = (change, index)
            result.append(scriptpubkey)
        self.next_index[change] = max(self.next_index[change], from_index+count)
        return result

class SingleSigP2PKHWallet(SingleSigWallet):
    def pubkey_to_scriptpubkey(self, pubkey):
        pkh = bh2u(hash_160(bfh(pubkey)))
        #op_dup op_hash_160 length hash160 op_equalverify op_checksig
        return "76a914" + pkh + "88ac"

class SingleSigP2WPKHWallet(SingleSigWallet):
    def pubkey_to_scriptpubkey(self, pubkey):
        pkh = bh2u(hash_160(bfh(pubkey)))
        #witness-version length hash160
        #witness version is always 0, length is always 0x14
        return "0014" + pkh

class SingleSigP2WPKH_P2SHWallet(SingleSigWallet):
    def pubkey_to_scriptpubkey(self, pubkey):
        #witness-version length pubkeyhash
        #witness version is always 0, length is always 0x14
        redeem_script = '0014' + bh2u(hash_160(bfh(pubkey)))
        sh = bh2u(hash_160(bfh(redeem_script)))
        return "a914" + sh + "87"

class SingleSigOldMnemonicWallet(SingleSigWallet):
    def __init__(self, mpk):
        super(SingleSigWallet, self).__init__()
        self.mpk = mpk

    def get_pubkey(self, change, index):
        return btc.electrum_pubkey(self.mpk, index, change)

    def pubkey_to_scriptpubkey(self, pubkey):
        pkh = bh2u(hash_160(bfh(pubkey)))
        #op_dup op_hash_160 length hash160 op_equalverify op_checksig
        return "76a914" + pkh + "88ac"

class MultisigWallet(DeterministicWallet):
    def __init__(self, m, mpk_list):
        super(MultisigWallet, self).__init__()
        self.m = m
        try:
            self.pubkey_branches = [(btc.bip32_ckd(mpk, 0), btc.bip32_ckd(mpk,
                1)) for mpk in mpk_list]
        except Exception:
            raise ValueError("Bad master public key format. Get it from " +
                "Electrum menu `Wallet` -> `Information`")
        #derivation path for pubkeys is m/change/index

    def redeem_script_to_scriptpubkey(self, redeem_script):
        raise RuntimeError()

    def get_scriptpubkeys(self, change, from_index, count):
        result = []
        for index in range(from_index, from_index + count):
            pubkeys = [btc.bip32_extract_key(btc.bip32_ckd(branch[change],
                index)) for branch in self.pubkey_branches]
            pubkeys = sorted(pubkeys)
            redeemScript = ""
            redeemScript += "%x"%(0x50 + self.m) #op_m
            for p in pubkeys:
                redeemScript += "21" #length
                redeemScript += p
            redeemScript += "%x"%(0x50 + len(pubkeys)) #op_n
            redeemScript += "ae" # op_checkmultisig
            scriptpubkey = self.redeem_script_to_scriptpubkey(redeemScript)
            self.scriptpubkey_index[scriptpubkey] = (change, index)
            result.append(scriptpubkey)
        self.next_index[change] = max(self.next_index[change], from_index+count)
        return result

class MultisigP2SHWallet(MultisigWallet):
    def redeem_script_to_scriptpubkey(self, redeem_script):
        sh = bh2u(hash_160(bfh(redeem_script)))
        #op_hash160 length hash160 op_equal
        return "a914" + sh + "87"

class MultisigP2WSHWallet(MultisigWallet):
    def redeem_script_to_scriptpubkey(self, redeem_script):
        sh = bh2u(sha256(bfh(redeem_script)))
        #witness-version length sha256
        #witness version is always 0, length is always 0x20
        return "0020" + sh

class MultisigP2WSH_P2SHWallet(MultisigWallet):
    def redeem_script_to_scriptpubkey(self, redeem_script):
        #witness-version length sha256
        #witness version is always 0, length is always 0x20
        nested_redeemScript = "0020" + bh2u(sha256(bfh(redeem_script)))
        sh = bh2u(hash_160(bfh(nested_redeemScript)))
        #op_hash160 length hash160 op_equal
        return "a914" + sh + "87"

