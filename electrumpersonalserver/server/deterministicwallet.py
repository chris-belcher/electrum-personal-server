
import logging

import electrumpersonalserver.bitcoin as btc
from electrumpersonalserver.server.hashes import bh2u, hash_160, bfh, sha256,\
    address_to_script, script_to_address
from electrumpersonalserver.server.jsonrpc import JsonRpcError
from electrumpersonalserver.server.descriptor import parse_descriptor

#the wallet types are here
#https://github.com/spesmilo/electrum/blob/3.0.6/RELEASE-NOTES
#and
#https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst

def import_addresses(rpc, watchonly_addrs, wallets, change_param, count,
        logger=None):
    """
    change_param = 0 for receive, 1 for change, -1 for both
    """
    logger = logger if logger else logging.getLogger('ELECTRUMPERSONALSERVER')
    logger.debug("Importing " + str(len(watchonly_addrs)) + " watch-only "
        + "address[es] and " + str(len(wallets)) + " wallet[s] ")

    for addr in watchonly_addrs:
        try:
            addr_desc = rpc.call("getdescriptorinfo",[f'addr({addr})'])["descriptor"]
            rpc.call("importdescriptors", [[{"desc": addr_desc, "timestamp": "now"}]])
        except JsonRpcError as e:
            ValueError(repr(e))

    for i, wal in enumerate(wallets):
        logger.info("Importing wallet " + str(i+1) + "/" + str(len(wallets)))
        if isinstance(wal, DescriptorDeterministicWallet):
            if change_param in (0, -1):
                #import receive addrs
                rpc.call("importdescriptors", [[{"desc": wal.descriptors[0], "range": [0, count-1], "timestamp": "now" }]])
            if change_param in (1, -1):
                #import change addrs
                rpc.call("importdescriptors", [[{"desc": wal.descriptors[1], "range": [0, count-1], "timestamp": "now" }]])
        else:
            #old-style-seed wallets
            logger.info("importing an old-style-seed wallet, will be slow...")
            for change in [0, 1]:
                addrs, spks = wal.get_addresses(change, 0, count)
                for a in addrs:
                    addr_desc = rpc.call("getdescriptorinfo", [f'addr({a})'])["descriptor"]
                    rpc.call("importdescriptors", [[{"desc": addr_desc, "timestamp": "now"}]])
    logger.debug("Importing done")


def is_string_parsable_as_hex_int(s):
    try:
        int(s, 16)
        return True
    except:
        return False

def parse_xpub_descriptor(desc, gaplimit, rpc, chain):
    if chain == "main":
        xpub_vbytes = b"\x04\x88\xb2\x1e"
    elif chain == "test" or chain == "regtest":
        xpub_vbytes = b"\x04\x35\x87\xcf"
    else:
        assert False
    parsed_descriptor = parse_descriptor(desc)
    if not parsed_descriptor.is_xpub():
        raise ValueError("The descriptor must include a master public key (xpub).")
    wallet = DescriptorWallet(rpc, xpub_vbytes, parsed_descriptor)
    wallet.gaplimit = gaplimit
    return wallet

def parse_electrum_master_public_key(keydata, gaplimit, rpc, chain):
    if chain == "main":
        xpub_vbytes = b"\x04\x88\xb2\x1e"
    elif chain == "test" or chain == "regtest":
        xpub_vbytes = b"\x04\x35\x87\xcf"
    else:
        assert False

    #https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md

    descriptor_template = None
    if keydata[:4] in ("xpub", "tpub"):
        descriptor_template = "pkh({xpub}/{change}/*)"
    elif keydata[:4] in ("zpub", "vpub"):
        descriptor_template = "wpkh({xpub}/{change}/*)"
    elif keydata[:4] in ("ypub", "upub"):
        descriptor_template = "sh(wpkh({xpub}/{change}/*))"

    if descriptor_template != None:
        wallet = SingleSigWallet(rpc, xpub_vbytes, keydata, descriptor_template)
    elif is_string_parsable_as_hex_int(keydata) and len(keydata) == 128:
        wallet = SingleSigOldMnemonicWallet(rpc, keydata)
    elif keydata.find(" ") != -1: #multiple keys = multisig
        chunks = keydata.split(" ")
        try:
            m = int(chunks[0])
        except ValueError:
            raise ValueError("Unable to parse m in multisig key data: "
                + chunks[0])
        pubkeys = chunks[1:]
        if not all([pubkeys[0][:4] == pub[:4] for pub in pubkeys[1:]]):
            raise ValueError("Inconsistent master public key types")
        if pubkeys[0][:4] in ("xpub", "tpub"):
            descriptor_script = "sh(sortedmulti("
        elif pubkeys[0][:4] in ("Zpub", "Vpub"):
            descriptor_script = "wsh(sortedmulti("
        elif pubkeys[0][:4] in ("Ypub", "Upub"):
            descriptor_script = "sh(wsh(sortedmulti("
        wallet = MultisigWallet(rpc, xpub_vbytes, m, pubkeys, descriptor_script)
    else:
        raise ValueError("Unrecognized electrum mpk format: " + keydata[:4])
    wallet.gaplimit = gaplimit
    return wallet

class DeterministicWallet(object):
    def __init__(self, rpc):
        self.gaplimit = 0
        self.next_index = [0, 0]
        self.scriptpubkey_index = {}
        self.rpc = rpc

    def _derive_addresses(self, change, from_index, count):
        raise RuntimeError()

    def get_addresses(self, change, from_index, count):
        """Returns addresses from this deterministic wallet"""
        addrs = self._derive_addresses(change, from_index, count)
        spks = [address_to_script(a, self.rpc) for a in addrs]
        for index, spk in enumerate(spks):
            self.scriptpubkey_index[spk] = (change, from_index + index)
        self.next_index[change] = max(self.next_index[change], from_index+count)
        return addrs, spks

    def get_new_addresses(self, change, count):
        """Returns newly-generated addresses from this deterministic wallet"""
        addrs, spks = self.get_addresses(change, self.next_index[change], count)
        return addrs, spks

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

class DescriptorDeterministicWallet(DeterministicWallet):
    def __init__(self, rpc, xpub_vbytes, *args):
        super(DescriptorDeterministicWallet, self).__init__(rpc)
        self.xpub_vbytes = xpub_vbytes

        descriptors_without_checksum = \
            self.obtain_descriptors_without_checksum(args)

        try:
            self.descriptors = []
            for desc in descriptors_without_checksum:
                self.descriptors.append(self.rpc.call("getdescriptorinfo",
                    [desc])["descriptor"])
        except JsonRpcError as e:
            raise ValueError(repr(e))

    def obtain_descriptors_without_checksum(self, *args):
        raise RuntimeError()

    def _derive_addresses(self, change, from_index, count):
        return self.rpc.call("deriveaddresses", [self.descriptors[change], [
            from_index, from_index + count - 1]])
        ##the minus 1 is because deriveaddresses uses inclusive range
        ##e.g. to get just the first address you use [0, 0]

    def _convert_to_standard_xpub(self, mpk):
        return btc.bip32_serialize((self.xpub_vbytes, *btc.bip32_deserialize(
            mpk)[1:]))

class DescriptorWallet(DescriptorDeterministicWallet):
    def __init__(self, rpc, xpub_vbytes, descriptor):
        super(DescriptorWallet, self).__init__(rpc, xpub_vbytes, descriptor)

    def obtain_descriptors_without_checksum(self, args):
        descriptor = args[0]
        descriptors_without_checksum = []
        for change in [0, 1]:
            descriptors_without_checksum.append(descriptor.to_ranged_string_no_checksum(change))
        return descriptors_without_checksum

class SingleSigWallet(DescriptorDeterministicWallet):
    def __init__(self, rpc, xpub_vbytes, xpub, descriptor_template):
        super(SingleSigWallet, self).__init__(rpc, xpub_vbytes, xpub,
            descriptor_template)

    def obtain_descriptors_without_checksum(self, args):
        ##example descriptor_template:
        #"pkh({xpub}/{change}/*)"
        xpub, descriptor_template = args

        descriptors_without_checksum = []
        xpub = self._convert_to_standard_xpub(xpub)
        for change in [0, 1]:
            descriptors_without_checksum.append(descriptor_template.format(
                change=change, xpub=xpub))
        return descriptors_without_checksum

class MultisigWallet(DescriptorDeterministicWallet):
    def __init__(self, rpc, xpub_vbytes, m, xpub_list, descriptor_script):
        super(MultisigWallet, self).__init__(rpc, xpub_vbytes, m, xpub_list,
            descriptor_script)

    def obtain_descriptors_without_checksum(self, args):
        ##example descriptor_script:
        #"sh(sortedmulti("
        m, xpub_list, descriptor_script = args

        descriptors_without_checksum = []
        xpub_list = [self._convert_to_standard_xpub(xpub) for xpub in xpub_list]
        for change in [0, 1]:
            descriptors_without_checksum.append(descriptor_script + str(m) +\
                "," + ",".join([xpub + "/" + str(change) + "/*"
                for xpub in xpub_list]) + ")"*descriptor_script.count("("))
        return descriptors_without_checksum

class SingleSigOldMnemonicWallet(DeterministicWallet):
    def __init__(self, rpc, mpk):
        super(SingleSigOldMnemonicWallet, self).__init__(rpc)
        self.mpk = mpk

    def _pubkey_to_scriptpubkey(self, pubkey):
        pkh = bh2u(hash_160(bfh(pubkey)))
        #op_dup op_hash_160 length hash160 op_equalverify op_checksig
        return "76a914" + pkh + "88ac"

    def _derive_addresses(self, change, from_index, count):
        result = []
        for index in range(from_index, from_index + count):
            pubkey = btc.electrum_pubkey(self.mpk, index, change)
            scriptpubkey = self._pubkey_to_scriptpubkey(pubkey)
            result.append(script_to_address(scriptpubkey, self.rpc))
        return result
