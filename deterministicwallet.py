
import bitcoin as btc
import util

def parse_electrum_master_public_key(keydata, gaplimit):
    if keydata[:4] == "xpub":
        return SingleSigP2PKHWallet(keydata, gaplimit)
    else:
        raise RuntimeError("Unrecognized electrum mpk format: " + keydata[:4])

#the wallet types are here
#https://github.com/spesmilo/electrum/blob/3.0.6/RELEASE-NOTES

class DeterministicWallet(object):
    def __init__(self, gaplimit):
        self.gaplimit = gaplimit

    def get_new_scriptpubkeys(self, change, count):
        """Returns newly-generated addresses from this deterministic wallet"""
        pass

    def get_scriptpubkeys(self, change, from_index, count):
        """Returns addresses from this deterministic wallet"""
        pass

    #called in check_for_new_txes() when a new tx of ours arrives
    #to see if we need to import more addresses
    def have_scriptpubkeys_overrun_gaplimit(self, scripts):
        """Return None if they havent, or how many addresses to
           import if they have"""
        pass

    def rewind_one(self, change):
        """Go back one pubkey in a branch"""
        pass

class SingleSigP2PKHWallet(DeterministicWallet):
    def __init__(self, mpk, gaplimit):
        super(SingleSigP2PKHWallet, self).__init__(gaplimit)
        self.branches = (btc.bip32_ckd(mpk, 0), btc.bip32_ckd(mpk, 1))
        self.next_index = [0, 0]
        self.scriptpubkey_index = {}

    def pubkey_to_scriptpubkey(self, pubkey):
        pkh = util.bh2u(util.hash_160(util.bfh(pubkey)))
        #op_dup op_hash_160 length hash160 op_equalverify op_checksig
        return "76a914" + pkh + "88ac"
        #for p2sh its "a9" + hash160 + "87" #op_hash_160 op_equal

    def get_new_scriptpubkeys(self, change, count):
        return self.get_scriptpubkeys(change, self.next_index[change],
            count)

    def get_scriptpubkeys(self, change, from_index, count):
        #m/change/i
        result = []
        for index in range(from_index, from_index + count):
            pubkey = btc.bip32_extract_key(btc.bip32_ckd(self.branches[change],
                index))
            scriptpubkey = self.pubkey_to_scriptpubkey(pubkey)
            self.scriptpubkey_index[scriptpubkey] = (change, index)
            result.append(scriptpubkey)
        self.next_index[change] = max(self.next_index[change], from_index+count)
        return result

    def have_scriptpubkeys_overrun_gaplimit(self, scriptpubkeys):
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
        self.next_index[change] -= 1

'''
recv
76a914b1847c763c9a9b12631ab42335751c1bf843880c88ac
76a914d8b6b932e892fad5132ea888111adac2171c5af588ac
76a914e44b19ef74814f977ae4e2823dd0a0b33480472a88ac
change
76a914d2c2905ca383a5b8f94818cb7903498061a6286688ac
76a914e7b4ddb7cede132e84ba807defc092cf52e005b888ac
76a91433bdb046a1d373728d7844df89aa24f788443a4588ac
'''

#need test vectors for each kind of detwallet


def test():
    xpub = ("xpub661MyMwAqRbcGVQTLtBFzc3ENvyZHoUEhWRdGwoqLZaf5wXP9VcDY2V" +
        "JV7usvsFLZz2RUTVhCVXYXc3S8zpLyAFbDFcfrpUiwLoE9VWH2yz")
    wal = parse_electrum_master_public_key(xpub)
    initial_count = 15
    gaplimit = 5
    spks = wal.get_scriptpubkeys(0, 0, initial_count)
    #for test, generate 15, check that the last 5 lead to gap limit overrun
    for i in range(initial_count - gaplimit):
        ret = wal.have_scriptpubkeys_overrun_gaplimit([spks[i]], gaplimit)
        assert ret == None
    for i in range(gaplimit):
        index = i + initial_count - gaplimit
        ret = wal.have_scriptpubkeys_overrun_gaplimit([spks[index]], gaplimit)
        assert ret != None and ret[0] == i+1
    last_index_add = 3
    last_index = initial_count - gaplimit + last_index_add
    ret = wal.have_scriptpubkeys_overrun_gaplimit(spks[2:last_index], gaplimit)
    assert ret[0] == last_index_add
    print("Test passed successfully")

if __name__ == "__main__":
    test()
