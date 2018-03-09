
import bitcoin as btc
import util

#the wallet types are here
#https://github.com/spesmilo/electrum/blob/3.0.6/RELEASE-NOTES
#and
#https://github.com/spesmilo/electrum-docs/blob/master/xpub_version_bytes.rst

def parse_electrum_master_public_key(keydata, gaplimit):
    if keydata[:4] in ("xpub", "tpub"):
        return SingleSigP2PKHWallet(keydata, gaplimit)
    elif keydata[:4] in ("zpub", "vpub"):
        return SingleSigP2WPKHWallet(keydata, gaplimit)
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
            return MultisigP2SHWallet(m, pubkeys, gaplimit)
        if pubkeys[0][:4] in("Zpub", "Vpub"):
            return MultisigP2WSHWallet(m, pubkeys, gaplimit)
    else:
        raise ValueError("Unrecognized electrum mpk format: " + keydata[:4])

class DeterministicWallet(object):
    def __init__(self, gaplimit):
        self.gaplimit = gaplimit
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
    def __init__(self, mpk, gaplimit):
        super(SingleSigWallet, self).__init__(gaplimit)
        self.branches = (btc.bip32_ckd(mpk, 0), btc.bip32_ckd(mpk, 1))
        #m/change/i

    def pubkey_to_scriptpubkey(self, pubkey):
        raise RuntimeError()

    def get_scriptpubkeys(self, change, from_index, count):
        result = []
        for index in range(from_index, from_index + count):
            pubkey = btc.bip32_extract_key(btc.bip32_ckd(self.branches[change],
                index))
            scriptpubkey = self.pubkey_to_scriptpubkey(pubkey)
            self.scriptpubkey_index[scriptpubkey] = (change, index)
            result.append(scriptpubkey)
        self.next_index[change] = max(self.next_index[change], from_index+count)
        return result

class SingleSigP2PKHWallet(SingleSigWallet):
    def pubkey_to_scriptpubkey(self, pubkey):
        pkh = util.bh2u(util.hash_160(util.bfh(pubkey)))
        #op_dup op_hash_160 length hash160 op_equalverify op_checksig
        return "76a914" + pkh + "88ac"

class SingleSigP2WPKHWallet(SingleSigWallet):
    def pubkey_to_scriptpubkey(self, pubkey):
        pkh = util.bh2u(util.hash_160(util.bfh(pubkey)))
        #witness-version length hash160
        #witness version is always 0, length is always 0x14
        return "0014" + pkh

class MultisigWallet(DeterministicWallet):
    def __init__(self, m, mpk_list, gaplimit):
        super(MultisigWallet, self).__init__(gaplimit)
        self.m = m
        self.pubkey_branches = [(btc.bip32_ckd(mpk, 0), btc.bip32_ckd(mpk, 1))
            for mpk in mpk_list]
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
        sh = util.bh2u(util.hash_160(util.bfh(redeem_script)))
        return "a914" + sh + "87"
        #op_hash160 length hash160 op_equal

class MultisigP2WSHWallet(MultisigWallet):
    def redeem_script_to_scriptpubkey(self, redeem_script):
        sh = util.bh2u(util.sha256(util.bfh(redeem_script)))
        return "0020" + sh
        #witness-version length sha256
        #witness version is always 0, length is always 0x20

electrum_keydata_test_vectors = [
    #p2pkh wallet
    ("xpub661MyMwAqRbcGVQTLtBFzc3ENvyZHoUEhWRdGwoqLZaf5wXP9VcDY2VJV7usvsFLZz" +
    "2RUTVhCVXYXc3S8zpLyAFbDFcfrpUiwLoE9VWH2yz", #pubkey
    ["76a914b1847c763c9a9b12631ab42335751c1bf843880c88ac" #recv scriptpubkeys
    ,"76a914d8b6b932e892fad5132ea888111adac2171c5af588ac"
    ,"76a914e44b19ef74814f977ae4e2823dd0a0b33480472a88ac"],
    ["76a914d2c2905ca383a5b8f94818cb7903498061a6286688ac" #change scriptpubkeys
    ,"76a914e7b4ddb7cede132e84ba807defc092cf52e005b888ac"
    ,"76a91433bdb046a1d373728d7844df89aa24f788443a4588ac"])
    , #p2wpkh wallet
    ("zpub6mr7wBKy3oJn89TCiXUAPBWpTTTx58BgEjPLzDNf5kMThvd6xchrobPTsJ5mP" +
    "w3NJ7zRhckN8cv4FhQBfwurZzNE5uTW5C5PYqNTkRAnTkP", #pubkey
    ['00142b82c61a7a48b7b10801f0eb247af46821bd33f5' #recv scriptpubkeys
    ,'0014073dc6bcbb18d6468c5996bdeba926f6805b74b1'
    ,'001400fa0b5cb21e8d442a7bd61af3d558a62be0c9aa'],
    ['00144f4a0655a4b586be1e08d97a2f55125120b84c69' #change scriptpubkeys
    ,'0014ef7967a7a56c23bbc9f317e612c93a5e23d25ffe'
    ,'0014ad768a11730bf54d10c72184d53239de0f310bc9'])
    ,#p2sh 2of2 multisig wallet
    ("2 tpubD6NzVbkrYhZ4YVMVzC7wZeRfz3bhqcHvV8M3UiULCfzFtLtp5nwvi6LnBQegrkx" +
    "YGPkSzXUEvcPEHcKdda8W1YShVBkhFBGkLxjSQ1Nx3cJ tpubD6NzVbkrYhZ4WjgNYq2nF" +
    "TbiSLW2SZAzs4g5JHLqwQ3AmR3tCWpqsZJJEoZuP5HAEBNxgYQhtWMezszoaeTCg6FWGQB" +
    "T74sszGaxaf64o5s", #m=2, 2 pubkeys, n=len(pubkeys)
    ['a914fe30a46a4e1b41f9bb758448fd84ee4628c103e187' #recv
    ,'a914dad5dd605871560ae5d219cd6275e6ad19bc6b9987'
    ,'a914471e158e2db190acdd8c76ed6d2ade102fe1e8ac87'
    ,'a914013449715a32f21d1a8a2b95a01b40eb41ada16f87'
    ,'a914ae3dd25567fb7c2f87be41220dd14025ca68b0e087'
    ,'a91462b90344947b610c4eadb7dd460fee3f32fefe7687'
    ,'a914d4388c7d5771ebf26b6e650c42e60e4cf7d4c5a187'
    ,'a914e4f0832e56591d01b71c72b9a3777dc8f9d9a92e87'
    ,'a914a5d5accd96d27403c7663b92fdb57299d7a871eb87'
    ,'a914f8f2c6ef2d80f972e4d8b418a15337a3c38af37f87'
    ,'a914a2bd2f67fac7c24e609b574ccc8cfaa2f90ebf8c87'
    ,'a914a56298a7decde1d18306f55d9305577c3fce690187'
    ,'a91430f2f83238ac29125a539055fa59efc86a73a23987'
    ,'a914263b4585d0735c5065987922af359d5eabeb880d87'
    ,'a91455d9d47113fb8b37705bdf6d4107d438afd63e4687'
    ,'a914970d754163b8957b73f4e8baaf23dea5f6e3db2287'
    ,'a914facbc921203a9ffd751cc246a884918beaac21b687'
    ,'a914fc7556833eca1e0f84c6d7acb875e645f7ed4e9687'
    ,'a914bbfe6a032d633f113b5d605e3a97cc08a47cc87d87'
    ,'a91403d733c4ca337b5fa1de95970ba6f898a9d36c4887'
    ,'a9148af27dc7c950e17c11e164065e672cd60ae3d48d87'
    ,'a914c026aa45377f2a4a62136bac1d3350c318fee5c587'
    ,'a9146337f59e3ea55e73725c9f2fc52a5ca5d68c361687'],
    ['a914aeaebf9d567ab8a6813e89668e16f40bf419408e87' #change
    ,'a914f2a6264dd3975297fa2a5a8e17321299a44f76d987'
    ,'a9142067a6c47958090a645137cc0898c0c7bbc69b5387'
    ,'a914210840f77ea5b7eb11cb55e5d719a93b7746fb9387'
    ,'a914163db6b8ca00362be63a26502c5f7bf64787506b87'
    ,'a91479b2c527594059c056e5367965ae92bbcf63512187'])
    ,#p2sh 2of3 multisig wallet
    ("2 tpubD6NzVbkrYhZ4WwaMJ3od4hANxdMVpb63Du3ERq1xjtowxVJEcTbGH2rFd9TFXxw" +
    "KJRKDn9vQjDPxFeaku6BHW6wHn2KPF1ijS4LwgwQFJ3B tpubD6NzVbkrYhZ4Wjv4ZRPD6" +
    "MNdiLmfvXztbKuuatkqHjukU3S6GXhmKnbAF5eU9bR2Nryiq8v67emUUSM1VUrAx5wcZ19" +
    "AsaGg3ZLmjbbwLXr tpubD6NzVbkrYhZ4Xxa2fEp7YsbnFnwuQNaogijbiX42Deqd4NiAD" +
    "tqNU6AXCU2d2kPFWBpAGG7K3HAKYwUfZBPgTLkfQp2dDg9SLVnkgYPgEXN",
    ['a914167c95beb25b984ace517d4346e6cdbf1381793687', #recv addrs
     'a914378bbda1ba7a713de18c3ba3c366f42212bfb45087',
     'a9142a5c9881c70906180f37dd02d8c830e9b6328d4a87',
     'a914ffe0832375b72ee5307bfa502896ba28cc470ee987',
     'a9147607d40e039fbea57d9c04e48b198c9fcf3356c187',
     'a9148d9582ad4cf0581c6e0697e4cba6a12e66ca1a0087',
     'a914d153a743b315ba19690823119019e16e3762104d87',
     'a914b4accc89e48610043e70371153fd8cb5a3eef34287',
     'a91406febca615e3631253fd75a1d819436e1d046e0487',
     'a914b863cbb888c6b28291cb87a2390539e28be37a9587',
     'a914ec39094e393184d2c352a29b9d7a3caddaccb6cf87',
     'a914da4faa4babbdf611caf511d287133f06c1c3244a87',
     'a9146e64561d0c5e2e9159ecff65db02e04b3277402487',
     'a914377d66386972492192ae827fb2208596af0941d187',
     'a914448d364ff2374449e57df13db33a40f5b099997c87',
     'a914f24b875d2cb99e0b138ab0e6dd65027932b3c6e787',
     'a914aa4bcee53406b1ef6c83852e3844e38a3a9d9f3087',
     'a9145e5ec40fdab54be0d6e21107bc38c39df97e37fc87',
     'a9141de4d402c82f4e9b0e6b792b331232a5405ebd3f87',
     'a9148873ee280e51f9c64d257dd6dedc8712fd652cc687'],
    ['a9142cc87d7562a85029a57cc37026e12dab72223db287', #change
     'a91499f4aee0b274f0b3ab48549a2c58cd667a62c0cb87',
     'a91497a89cd5ada3a766a1275f8151e9256fcf537f6c87',
     'a9147ffc9f3a3b60635ea1783243274f4d07ab617cb487',
     'a9143423113ab913d86fd47e55488a0c559e18b457b987',
     'a914a28a3773a37c52ff6fd7dff497d0eaf80a46febb87'])
    , #p2wsh 1of2 multisig wallet
    ("1 Vpub5fAqpSRkLmvXwqbuR61MaKMSwj5z5xUBwanaz3qnJ5MgaBDpFSLUvKTiNK9zHp" +
    "dvrg2LHHXkKxSXBHNWNpZz9b1VqADjmcCs3arSoxN3F3r Vpub5fvEo4MUpbVs9sZqr45" +
    "zmRVEsTcQ49MA9m3MLht3XzdZvS9eMXLLu1H6TL1j2SMnykHqXNzG5ycMyQmFDvEE5B32" +
    "sP8TmRe6wW8HjBgMssh",
    #recv scriptpubkeys
    ['002031fbaa839e96fc1abaf3453b9f770e0ccfe2d8e3e990bb381fdcb7db4722986a',
     '0020820ae739b36f4feb1c299ced201db383bbcf1634e0071e489b385f43c2323761',
     '0020eff05f4d14aa1968a7142b1009aa57a6208fb01b212f8b8f7df63645d26a1292',
     '002049c6e17979dca380ffb66295d27f609bea2879d4f0b590c96c70ff12260a8721',
     '002002bf2430fc7ebc6fb27da1cb80e52702edcc62a29f65c997e5c924dcd98411bd',
     '0020c7a58dcf9633453ba12860b57c14af67d87d022be5c52bf6be7a6abdc295c6e0',
     '0020136696059a5e932c72f4f0a05fa7f52faf9b54f1b7694e15acce710e6cc9e89d',
     '0020c372e880227f35c2ee35d0724bf05cea95e74dcb3e6aa67ff15f561a29c0645d',
     '002095c705590e2b84996fa44bff64179b26669e53bbd58d76bb6bbb5c5498a981ce',
     '00207217754dae083c3c365c7e1ce3ad889ca2bd88e4f809cec66b9987adc390aa26',
     '0020bee30906450e099357cc96a1f472c1ef70089cd4a0cba96749adfe1c9a2f9e87',
     '0020b1838b3d5a386ad6c90eeae9a27a9b812e32ce06376f261dea89e405bc8209d9',
     '0020231a3d05886efff601f0702d4c8450dfcce8d6a4bd90f17f7ff76f5c25c632de',
     '002071220f3941b5f65aca90e464db4291cd5ea63f37fa858fd5b66d5019f0dbab0f',
     '0020fc3c7db9f0e773f9f9c725d4286ddcc88db9575c45b2441d458018150eb4ef10',
     '00209f037bfc98dee2fc0d3cca54df09b2d20e92a0133fa381a4dd74c49e4d0a89f5',
     '0020c9060d0554ba2ca92048e1772e806d796ba41f10bf6aee2653a9eba96b05c944',
     '0020a7cb1dd2730dba564f414ed8d9312370ff89c34df1441b83125cb4d97a96005a',
     '00209fddc9b4e070b887dec034ed74f15f62d075a3ac8cf6eb95a88c635e0207534c',
     '0020c48f9c50958ab8e386a8bd3888076f31d12e5cf011ff46cc83c6fadfe6d47d20',
     '0020a659f4621dca404571917e73dedb26b6d7c49a07dacbf15890760ac0583d3267'],
    #change scriptpubkeys
    ['002030213b5d3b6988b86aa13a9eaca08e718d51f32dc130c70981abb0102173c791',
     '002027bd198f9783a58e9bc4d3fdbd1c75cc74154905cce1d23c7bd3e051695418fe',
     '0020c1fd2cdebf120d3b1dc990dfdaca62382ff9525beeb6a79a908ddecb40e2162c',
     '00207a3e478266e5fe49fe22e3d8f04d3adda3b6a0835806a0db1f77b84d0ba7f79c',
     '002059e66462023ecd54e20d4dce286795e7d5823af511989736edc0c7a844e249f5',
     '0020bd8077906dd367d6d107d960397e46db2daba5793249f1f032d8d7e12e6f193c'])
]

electrum_bad_keydata_test_vectors = [
    "zpub661MyMwAqRbcGVQTLtBFzc3ENvyZHoUEhWRdGwoqLZaf5wXP9VcDY2VJV7usvsFLZz" +
    "2RUTVhCVXYXc3S8zpLyAFbDFcfrpUiwLoE9VWH2yz", #bad checksum
    "a tpubD6NzVbkrYhZ4YVMVzC7wZeRfz3bhqcHvV8M3UiULCfzFtLtp5nwvi6LnBQegrkx" +
    "YGPkSzXUEvcPEHcKdda8W1YShVBkhFBGkLxjSQ1Nx3cJ tpubD6NzVbkrYhZ4WjgNYq2nF" +
    "TbiSLW2SZAzs4g5JHLqwQ3AmR3tCWpqsZJJEoZuP5HAEBNxgYQhtWMezszoaeTCg6FWGQB" +
    "T74sszGaxaf64o5s", #unparsable m number
    "2 tpubD6NzVbkrYhZ4YVMVzC7wZeRfz3bhqcHvV8M3UiULCfzFtLtp5nwvi6LnBQegrkx" +
    "YGPkSzXUEvcPEHcKdda8W1YShVBkhFBGkLxjSQ1Nx3cJ Vpub5fAqpSRkLmvXwqbuR61M" +
    "aKMSwj5z5xUBwanaz3qnJ5MgaBDpFSLUvKTiNK9zHpdvrg2LHHXkKxSXBHNWNpZz9b1Vq" +
    "ADjmcCs3arSoxN3F3r" #inconsistent magic
]

def test():
    for keydata, recv_spks, change_spks in electrum_keydata_test_vectors:
        initial_count = 15
        gaplimit = 5
        wal = parse_electrum_master_public_key(keydata, gaplimit)
        spks = wal.get_scriptpubkeys(0, 0, initial_count)
        #for test, generate 15, check that the last 5 lead to gap limit overrun
        for i in range(initial_count - gaplimit):
            ret = wal.have_scriptpubkeys_overrun_gaplimit([spks[i]])
            assert ret == None
        for i in range(gaplimit):
            index = i + initial_count - gaplimit
            ret = wal.have_scriptpubkeys_overrun_gaplimit([spks[index]])
            assert ret != None and ret[0] == i+1
        last_index_add = 3
        last_index = initial_count - gaplimit + last_index_add
        ret = wal.have_scriptpubkeys_overrun_gaplimit(spks[2:last_index])
        assert ret[0] == last_index_add
        assert wal.get_scriptpubkeys(0, 0, len(recv_spks)) == recv_spks
        assert wal.get_scriptpubkeys(1, 0, len(change_spks)) == change_spks
    for keydata in electrum_bad_keydata_test_vectors:
        try:
            parse_electrum_master_public_key(keydata, 5)
            raised_error = False
        except (ValueError, Exception):
            raised_error = True
        assert raised_error
    print("All tests passed successfully")

if __name__ == "__main__":
    test()
    pass

