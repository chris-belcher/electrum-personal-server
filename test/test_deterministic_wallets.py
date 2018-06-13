
import pytest

from electrumpersonalserver import parse_electrum_master_public_key

# electrum has its own tests here
#https://github.com/spesmilo/electrum/blob/03b40a3c0a7dd84e76bc0d0ea2ad390dafc92250/lib/tests/test_wallet_vertical.py

@pytest.mark.parametrize(
    "master_public_key, recv_spks, change_spks",
    [
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
    , #p2wpkh-p2sh
    ("upub5E4QEumGPNTmSKD95TrYX2xqLwwvBULbRzzHkrpW9WKKCB1y9DEfPXDnUyQjLjmVs" +
    "7gSd7k5vRb1FoSb6BjyiWNg4arkJLaqk1jULzbwA5q",
    ["a914ae8f84a06668742f713d0743c1f54d248040e63387", #recv
     "a914c2e9bdcc48596b8cce418042ade72198fddf3cd987",
     "a914a44b6ad63ccef0ae1741eaccee99bf2fa83f842987",
     "a9148cf1c891d96a0be07893d0bddcf00ed5dad2c46e87",
     "a91414d677b32f2409f4dfb3073d382c302bcd6ed33587",
     "a9141b284bee7198d5134512f37ef60e4048864b4bd687"],
    ["a914a5aacff65860440893107b01912dc8f60cadab2b87", #change
     "a914dcd74ebc8bfc5cf0535717a3e833592d54b3c48687",
     "a91446793cae4c2b8149ade61c1627b96b90599bc08787",
     "a91439f3776831f321125bdb5099fbbd654923f8316c87"])
    , #p2wpkh-p2sh
    ("ypub6XrRLtXNB7NQo3vDaMNnffXVJe1WVaebXcb4ncpTHHADLuFYmf2CcPn96YzUbMt8s" +
    "HSMmtr1mCcMgCBLqNdY2hrXXcdiLxCdD9e2dChBLun",
    ["a91429c2ad045bbb162ef3c2d9cacb9812bec463061787", #recv
     "a91433ec6bb67b113978d9cfd307a97fd15bc0a5a62087",
     "a91450523020275ccbf4e916a0d8523ae42391ad988a87",
     "a91438c2e5e76a874d86cfc914fe9fc1868b6afb5c5487"],
    ["a91475f608698bb735120a17699fee854bce9a8dc8d387",
     "a91477e69344ef53587051c85a06a52a646457b44e6c87",
     "a914607c98ea34fbdffe39fee161ae2ffd5517bf1a5587"])
    , #old mnemonic mpk
    ("e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d" +
    "5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3",
    ["76a9149cd3dfb0d87a861770ae4e268e74b45335cf00ab88ac", #recv
     "76a914c30f2af6a79296b6531bf34dba14c8419be8fb7d88ac",
     "76a9145eb4eeaefcf9a709f8671444933243fbd05366a388ac",
     "76a914f96669095e6df76cfdf5c7e49a1909f002e123d088ac"],
    ["76a914ca14915184a2662b5d1505ce7142c8ca066c70e288ac", #change
     "76a9148942ac692ace81019176c4fb0ac408b18b49237f88ac",
     "76a914e1232622a96a04f5e5a24ca0792bb9c28b089d6e88ac"])
    , #p2wsh-p2sh 2of2 multisig
    ("2 Ypub6hWbqA2p47QgsLt5J4nxrR3ngu8xsPGb7PdV8CDh48KyNngNqPKSqertAqYhQ4u" +
    "mELu1UsZUCYfj9XPA6AdSMZWDZQobwF7EJ8uNrECaZg1 Ypub6iNDhL4WWq5kFZcdFqHHw" +
    "X4YTH4rYGp8xbndpRrY7WNZFFRfogSrL7wRTajmVHgR46AT1cqUG1mrcRd7h1WXwBsgX2Q" +
    "vT3zFbBCDiSDLkau",
    ["a91428060ade179c792fac07fc8817fd150ce7cdd3f987", #recv
     "a9145ba5ed441b9f3e22f71193d4043b645183e6aeee87",
     "a91484cc1f317b7d5afff115916f1e27319919601d0187",
     "a9144001695a154cac4d118af889d3fdcaf929af315787",
     "a914897888f3152a27cbd7611faf6aa01085931e542a87"],
    ["a91454dbb52de65795d144f3c4faeba0e37d9765c85687", #change
     "a914f725cbd61c67f34ed40355f243b5bb0650ce61c587",
     "a9143672bcd3d02d3ea7c3205ddbc825028a0d2a781987"])
    ]
)

def test_deterministic_wallets(master_public_key, recv_spks, change_spks):
    initial_count = 15
    gaplimit = 5
    wal = parse_electrum_master_public_key(master_public_key, gaplimit)
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

