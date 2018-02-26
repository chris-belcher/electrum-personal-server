
import bitcoin as btc
import hashlib, binascii
from math import ceil, log

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

def address_to_script(addr, rpc):
    return rpc.call("validateaddress", [addr])["scriptPubKey"]

def address_to_scripthash(addr, rpc):
    return script_to_scripthash(address_to_script(addr, rpc))

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

def calc_tree_width(height, txcount):
    return (txcount + (1 << height) - 1) >> height

#follow the flags down into the tree, building up the datastructure
def decend_merkle_tree(hashes, flags, height, txcount, pos):
    flag = next(flags)
    print("f=" + str(flag) + " height=" + str(height) + " txc=" +
        str(txcount) + " pos=" + str(pos) + " width=" +
        str(calc_tree_width(height, txcount)))
    if height > 0:
        #non-txid node
        if flag:
            left = decend_merkle_tree(hashes, flags, height-1, txcount, pos*2)
            #bitcoin has a rule that if theres an odd number of nodes in
            # the merkle tree, the last hash is duplicated
            #in the electrum format we must hash together the duplicate
            # tree branch
            if pos*2+1 < calc_tree_width(height-1, txcount):
                right = decend_merkle_tree(hashes, flags, height-1,
                    txcount, pos*2+1)
            else:
                if isinstance(left, tuple):
                    right = expand_tree_hashing(left)
                else:
                    right = left
            return (left, right)
        else:
            hs = next(hashes)
            #hs = hs[:4] + '...' + hs[-4:]
            #print(hs)
            return hs
    else:
        #txid node
        hs = next(hashes)
        #hs = hs[:4] + '...' + hs[-4:]
        #print(hs)
        if flag:
            return "tx:" + str(pos) + ":" + hs
        else:
            return hs

def deserialize_core_format_merkle_proof(hash_list, flag_value, txcount):
    tree_depth = int(ceil(log(txcount, 2)))
    hashes = iter(hash_list)
    #one-liner which converts the flags value to a list of True/False bits
    flags = (flag_value[i//8]&1 << i%8 != 0 for i in range(len(flag_value)*8))
    try:
        root_node = decend_merkle_tree(hashes, flags, tree_depth, txcount, 0)
        return root_node
    except StopIteration:
        raise ValueError

#recurse down into the tree, adding hashes to the result list in depth order
def expand_tree_electrum_format(node, result):
    left, right = node
    if isinstance(left, tuple):
        expand_tree_electrum_format(left, result)
    if isinstance(right, tuple):
        expand_tree_electrum_format(right, result)
    if not isinstance(left, tuple):
        result.append(left)
    if not isinstance(right, tuple):
        result.append(right)

def deserialize_hash_node(node):
    if node.startswith("tx"):
        return node.split(":")[2]
    else:
        return node

#recurse down into the tree, hashing everything and returning root hash
def expand_tree_hashing(node):
    left, right = node
    if isinstance(left, tuple):
        hash_left = expand_tree_hashing(left)
    else:
        hash_left = deserialize_hash_node(left)
    if isinstance(right, tuple):
        hash_right = expand_tree_hashing(right)
    else:
        hash_right = deserialize_hash_node(right)
    return hash_encode(Hash(hash_decode(hash_left) + hash_decode(hash_right)))

#https://github.com/bitcoin/bitcoin/blob/master/src/merkleblock.h
#https://github.com/breadwallet/breadwallet-core/blob/master/BRMerkleBlock.c
def convert_core_to_electrum_merkle_proof(proof):
    proof = binascii.unhexlify(proof)
    pos = [0]
    def read_as_int(bytez):
        pos[0] += bytez
        return btc.decode(proof[pos[0] - bytez:pos[0]][::-1], 256)
    def read_var_int():
        pos[0] += 1
        val = btc.from_byte_to_int(proof[pos[0] - 1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))
    def read_bytes(bytez):
        pos[0] += bytez
        return proof[pos[0] - bytez:pos[0]]

    pos[0] = 80
    txcount = read_as_int(4)
    hash_count = read_var_int()
    hashes = [binascii.hexlify(read_bytes(32)[::-1]).decode()
        for i in range(hash_count)]
    flags_count = read_var_int()
    flags = read_bytes(flags_count)

    print(hashes)
    print([flags[i//8]&1 << i%8 != 0 for i in range(len(flags)*8)])
    print(txcount)

    root_node = deserialize_core_format_merkle_proof(hashes, flags, txcount)
    print(root_node)
    hashes_list = []
    expand_tree_electrum_format(root_node, hashes_list)

    #remove the first or second element which is the txhash
    tx = hashes_list[0]
    if hashes_list[1].startswith("tx"):
        tx = hashes_list[1]
    assert(tx.startswith("tx"))
    hashes_list.remove(tx)
    #if the txhash was duplicated, that is included in electrum's format
    if hashes_list[0].startswith("tx"):
        hashes_list[0] = tx.split(":")[2]
    pos, txid = tx.split(":")[1:3]
    pos = int(pos)
    blockhash = binascii.hexlify(btc.bin_dbl_sha256(proof[:80])[::-1])
    result = {"pos": pos, "merkle": hashes_list, "txid": txid,
        "blockhash": blockhash.decode()}
    return result

merkle_test_vectors = [
    {'coreproof':
        "0300000026e696fba00f0a43907239305eed9e55824e0e376636380f00000000000" + 
        "000004f8a2ce51d6c69988029837688cbfc2f580799fa1747456b9c80ab808c1431" + 
        "acd0b07f5543201618cadcfbf7330300000b0ff1e0050fed22ca360e0935e053b0f" + 
        "e098f6f9e090f5631013361620d964fe2fd88544ae10b40621e1cd24bb4306e3815" + 
        "dc237f77118a45d75ada9ee362314b70573732bce59615a3bcc1bbacd04b33b7819" + 
        "198212216b5d62d75be59221ada17ba4fb2476b689cccd3be54732fd5630832a94f" + 
        "11fa3f0dafd6f904d43219e0d7de110158446b5b598bd241f7b5df4da0ebc7d30e7" + 
        "748d487917b718df51c681174e6abab8042cc7c1c436221c098f06a56134f9247a8" + 
        "12126d675d69c82ba1c715cfc0cde462fd1fbe5dc87f6b8db2b9c060fcd59a20e7f" + 
        "e8e921c3676937a873ff88684f4be4d015f24f26af6d2cf78335e9218bcceba4507" + 
        "d0b4ba6cb933aa01ef77ae5eb411893ec0f74b69590fb0f5118ac937c02ccd47e9d" + 
        "90be78becd11ecf854d7d268eeb479b74d137278c0a5017d29e90cd5b35a4680201" + 
        "824fb0eb4f404e20dfeaec4d50549030b7e7e220b02eb2105f3d2e8bcc94d547214" + 
        "a9d03ff1600",
    'electrumproof':
        {'pos': 5, 'merkle': [
        '4b3162e39eda5ad7458a11777f23dc15386e30b44bd21c1e62400be14a5488fd',
        'e01932d404f9d6af0d3ffa114fa9320863d52f7354bed3cc9c686b47b24fba17',
        'e24f960d6261330131560f099e6f8f09feb053e035090e36ca22ed0f05e0f10f',
        '681cf58d717b9187d448770ed3c7eba04ddfb5f741d28b595b6b44580111ded7',
        'a12bc8695d676d1212a847924f13566af098c02162431c7ccc4280ababe67411',
        '7a9376361c928efee7209ad5fc60c0b9b28d6b7fc85dbe1ffd62e4cdc0cf15c7',
        '33b96cbab4d00745bacebc18925e3378cfd2f66af2245f014dbef48486f83f87',
        'ec8be70bd9e947cd2cc037c98a11f5b00f59694bf7c03e8911b45eae77ef01aa',
        'b04f82010268a4355bcd909ed217500a8c2737d1749b47eb8e267d4d85cf1ed1',
        '9d4a2147d594cc8b2e3d5f10b22eb020e2e7b7309054504deceadf204e404feb'],
        'txid':
        'da1a2259be752dd6b5162221989181b7334bd0acbbc1bca31596e5bc32375770',
        'blockhash':
        "000000000000000014491e51be24278716c24d12ec0dbadf8c5f04f7f1846f5a"}
    },
    {"coreproof":
        "0100000053696a625fbd16df418575bce0c4148886c422774fca5fcab8010000000" + 
        "000001532bfe4f9c4f56cd141028e5b59384c133740174b74b1982c7f01020b90ce" + 
        "05577c67508bdb051a7ec2ef942f000000076cde2eb7efa90b36d48aed612e559ff" + 
        "2ba638d8d400b14b0c58df00c6a6c33b65dc8fa02f4ca56e1f4dcf17186fa9bbd99" + 
        "0ce150b6e2dc9e9e56bb4f270fe56fde6bdd73a7a7e82767714862888e6b759568f" + 
        "b117674ad23050e2931197494d457efb72efdb9cb79cd4a435724908a0eb31ec7f7" + 
        "a67ee03837319e098b43edad3be9af75ae7b30db6f4f93ba0fdd941fdf70fe8cc38" + 
        "982e03bd292f5bd02f28137d343f908c7d6417379afe8349a257af3ca1f74f623be" + 
        "6a416fe1aa96a8f259983f2cf32121bce203955a378b3b44f132ea6ab94c7829a6c" + 
        "3b360c9f8da8e74027701",
    "electrumproof":
        {'pos': 9, 'merkle': [
        '6fe50f274fbb569e9edce2b650e10c99bd9bfa8671f1dcf4e156caf402fac85d',
        'aded438b099e313738e07ea6f7c71eb30e8a902457434acd79cbb9fd2eb7ef57',
        '81f202bdf592d23be08289c38cfe70df1f94dd0fba934f6fdb307bae75afe93b',
        'b6336c6a0cf08dc5b0140b408d8d63baf29f552e61ed8ad4360ba9efb72ede6c',
        '59f2a896aae16f416abe23f6741fcaf37a259a34e8af797341d6c708f943d337',
        '748edaf8c960b3c3a629784cb96aea32f1443b8b375a9503e2bc2121f32c3f98'],
        'txid':
        'd494741931290e0523ad747611fb6895756b8e886248716727e8a7a773dd6bde',
        "blockhash":
        "000000000000028113c80cc4be7058ab80a7767329d0253558d81d709f62ca40"}
    },
    {"coreproof":
        "000000206365d5e1d8b7fdf0b846cfa902115c1b8ced9dd49cb1780000000000000" + 
        "000001032e829e1f9a5a09d0492f9cd3ec0762b7facea555989c3927d3d975fd407" + 
        "8c7718495a45960018edd3b9e0160a00000dfe856a7d5d77c23ebf85c68b5eb303d" + 
        "85e56491ed6d204372625d0b4383df5a44d6e46d2db09d936b9f5d0b53e0dbcb3ef" + 
        "b7773d457369c228fd1ce6e11645e366a58b3fc1e8a7c916710ce29a87265a6729a" + 
        "3b221b47ea9c8e6f48707b112b8d67e5cfb3db5f88b042dc49e4e5bc2e61c28e1e0" + 
        "fbcba4c741bb5c75cac58ca04161a7377d70f3fd19a3e248ed918c91709b49afd37" + 
        "60f89ed2fefbcc9c23447ccb40a2be7aba22b07189b0bf90c62db48a9fe37227e12" + 
        "c7af8c1d4c22f9f223530dacdd5f3ad850ad4badf16cc24049a65334f59bf28c15c" + 
        "ecda1a4cf3f2937bd70ee84f66569ce8ef951d50cca46d60337e6c697685b38ad21" + 
        "7967bbe6801d03c44fcb808cd035be31888380a2df1be14b6ff100de83cab0dce25" + 
        "0e2b40ca3b47e8309f848646bee63b6185c176d84f1546a482e7a65a87d1a2d0d5a" + 
        "2b683e2cae0520df1e3525a71d71e1f551abd7d238c3bcb4ecaeea7d5988745fa42" + 
        "1a8604a99857426957a2ccfa7cd8df145aa8293701989dd207505923fcb33984394" + 
        "4ce3d21dc259bcda9c251ed90d4e55af2cf5b15432050084f513ac74c0bdd4b6046" + 
        "fb70100",
    "electrumproof":
        {'pos': 330, 'merkle': [
        '23f2f9224c1d8cafc7127e2237fea948db620cf90b9b18072ba2abe72b0ab4cc',
        'a08cc5ca755cbb41c7a4cbfbe0e1281ce6c25b4e9ec42d048bf8b53dfb5c7ed6',
        '37293fcfa4a1cdce158cf29bf53453a64940c26cf1ad4bad50d83a5fddac0d53',
        'b812b10787f4e6c8a97eb421b2a329675a26879ae20c7116c9a7e8c13f8ba566',
        '1d80e6bb677921ad385b6897c6e63703d646ca0cd551f98ece6965f684ee70bd',
        'a30cb4e250e2dcb0ca83de00f16f4be11bdfa280838831be35d08c80cb4fc403',
        'e34516e1e61cfd28c26973453d77b7efb3bc0d3eb5d0f5b936d909dbd2466e4d',
        '3e682b5a0d2d1a7da8657a2e486a54f1846d175c18b663ee6b6448f809837eb4',
        'a4f53d38b4d025263704d2d61e49565ed803b35e8bc685bf3ec2775d7d6a85fe',
        'a821a45f7488597deaaeecb4bcc338d2d7ab51f5e1711da725351edf2005ae2c',
        '94439833cb3f92057520dd8919709382aa45f18dcda7cf2c7a95267485994a60',
        'b6d4bdc074ac13f58400053254b1f52caf554e0dd91e259cdabc59c21dd2e34c'],
        'txid':
        '4734c2c9bcef2fed890f76d3af499b70918c91ed48e2a319fdf3707d37a76141',
        "blockhash":
        "00000000000000000035c1e0b8f6c7886a5d41b685c4f0094a5b91759a5fe235"}
    }
]

#response electrum3.hachre.de {'result': {'pos': 2860, 'block_height': 503961, 'merkle': ['590e0d07c8d33b0453748d1034d3fd4e779e1e78a2c8ef20c2e66830a6d4230d', '0f1d4d6aaa71beaf8d30b7df3cd776ece4bcd1169d1550e8abfb2b3053388ac8', 'cbd44606e7d8ca49ccaa409a51b60854d6e31534c5c6315a257ef571f1398db3', '7d4d426bb8a3b5146b0c35845b7e12dc7bcd7f44c570ff712632d0d86b695cbd', '20e5e6a7eb7cf42e4d3a9ac803f160973b10da3da74d68afb8bfef04d9a46d85', '9032b3b57d81862168733b5a6b6370eaeafb4aaaea5023bf4cf3a998f8ca67e2', 'a16ed5aa6bab2c9b64e91f033aa1fdffa44270f0907aeb8eedd31840514f8f26', 'a53a1448437ac49c9f560f3e5c4a769c6295df2a04242b713d1f0747d90a8fe4', '6922f4bd74e95ae28fcd71c35dfb95e4551876ba78cb828cbc863870b34add53', 'bf152261c5f22dc73cb2fe5ee85984f0c8d71ab8db28bd0e39931f43d6766f1e', '2cbe3c851f5a58e2a407bf38bb829fde76e4fd22005b5c3124d3eff4de55c3a5', '0b7ceffc6a25d3b3c0619fd2d254881e8987f9182c3fb12bf5db14311cd7208d']}, 'method': 'blockchain.transaction.get_merkle', 'id': 32, 'jsonrpc': '2.0', 'params': ['590e0d07c8d33b0453748d1034d3fd4e779e1e78a2c8ef20c2e66830a6d4230d', 503961]}
#proof = "00000020c656c90b521a2bbca14174f2939b882a28d23d86144b0e000000000000000000cf5185a8e369c3de5f15e039e777760994fd66184b619d839dace3aec9953fd6d861595ac1910018ee097a972d0b0000078d20d71c3114dbf52bb13f2c18f987891e8854d2d29f61c0b3d3256afcef7c0b1e6f76d6431f93390ebd28dbb81ad7c8f08459e85efeb23cc72df2c5612215bf53dd4ab3703886bc8c82cb78ba761855e495fb5dc371cd8fe25ae974bdf42269e267caf898a9f34cbf2350eaaa4afbeaea70636b5a3b73682186817db5b33290bd5c696bd8d0322671ff70c5447fcd7bdc127e5b84350c6b14b5a3b86b424d7db38d39f171f57e255a31c6c53415e3d65408b6519a40aacc49cad8e70646d4cb0d23d4a63068e6c220efc8a2781e9e774efdd334108d7453043bd3c8070d0e5903ad5b07"

#has 7 txes, duplicated entry in the last depth, at tx level
# 0000000000007d1bdd2cfd23ffb3c2bae3143772bd6577aecae9c6b29f88c2af
#lasttx c40bbed8f34cb1c24660e2e0cb51e09a180f1ab97037265293fceab88247bccf
#addr 15dcVuX7UT4fB74dikaAE4MXhCTkFZpV8F
#response electrum3.hachre.de {'id': 33, 'params': ['c40bbed8f34cb1c24660e2e0cb51e09a180f1ab97037265293fceab88247bccf', 120013], 'result': {'block_height': 120013, 'pos': 6, 'merkle': ['c40bbed8f34cb1c24660e2e0cb51e09a180f1ab97037265293fceab88247bccf', 'ad69c91b8e9b7122dc2a2575cfa12a36de05595e0e8f59092d04b263b4c8f70f', '8ae24d1f1c3b0d65ec88f8c84cad7e02e98b26d7ad566bf3653158b72ebb3acd']}, 'jsonrpc': '2.0', 'method': 'blockchain.transaction.get_merkle'}
#proof = "0100000056e02c6d3278c754e0699517834741f7c4ad3dcbfeb7803a3462000000000000af3bdd5dd465443fd003e9281455e60aae573dd4d46304d7ba17276ea33d506488cbb44dacb5001b9ebb193b0700000003cd3abb2eb7583165f36b56add7268be9027ead4cc8f888ec650d3b1c1f4de28a0ff7c8b463b2042d09598f0e5e5905de362aa1cf75252adc22719b8e1bc969adcfbc4782b8eafc9352263770b91a0f189ae051cbe0e26046c2b14cf3d8be0bc40135"

#has 6 txes, duplicated entry in the last-but-one depth
# 00000000000005163d8d16192985a3f2d0f6f44e668ad05b26f7edcd3385a37f
# last tx eaefedc6dbb37223c771d8ccbbe4dac9e9d646ab90f17e387b63c866fad6e2c3
# addr 1NwNmR7sd6NqxXBJMXrwt9yUms29pSDmm
#response electrum3.hachre.de {'jsonrpc': '2.0', 'id': 33, 'method': 'blockchain.transaction.get_merkle', 'result': {'pos': 5, 'block_height': 150106, 'merkle': ['1f12a4c866548ab51766172f97a6741fbd62834ddfcadba249909ea8150eca88', 'f5a5aa78bd1f1ee5de900b7d1928864912425b67ece4a07e40af8eeb86f10d94', 'd52e599bc0ecc5e17bcb1e7539b61586c7457170923eab6d36243995ed452bf5']}, 'params': ['eaefedc6dbb37223c771d8ccbbe4dac9e9d646ab90f17e387b63c866fad6e2c3', 150106]}
proof = "01000000299edfd28524eae4fb6012e4087afdb6e1b912db85e612374b03000000000000e16572394f8578a47bf36e15cd16faa5e3b9e18805cf4e271ae4ef95aa8cea7eb31fa14e4b6d0b1a42857d960600000003f52b45ed953924366dab3e92707145c78615b639751ecb7be1c5ecc09b592ed588ca0e15a89e9049a2dbcadf4d8362bd1f74a6972f176617b58a5466c8a4121fc3e2d6fa66c8637b387ef190ab46d6e9c9dae4bbccd871c72372b3dbc6edefea012d"
'''
ix = 1
try:
    #proof = merkle_test_vectors[ix]['coreproof']
    merkleproof = convert_core_to_electrum_merkle_proof(proof)
    print(merkleproof)
except ValueError:
    print("valueerror")
'''
#the function electrum uses to verify merkle branches is in verifer.py called hash_merkle_root()

'''
h1 = b"1f12a4c866548ab51766172f97a6741fbd62834ddfcadba249909ea8150eca88"
h2 = b"eaefedc6dbb37223c771d8ccbbe4dac9e9d646ab90f17e387b63c866fad6e2c3"
h1 = binascii.unhexlify(h1)[::-1]
h2 = binascii.unhexlify(h2)[::-1]
print(btc.dbl_sha256(h2 + h1))

merkle_s = {'pos': 5, 'block_height': 150106, 'merkle':
['1f12a4c866548ab51766172f97a6741fbd62834ddfcadba249909ea8150eca88',
'f5a5aa78bd1f1ee5de900b7d1928864912425b67ece4a07e40af8eeb86f10d94',
'd52e599bc0ecc5e17bcb1e7539b61586c7457170923eab6d36243995ed452bf5']}
'''


'''
ix = 1
electrumproof = merkle_test_vectors[ix]['electrumproof']
print("txid = " + electrumproof['txid'])
print("mkpf = " + hash_merkle_root(electrumproof["merkle"],
    electrumproof['txid'], electrumproof["pos"]))
'''


'''
    merkle_test_vectors[ix]['coreproof'])
assert(merkleproof['pos'] ==
    merkle_test_vectors[ix]["electrumproof"]["pos"])
assert(merkleproof['blockhash'] ==
    merkle_test_vectors[ix]["electrumproof"]["blockhash"])
assert(len(merkleproof["merkle"]) ==
    len(merkle_test_vectors[ix]["electrumproof"]["merkle"]))
for i in range(len(merkleproof["merkle"])):
    assert(merkleproof["merkle"][i] ==
        merkle_test_vectors[ix]["electrumproof"]["merkle"][i])
'''

'''
def chunks(d, n):
    return [d[x:x + n] for x in range(0, len(d), n)]

print(merkleproof)
print("\" + \n\"".join(chunks(proof, 67)))
'''


#has 15
# 000000000000b2847f688808836c3905fab245cf8081befb11d1422ad59be780
#should get a block with 13 txes
#get a block with 1tx, only the coinbase

'''
print(address_to_scripthash(addr))
print(spkhash + " should be")

print(get_status([(txhash, txheight)]))
print(history_hash + " should be")

print(get_status([(r['tx_hash'], r['height']) for r in history['result']]))
print(history_status + " should be")
'''
