
import bitcoin as btc
import binascii
from math import ceil, log

from hashes import hash_encode, hash_decode, Hash, hash_merkle_root

#lots of ideas and code taken from bitcoin core and breadwallet
#https://github.com/bitcoin/bitcoin/blob/master/src/merkleblock.h
#https://github.com/breadwallet/breadwallet-core/blob/master/BRMerkleBlock.c

def calc_tree_width(height, txcount):
    """Efficently calculates the number of nodes at given merkle tree height"""
    return (txcount + (1 << height) - 1) >> height

def decend_merkle_tree(hashes, flags, height, txcount, pos):
    """Function recursively follows the flags bitstring down into the
       tree, building up a tree in memory"""
    flag = next(flags)
    if height > 0:
        #non-txid node
        if flag:
            left = decend_merkle_tree(hashes, flags, height-1, txcount, pos*2)
            #bitcoin's merkle tree format has a rule that if theres an
            # odd number of nodes in then the tree, the last hash is duplicated
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
            return hs
    else:
        #txid node
        hs = next(hashes)
        if flag:
            #for the actual transaction, also store its position with a flag 
            return "tx:" + str(pos) + ":" + hs
        else:
            return hs

def deserialize_core_format_merkle_proof(hash_list, flag_value, txcount):
    """Converts core's format for a merkle proof into a tree in memory"""
    tree_depth = int(ceil(log(txcount, 2)))
    hashes = iter(hash_list)
    #one-liner which converts the flags value to a list of True/False bits
    flags = (flag_value[i//8]&1 << i%8 != 0 for i in range(len(flag_value)*8))
    try:
        root_node = decend_merkle_tree(hashes, flags, tree_depth, txcount, 0)
        return root_node
    except StopIteration:
        raise ValueError

def expand_tree_electrum_format_merkle_proof(node, result):
    """Recurse down into the tree, adding hashes to the result list
       in depth order"""
    left, right = node
    if isinstance(left, tuple):
        expand_tree_electrum_format_merkle_proof(left, result)
    if isinstance(right, tuple):
        expand_tree_electrum_format_merkle_proof(right, result)
    if not isinstance(left, tuple):
        result.append(left)
    if not isinstance(right, tuple):
        result.append(right)

def get_node_hash(node):
    if node.startswith("tx"):
        return node.split(":")[2]
    else:
        return node

def expand_tree_hashing(node):
    """Recurse down into the tree, hashing everything and
       returning root hash"""
    left, right = node
    if isinstance(left, tuple):
        hash_left = expand_tree_hashing(left)
    else:
        hash_left = get_node_hash(left)
    if isinstance(right, tuple):
        hash_right = expand_tree_hashing(right)
    else:
        hash_right = get_node_hash(right)
    return hash_encode(Hash(hash_decode(hash_left) + hash_decode(hash_right)))

def convert_core_to_electrum_merkle_proof(proof):
    """Bitcoin Core and Electrum use different formats for merkle
       proof, this function converts from Core's format to Electrum's format"""
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

    merkle_root = proof[36:36+32]
    pos[0] = 80
    txcount = read_as_int(4)
    hash_count = read_var_int()
    hashes = [hash_encode(read_bytes(32)) for i in range(hash_count)]
    flags_count = read_var_int()
    flags = read_bytes(flags_count)

    root_node = deserialize_core_format_merkle_proof(hashes, flags, txcount)
    #check special case of a tree of zero height, block with only coinbase tx
    if not isinstance(root_node, tuple):
        root_node = root_node[5:] #remove the "tx:0:"
        result = {"pos": 0, "merkle": [], "txid": root_node,
            "merkleroot": hash_encode(merkle_root)}
        return result

    hashes_list = []
    expand_tree_electrum_format_merkle_proof(root_node, hashes_list)
    #remove the first or second element which is the txhash
    tx = hashes_list[0]
    if hashes_list[1].startswith("tx"):
        tx = hashes_list[1]
    assert(tx.startswith("tx"))
    hashes_list.remove(tx)
    #if the txhash was duplicated, that _is_ included in electrum's format
    if hashes_list[0].startswith("tx"):
        hashes_list[0] = tx.split(":")[2]
    tx_pos, txid = tx.split(":")[1:3]
    tx_pos = int(tx_pos)
    result = {"pos": tx_pos, "merkle": hashes_list, "txid": txid,
        "merkleroot": hash_encode(merkle_root)}
    return result

merkle_proof_test_vectors = [
    #txcount 819, pos 5
    "0300000026e696fba00f0a43907239305eed9e55824e0e376636380f000000000000000" + 
    "04f8a2ce51d6c69988029837688cbfc2f580799fa1747456b9c80ab808c1431acd0b07f" + 
    "5543201618cadcfbf7330300000b0ff1e0050fed22ca360e0935e053b0fe098f6f9e090" + 
    "f5631013361620d964fe2fd88544ae10b40621e1cd24bb4306e3815dc237f77118a45d7" + 
    "5ada9ee362314b70573732bce59615a3bcc1bbacd04b33b7819198212216b5d62d75be5" + 
    "9221ada17ba4fb2476b689cccd3be54732fd5630832a94f11fa3f0dafd6f904d43219e0" + 
    "d7de110158446b5b598bd241f7b5df4da0ebc7d30e7748d487917b718df51c681174e6a" + 
    "bab8042cc7c1c436221c098f06a56134f9247a812126d675d69c82ba1c715cfc0cde462" + 
    "fd1fbe5dc87f6b8db2b9c060fcd59a20e7fe8e921c3676937a873ff88684f4be4d015f2" + 
    "4f26af6d2cf78335e9218bcceba4507d0b4ba6cb933aa01ef77ae5eb411893ec0f74b69" + 
    "590fb0f5118ac937c02ccd47e9d90be78becd11ecf854d7d268eeb479b74d137278c0a5" + 
    "017d29e90cd5b35a4680201824fb0eb4f404e20dfeaec4d50549030b7e7e220b02eb210" + 
    "5f3d2e8bcc94d547214a9d03ff1600",
    #txcount 47, pos 9
    "0100000053696a625fbd16df418575bce0c4148886c422774fca5fcab80100000000000" + 
    "01532bfe4f9c4f56cd141028e5b59384c133740174b74b1982c7f01020b90ce05577c67" + 
    "508bdb051a7ec2ef942f000000076cde2eb7efa90b36d48aed612e559ff2ba638d8d400" + 
    "b14b0c58df00c6a6c33b65dc8fa02f4ca56e1f4dcf17186fa9bbd990ce150b6e2dc9e9e" + 
    "56bb4f270fe56fde6bdd73a7a7e82767714862888e6b759568fb117674ad23050e29311" + 
    "97494d457efb72efdb9cb79cd4a435724908a0eb31ec7f7a67ee03837319e098b43edad" + 
    "3be9af75ae7b30db6f4f93ba0fdd941fdf70fe8cc38982e03bd292f5bd02f28137d343f" + 
    "908c7d6417379afe8349a257af3ca1f74f623be6a416fe1aa96a8f259983f2cf32121bc" + 
    "e203955a378b3b44f132ea6ab94c7829a6c3b360c9f8da8e74027701",
    #txcount 2582, pos 330
    "000000206365d5e1d8b7fdf0b846cfa902115c1b8ced9dd49cb17800000000000000000" + 
    "01032e829e1f9a5a09d0492f9cd3ec0762b7facea555989c3927d3d975fd4078c771849" + 
    "5a45960018edd3b9e0160a00000dfe856a7d5d77c23ebf85c68b5eb303d85e56491ed6d" + 
    "204372625d0b4383df5a44d6e46d2db09d936b9f5d0b53e0dbcb3efb7773d457369c228" + 
    "fd1ce6e11645e366a58b3fc1e8a7c916710ce29a87265a6729a3b221b47ea9c8e6f4870" + 
    "7b112b8d67e5cfb3db5f88b042dc49e4e5bc2e61c28e1e0fbcba4c741bb5c75cac58ca0" + 
    "4161a7377d70f3fd19a3e248ed918c91709b49afd3760f89ed2fefbcc9c23447ccb40a2" + 
    "be7aba22b07189b0bf90c62db48a9fe37227e12c7af8c1d4c22f9f223530dacdd5f3ad8" + 
    "50ad4badf16cc24049a65334f59bf28c15cecda1a4cf3f2937bd70ee84f66569ce8ef95" + 
    "1d50cca46d60337e6c697685b38ad217967bbe6801d03c44fcb808cd035be31888380a2" + 
    "df1be14b6ff100de83cab0dce250e2b40ca3b47e8309f848646bee63b6185c176d84f15" + 
    "46a482e7a65a87d1a2d0d5a2b683e2cae0520df1e3525a71d71e1f551abd7d238c3bcb4" + 
    "ecaeea7d5988745fa421a8604a99857426957a2ccfa7cd8df145aa8293701989dd20750" + 
    "5923fcb339843944ce3d21dc259bcda9c251ed90d4e55af2cf5b15432050084f513ac74" + 
    "c0bdd4b6046fb70100",
    #txcount 2861, pos 2860, last tx with many duplicated nodes down the tree
    "00000020c656c90b521a2bbca14174f2939b882a28d23d86144b0e00000000000000000" + 
    "0cf5185a8e369c3de5f15e039e777760994fd66184b619d839dace3aec9953fd6d86159" + 
    "5ac1910018ee097a972d0b0000078d20d71c3114dbf52bb13f2c18f987891e8854d2d29" + 
    "f61c0b3d3256afcef7c0b1e6f76d6431f93390ebd28dbb81ad7c8f08459e85efeb23cc7" + 
    "2df2c5612215bf53dd4ab3703886bc8c82cb78ba761855e495fb5dc371cd8fe25ae974b" + 
    "df42269e267caf898a9f34cbf2350eaaa4afbeaea70636b5a3b73682186817db5b33290" + 
    "bd5c696bd8d0322671ff70c5447fcd7bdc127e5b84350c6b14b5a3b86b424d7db38d39f" + 
    "171f57e255a31c6c53415e3d65408b6519a40aacc49cad8e70646d4cb0d23d4a63068e6" + 
    "c220efc8a2781e9e774efdd334108d7453043bd3c8070d0e5903ad5b07",
    #txcount 7, pos 6, duplicated entry in the last depth, at tx level
    "0100000056e02c6d3278c754e0699517834741f7c4ad3dcbfeb7803a346200000000000" + 
    "0af3bdd5dd465443fd003e9281455e60aae573dd4d46304d7ba17276ea33d506488cbb4" + 
    "4dacb5001b9ebb193b0700000003cd3abb2eb7583165f36b56add7268be9027ead4cc8f" + 
    "888ec650d3b1c1f4de28a0ff7c8b463b2042d09598f0e5e5905de362aa1cf75252adc22" + 
    "719b8e1bc969adcfbc4782b8eafc9352263770b91a0f189ae051cbe0e26046c2b14cf3d" + 
    "8be0bc40135",
    #txcount 6, pos 5, duplicated entry in the last-but-one depth
    "01000000299edfd28524eae4fb6012e4087afdb6e1b912db85e612374b0300000000000" + 
    "0e16572394f8578a47bf36e15cd16faa5e3b9e18805cf4e271ae4ef95aa8cea7eb31fa1" + 
    "4e4b6d0b1a42857d960600000003f52b45ed953924366dab3e92707145c78615b639751" + 
    "ecb7be1c5ecc09b592ed588ca0e15a89e9049a2dbcadf4d8362bd1f74a6972f176617b5" + 
    "8a5466c8a4121fc3e2d6fa66c8637b387ef190ab46d6e9c9dae4bbccd871c72372b3dbc" + 
    "6edefea012d",
    #txcount 5, pos 4, duplicated on the last and second last depth
    "010000004d891de57908d89e9e5585648978d7650adc67e856c2d8c18c1800000000000" + 
    "04746fd317bffecd4ffb320239caa06685bafe0c1b5463b24d636e45788796657843d1b" + 
    "4d4c86041be68355c40500000002d8e26c89c46477f2407d866d2badbd98e43e732a670" + 
    "e96001faf1744b27e5fdd018733d72e31a2d6a0d94f2a3b35fcc66fb110c40c5bbff82b" + 
    "f87606553d541d011d",
    #txcount 2739, pos 0, coinbase tx
    "000000209f283da030c6e6d0ff5087a87c430d140ed6b4564fa34d00000000000000000" + 
    "0ec1513723e3652c6b8e777c41eb267ad8dd2025e85228840f5cfca7ffe1fb331afff8a" + 
    "5af8e961175e0f7691b30a00000df403e21a4751fbd52457f535378ac2dcf111199e9ea" + 
    "6f78f6c2663cb99b58203438d8f3b26f7f2804668c1df7d394a4726363d4873b2d85b71" + 
    "2e44cf4f5e4f33f22a8f3a1672846bd7c4570c668e6ee12befda23bfa3d0fcd30b1b079" + 
    "19b01c40b1e31b6d34fcdbb99539d46eb97a3ae15386f1ab0f28ecacadd9fc3fa4ce49a" + 
    "1a1839d815229f54036c8a3035d91e80e8dc127b62032b4e652550b4fc0aee0f6e85a14" + 
    "307d85ed9dde62acff9a0f7e3b52370a10d6c83ec13a0b4a8fafe87af368a167d7e9b63" + 
    "3b84b6ea65f1ce5e8ccc1840be0a4dab0099e25afccc7f2fdbda54cd65ecbac8d9a550c" + 
    "108b4e18d3af59129d373fde4c80848858fd6f7fc1e27387a38833473ca8a47729fa6e1" + 
    "cc14b584c14dad768108ff18cc6acdc9c31d32dc71c3c80856664a3fff870fe419a59aa" + 
    "9033356590475d36086f0b3c0ece34c0f3756675c610fb980ff3363af6f9c0918a7c677" + 
    "23371849de9c1026515c2900a80b3aee4f2625c8f48cd5eb967560ee8ebe58a8d41c331" + 
    "f6d5199795735d4f0494bdf592d166fa291062733619f0f133605087365639de2d9d5d6" + 
    "921f4b4204ff1f0000",
    #txcount 1, pos 0, coinbase tx in an empty block, tree with height 1
    "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d0000000" + 
    "0112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd66" + 
    "49ffff001d1e2de5650100000001112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98" + 
    "173ac9799a852fa39add30101",
    #txcount 2, pos 1, tree with height 2
    "010000004e24a2880cd72d9bde7502087bd3756819794dc7548f68dd68dc30010000000" + 
    "02793fce9cdf91b4f84760571bf6009d5f0ffaddbfdc9234ef58a036096092117b10f4b" + 
    "4cfd68011c903e350b0200000002ee50562fc6f995eff2df61be0d5f943bac941149aa2" + 
    "1aacb32adc130c0f17d6a2077a642b1eabbc5120e31566a11e2689aa4d39b01cce9a190" + 
    "2360baa5e4328e0105"
]

def test():
    for proof in merkle_proof_test_vectors:
        try:
            electrum_proof = convert_core_to_electrum_merkle_proof(proof)
            #print(electrum_proof)
            implied_merkle_root = hash_merkle_root(
                electrum_proof["merkle"], electrum_proof["txid"],
                electrum_proof["pos"])
            assert implied_merkle_root == electrum_proof["merkleroot"]
        except ValueError:
            import traceback
            traceback.print_exc()
            assert 0
    print("All tests passed")

'''
proof = ""
def chunks(d, n):
    return [d[x:x + n] for x in range(0, len(d), n)]
#print(proof)
print("\" + \n\"".join(chunks(proof, 71)))
'''

if __name__ == "__main__":
    test()

