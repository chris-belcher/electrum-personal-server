
import electrumpersonalserver.bitcoin as btc
import binascii
from math import ceil, log

from electrumpersonalserver.server.hashes import Hash, hash_encode, hash_decode

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

