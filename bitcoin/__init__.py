from bitcoin.py2specials import *
from bitcoin.py3specials import *
secp_present = False
try:
    import secp256k1
    secp_present = True
    from bitcoin.secp256k1_main import *
    from bitcoin.secp256k1_transaction import *
    from bitcoin.secp256k1_deterministic import *    
except ImportError as e:
    from bitcoin.main import *
    from bitcoin.deterministic import *
    from bitcoin.transaction import *
