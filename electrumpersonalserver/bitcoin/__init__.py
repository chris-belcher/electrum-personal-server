from electrumpersonalserver.bitcoin.py2specials import *
from electrumpersonalserver.bitcoin.py3specials import *

secp_present = False
try:
    import secp256k1

    secp_present = True
    from electrumpersonalserver.bitcoin.secp256k1_main import *
    from electrumpersonalserver.bitcoin.secp256k1_transaction import *
    from electrumpersonalserver.bitcoin.secp256k1_deterministic import *
except ImportError as e:
    from electrumpersonalserver.bitcoin.main import *
    from electrumpersonalserver.bitcoin.deterministic import *
    from electrumpersonalserver.bitcoin.transaction import *
