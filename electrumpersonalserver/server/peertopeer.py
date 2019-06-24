#! /usr/bin/env python

import socket, time
import base64
import threading
from struct import pack, unpack
from datetime import datetime

import electrumpersonalserver.bitcoin as btc
from electrumpersonalserver.server.socks import (
    socksocket,
    setdefaultproxy,
    PROXY_TYPE_SOCKS5
)
from electrumpersonalserver.server.jsonrpc import JsonRpcError

PROTOCOL_VERSION = 70012
DEFAULT_USER_AGENT = '/Satoshi:0.18.0/'
NODE_WITNESS = (1 << 3)

# protocol versions above this also send a relay boolean
RELAY_TX_VERSION = 70001

# length of bitcoin p2p packets
HEADER_LENGTH = 24

# if no message has been seen for this many seconds, send a ping
KEEPALIVE_INTERVAL = 2 * 60

# close connection if keep alive ping isnt responded to in this many seconds
KEEPALIVE_TIMEOUT = 20 * 60

def ip_to_hex(ip_str):
    # ipv4 only for now
    return socket.inet_pton(socket.AF_INET, ip_str)

def create_net_addr(hexip, port): # doesnt contain time as in bitcoin wiki
    services = 0
    hex = bytes(10) + b'\xFF\xFF' + hexip
    return pack('<Q16s', services, hex) + pack('>H', port)

def create_var_str(s):
    return btc.num_to_var_int(len(s)) + s.encode()

def read_int(ptr, payload, n, littleendian=True):
    data = payload[ptr[0] : ptr[0]+n]
    if littleendian:
        data = data[::-1]
    ret =  btc.decode(data, 256)
    ptr[0] += n
    return ret

def read_var_int(ptr, payload):
    val = payload[ptr[0]]
    ptr[0] += 1
    if val < 253:
        return val
    return read_int(ptr, payload, 2**(val - 252))

def read_var_str(ptr, payload):
    l = read_var_int(ptr, payload)
    ret = payload[ptr[0]: ptr[0] + l]
    ptr[0] += l
    return ret

def ip_hex_to_str(ip_hex):
    # https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses
    # https://www.cypherpunk.at/onioncat_trac/wiki/OnionCat
    if ip_hex[:14] == '\x00'*10 + '\xff'*2:
        # ipv4 mapped ipv6 addr
        return socket.inet_ntoa(ip_hex[12:])
    elif ip_hex[:6] == '\xfd\x87\xd8\x7e\xeb\x43':
        return base64.b32encode(ip_hex[6:]).lower() + '.onion'
    else:
        return socket.inet_ntop(socket.AF_INET6, ip_hex)

class P2PMessageHandler(object):
    def __init__(self, logger):
        self.last_message = datetime.now()
        self.waiting_for_keepalive = False
        self.logger = logger

    def check_keepalive(self, p2p):
        if self.waiting_for_keepalive:
            if ((datetime.now() - self.last_message).total_seconds()
                    < KEEPALIVE_TIMEOUT):
                return
            self.logger.info('keepalive timed out, closing')
            p2p.sock.close()
        else:
            if ((datetime.now() - self.last_message).total_seconds()
                    < KEEPALIVE_INTERVAL):
                return
            self.logger.debug('sending keepalive to peer')
            self.waiting_for_keepalive = True
            p2p.sock.sendall(p2p.create_message('ping', '\x00'*8))

    def handle_message(self, p2p, command, length, payload):
        self.last_message = datetime.now()
        self.waiting_for_keepalive = False
        ptr = [0]
        if command == b'version':
            version = read_int(ptr, payload, 4)
            services = read_int(ptr, payload, 8)
            timestamp = read_int(ptr, payload, 8)
            addr_recv_services = read_int(ptr, payload, 8)
            addr_recv_ip = payload[ptr[0] : ptr[0]+16]
            ptr[0] += 16
            addr_recv_port = read_int(ptr, payload, 2, False)
            addr_trans_services = read_int(ptr, payload, 8)
            addr_trans_ip = payload[ptr[0] : ptr[0]+16]
            ptr[0] += 16
            addr_trans_port = read_int(ptr, payload, 2, False)
            ptr[0] += 8 # skip over nonce
            user_agent = read_var_str(ptr, payload)
            start_height = read_int(ptr, payload, 4)
            if version > RELAY_TX_VERSION:
                relay = read_int(ptr, payload, 1) != 0
            else:
                # must check node accepts unconfirmed txes before broadcasting
                relay = True
            self.logger.debug(('Received peer version message: version=%d'
                + ' services=0x%x'
                + ' timestamp=%s user_agent=%s start_height=%d relay=%i'
                + ' them=%s:%d us=%s:%d') % (version,
                services, str(datetime.fromtimestamp(timestamp)),
                user_agent, start_height, relay, ip_hex_to_str(addr_trans_ip)
                , addr_trans_port, ip_hex_to_str(addr_recv_ip), addr_recv_port))
            p2p.sock.sendall(p2p.create_message('verack', b''))
            self.on_recv_version(p2p, version, services, timestamp,
                addr_recv_services, addr_recv_ip, addr_trans_services,
                addr_trans_ip, addr_trans_port, user_agent, start_height,
                relay)
        elif command == b'verack':
            self.on_connected(p2p)
        elif command == b'ping':
            p2p.sock.sendall(p2p.create_message('pong', payload))

    # optional override these in a subclass

    def on_recv_version(self, p2p, version, services, timestamp,
            addr_recv_services, addr_recv_ip, addr_trans_services,
            addr_trans_ip, addr_trans_port, user_agent, start_height, relay):
        pass

    def on_connected(self, p2p):
        pass

    def on_heartbeat(self, p2p):
        pass


class P2PProtocol(object):
    def __init__(self, p2p_message_handler, remote_hostport,
                 network, logger, user_agent=DEFAULT_USER_AGENT,
                 socks5_hostport=("localhost", 9050), connect_timeout=30,
                 heartbeat_interval=15):
        self.logger = logger
        self.p2p_message_handler = p2p_message_handler
        self.network = network
        self.user_agent = user_agent
        self.socks5_hostport = socks5_hostport
        self.heartbeat_interval = heartbeat_interval
        self.connect_timeout = connect_timeout
        if self.network == "testnet":
            self.magic = 0x0709110b
        elif self.network == "regtest":
            self.magic = 0xdab5bffa
        else:
            self.magic = 0xd9b4bef9
        self.closed = False
        self.remote_hostport = remote_hostport

    def run(self):
        services = NODE_WITNESS
        st = int(time.time())
        nonce = 0
        start_height = 0

        netaddr = create_net_addr(ip_to_hex('0.0.0.0'), 0)
        version_message = (pack('<iQQ', PROTOCOL_VERSION, services, st)
                           + netaddr
                           + netaddr
                           + pack('<Q', nonce)
                           + create_var_str(self.user_agent)
                           + pack('<I', start_height)
                           + b'\x01')

        self.logger.debug('Connecting to bitcoin peer at ' +
                str(self.remote_hostport) + ' with proxy ' +
                str(self.socks5_hostport))
        setdefaultproxy(PROXY_TYPE_SOCKS5, self.socks5_hostport[0],
                        self.socks5_hostport[1], True)
        self.sock = socksocket()
        self.sock.settimeout(self.connect_timeout)
        self.sock.connect(self.remote_hostport)
        self.sock.sendall(self.create_message('version', version_message))

        self.logger.debug('Connected to bitcoin peer')
        self.sock.settimeout(self.heartbeat_interval)
        self.closed = False
        try:
            recv_buffer = b''
            payload_length = -1  # -1 means waiting for header
            command = None
            checksum = None
            while not self.closed:
                try:
                    recv_data = self.sock.recv(4096)
                    if not recv_data or len(recv_data) == 0:
                        raise EOFError()
                    recv_buffer += recv_data
                    # this is O(N^2) scaling in time, another way would be to
                    # store in a list and combine at the end with "".join()
                    # but this isnt really timing critical so didnt optimize it

                    data_remaining = True
                    while data_remaining and not self.closed:
                        if payload_length == -1 and (len(recv_buffer)
                                >= HEADER_LENGTH):
                            net_magic, command, payload_length, checksum =\
                                unpack('<I12sI4s', recv_buffer[:HEADER_LENGTH])
                            recv_buffer = recv_buffer[HEADER_LENGTH:]
                            if net_magic != self.magic:
                                self.logger.debug('wrong MAGIC: ' +
                                    hex(net_magic))
                                self.sock.close()
                                break
                            command = command.strip(b'\0')
                        else:
                            if payload_length >= 0 and (len(recv_buffer)
                                    >= payload_length):
                                payload = recv_buffer[:payload_length]
                                recv_buffer = recv_buffer[payload_length:]
                                if btc.bin_dbl_sha256(payload)[:4] == checksum:
                                    self.p2p_message_handler.handle_message(
                                        self, command, payload_length, payload)
                                else:
                                    self.logger.debug("wrong checksum, " +
                                        "dropping " +
                                        "message, cmd=" + command +
                                        " payloadlen=" + str(payload_length))
                                payload_length = -1
                                data_remaining = True
                            else:
                                data_remaining = False
                except socket.timeout:
                    self.p2p_message_handler.check_keepalive(self)
                    self.p2p_message_handler.on_heartbeat(self)
        except EOFError as e:
            self.closed = True
        except IOError as e:
            import traceback
            self.logger.debug("logging traceback from %s: \n" %
                traceback.format_exc())
            self.closed = True
        finally:
            try:
                self.sock.close()
            except Exception as _:
                pass

    def close(self):
        self.closed = True

    def create_message(self, command, payload):
        return (pack("<I12sI", self.magic, command.encode(), len(payload))
            + btc.bin_dbl_sha256(payload)[:4] + payload)

class P2PBroadcastTx(P2PMessageHandler):
    def __init__(self, txhex, logger):
        P2PMessageHandler.__init__(self, logger)
        self.txhex = bytes.fromhex(txhex)
        self.txid = btc.bin_txhash(self.txhex)
        self.uploaded_tx = False
        self.time_marker = datetime.now()
        self.connected = False

    def on_recv_version(self, p2p, version, services, timestamp,
            addr_recv_services, addr_recv_ip, addr_trans_services,
            addr_trans_ip, addr_trans_port, user_agent, start_height, relay):
        if not relay:
            self.logger.debug('peer not accepting unconfirmed txes, trying ' +
                'another')
            # this happens if the other node is using blockonly=1
            p2p.close()
        if not services & NODE_WITNESS:
            self.logger.debug('peer not accepting witness data, trying another')
            p2p.close()

    def on_connected(self, p2p):
        MSG = 1 #msg_tx
        inv_payload = pack('<BI', 1, MSG) + self.txid
        p2p.sock.sendall(p2p.create_message('inv', inv_payload))
        self.time_marker = datetime.now()
        self.uploaded_tx = False
        self.connected = True

    def on_heartbeat(self, p2p):
        self.logger.debug('broadcaster heartbeat')
        VERACK_TIMEOUT = 40
        GETDATA_TIMEOUT = 60
        if not self.connected:
            if ((datetime.now() - self.time_marker).total_seconds()
                    < VERACK_TIMEOUT):
                return
            self.logger.debug('timed out of waiting for verack')
        else:
            if ((datetime.now() - self.time_marker).total_seconds()
                    < GETDATA_TIMEOUT):
                return
            self.logger.debug('timed out in waiting for getdata, node ' +
                'already has tx')
            self.uploaded_tx = True
        p2p.close()

    def handle_message(self, p2p, command, length, payload):
        P2PMessageHandler.handle_message(self, p2p, command, length, payload)
        ptr = [0]
        if command == b'getdata':
            count = read_var_int(ptr, payload)
            for _ in range(count):
                ptr[0] += 4
                hash_id = payload[ptr[0] : ptr[0] + 32]
                ptr[0] += 32
                if hash_id == self.txid:
                    p2p.sock.sendall(p2p.create_message('tx', self.txhex))
                    self.uploaded_tx = True
                    self.logger.info("Uploaded transaction via tor to peer at "
                        + str(p2p.remote_hostport))
                    p2p.close()

def broadcaster_thread(txhex, node_addrs, tor_hostport, network, logger):
    for node_addr in node_addrs:
        remote_hostport = (node_addr["address"], node_addr["port"])
        p2p_msg_handler = P2PBroadcastTx(txhex, logger)
        p2p = P2PProtocol(p2p_msg_handler, remote_hostport=remote_hostport,
            network=network, logger=logger, socks5_hostport=tor_hostport,
            heartbeat_interval=20)
        try:
            p2p.run()
        except IOError as e:
            logger.debug("p2p.run() exited: " + repr(e))
            continue
        if p2p_msg_handler.uploaded_tx:
            break
    logger.debug("Exiting tor broadcast thread, uploaded_tx = " +
        str(p2p_msg_handler.uploaded_tx))
    # return false if never found a node that accepted unconfirms
    return p2p_msg_handler.uploaded_tx

def chunk_list(d, n):
    return [d[x:x + n] for x in range(0, len(d), n)]

def tor_broadcast_tx(txhex, tor_hostport, network, rpc, logger):
    CONNECTION_THREADS = 8
    CONNECTION_ATTEMPTS_PER_THREAD = 10

    required_address_count = CONNECTION_ATTEMPTS_PER_THREAD * CONNECTION_THREADS
    node_addrs_witness = []
    while True:
        try:
            new_node_addrs = rpc.call("getnodeaddresses",
                [3*required_address_count//2])
        except JsonRpcError as e:
            logger.debug(repr(e))
            logger.error("Bitcoin Core v0.18.0 or higher is required "
                "to broadcast through Tor")
            return False
        node_addrs_witness.extend(
            [a for a in new_node_addrs if a["services"] & NODE_WITNESS]
        )
        logger.debug("len(new_node_addrs) = " + str(len(new_node_addrs)) +
            " len(node_addrs_witness) = " + str(len(node_addrs_witness)))
        if len(node_addrs_witness) > required_address_count:
            break
    node_addrs_chunks = chunk_list(
        node_addrs_witness[:required_address_count],
        CONNECTION_ATTEMPTS_PER_THREAD
    )
    for node_addrs in node_addrs_chunks:
        t = threading.Thread(target=broadcaster_thread,
            args=(txhex, node_addrs, tor_hostport, network, logger),
            daemon=True)
        t.start()

