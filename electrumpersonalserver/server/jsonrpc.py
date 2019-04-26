# Copyright (C) 2013,2015 by Daniel Kraft <d@domob.eu>
# Copyright (C) 2014 by phelix / blockchained.com

#jsonrpc.py from https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/jmclient/jmclient/jsonrpc.py

import base64
import http.client
import json

class JsonRpcError(Exception): pass
class JsonRpcConnectionError(JsonRpcError): pass

class JsonRpc(object):
    """
    Simple implementation of a JSON-RPC client that is used
    to connect to Bitcoin.
    """
    def __init__(self, host, port, user, password, wallet_filename="",
            logger=None):
        self.host = host
        self.port = port
        self.conn = http.client.HTTPConnection(self.host, self.port)
        self.authstr = "%s:%s" % (user, password)
        if len(wallet_filename) > 0:
            self.url = "/wallet/" + wallet_filename
        else:
            self.url = ""
        self.logger = logger
        self.queryId = 1

    def queryHTTP(self, obj):
        """
        Send an appropriate HTTP query to the server.  The JSON-RPC
        request should be (as object) in 'obj'.  If the call succeeds,
        the resulting JSON object is returned.  In case of an error
        with the connection (not JSON-RPC itself), an exception is raised.
        """
        headers = {"User-Agent": "electrum-personal-server",
                   "Content-Type": "application/json",
                   "Accept": "application/json"}
        headers["Authorization"] = (b"Basic " +
            base64.b64encode(self.authstr.encode('utf-8')))
        body = json.dumps(obj)
        for i in range(20):
            try:
                self.conn.request("POST", self.url, body, headers)
                response = self.conn.getresponse()
                if response.status == 401:
                    self.conn.close()
                    raise JsonRpcConnectionError(
                            "authentication for JSON-RPC failed")
                #All the codes below are 'fine' from a JSON-RPC point of view.
                if response.status not in [200, 404, 500]:
                    self.conn.close()
                    raise JsonRpcConnectionError("unknown error in JSON-RPC")
                data = response.read()
                return json.loads(data.decode('utf-8'))
            except JsonRpcConnectionError as exc:
                raise exc
            except http.client.BadStatusLine:
                return "CONNFAILURE"
            except OSError as e:
                    self.logger.debug('Reconnecting RPC after error: ' + repr(e))
                    self.conn.close()
                    self.conn.connect()
                    continue
            except Exception as exc:
                raise JsonRpcConnectionError("JSON-RPC connection failed. Err:"
                    + repr(exc))
            break
        return None

    def call(self, method, params):
        currentId = self.queryId
        self.queryId += 1

        request = {"method": method, "params": params, "id": currentId}
        #query can fail from keepalive timeout; keep retrying if it does, up
        #to a reasonable limit, then raise (failure to access blockchain
        #is a critical failure). Note that a real failure to connect (e.g.
        #wrong port) is raised in queryHTTP directly.
        response_received = False
        for i in range(100):
            response = self.queryHTTP(request)
            if response != "CONNFAILURE":
                response_received = True
                break
            #Failure means keepalive timed out, just make a new one
            self.conn = http.client.HTTPConnection(self.host, self.port)
            self.logger.debug("Creating new jsonrpc HTTPConnection")
        if not response_received:
            raise JsonRpcConnectionError("Unable to connect over RPC")
        if response["id"] != currentId:
            raise JsonRpcConnectionError("invalid id returned by query")
        if response["error"] is not None:
            raise JsonRpcError(response["error"])
        return response["result"]
